"""Dados da análise (W3, PROPOSTA_WEB §7.6, §7.7, §8.4): agregados por hora, destaques, eventos com paginação por
chave, contas e cobertura. Tudo sobre pseudônimos e dimensões técnicas: nada aqui decifra conta, IP ou sessão, exceto
`detalhe_evento`, que abre um evento com a DEK e o devolve pela visão mascarada.

As regras de negócio (categorias, fora do expediente, rajadas, IP novo) são as mesmas de `consolidar.py` (que continua
alimentando a planilha e o pacote); `tests/analise.py` confere que os números são iguais aos do XLSX.
"""
from __future__ import annotations

import base64
import json
from datetime import datetime, timedelta, timezone

from psycopg.types.json import Jsonb

from .consolidar import ERROS, EXPEDIENTE, FALHAS, GLOSSARIO, GRAN, LOGINS, categoria, fracoes, nome_evento

PRELIMINAR_S = 30            # durante a coleta, agregados refeitos no máximo a cada 30 s (laço de limpeza do worker)
LIMITE_EVENTOS = 200
TOPO = 20
CATEGORIAS = ("Acesso", "Conta", "Técnico", "Outro")
ESTADOS_COM_DADOS = ("coletando", "pausada", "coletada", "concluida", "concluida_com_lacunas", "parcial", "falhou")
FINAIS = ("concluida", "concluida_com_lacunas", "parcial")


def _case_categoria(col: str = "type") -> str:
    partes = " ".join(f"WHEN '{k}' THEN '{v[1]}'" for k, v in GLOSSARIO.items())
    return f"(CASE {col} {partes} ELSE 'Outro' END)"


# ------------------------------------------------------------------ regras puras
def fora_expediente(t_ms: int, tz) -> bool:
    d = datetime.fromtimestamp(t_ms / 1000, tz)
    return d.isoweekday() >= 6 or not (EXPEDIENTE[0] <= d.hour < EXPEDIENTE[1])


def rajadas(falhas: list[dict], minimo: int = 5, janela_ms: int = 600_000) -> list[dict]:
    """≥ 5 falhas de login em 10 min na mesma conta; rajadas sobrepostas são unidas (mesma regra de
    consolidar._rajadas, aqui sobre pseudônimos: a conta é o par instância × realm × conta_id)."""
    out: list[dict] = []
    por_conta: dict = {}
    for e in falhas:
        por_conta.setdefault((e["instancia_id"], e["realm"], e["conta_id"]), []).append(e)
    for chave, evs in por_conta.items():
        evs.sort(key=lambda x: x["time_ms"])
        i, atual = 0, None
        for j in range(len(evs)):
            while evs[j]["time_ms"] - evs[i]["time_ms"] > janela_ms:
                i += 1
            if j - i + 1 >= minimo:
                ini = evs[i]["time_ms"]
                if atual and ini <= atual["fim_ms"]:
                    atual["fim_ms"] = evs[j]["time_ms"]
                    atual["n"] = j - atual["_i"] + 1
                    atual["_ips"] |= {x["ps_ip"] for x in evs[i:j + 1]}
                else:
                    atual = {"instancia_id": chave[0], "realm": chave[1], "conta_id": chave[2],
                             "ps_conta": evs[i]["ps_conta"], "inicio_ms": ini, "fim_ms": evs[j]["time_ms"],
                             "n": j - i + 1, "_i": i, "_ips": {x["ps_ip"] for x in evs[i:j + 1]}}
                    out.append(atual)
    for r in out:
        r.pop("_i")
        r["ps_ips"] = sorted(p for p in r.pop("_ips") if p)
    return out


# ------------------------------------------------------------------ filtros
class Filtros:
    """Filtros técnicos e por pseudônimo (rótulo, ex.: "IP 3"). Valores reais nunca entram aqui (§7.6)."""

    def __init__(self, cx, inv: dict, q: dict):
        self.inv, self.q = inv, {k: v for k, v in q.items() if v not in (None, "", [])}
        cats = self.q.get("categorias")
        if isinstance(cats, str):
            cats = [c for c in cats.split(",") if c]
        cats = list(cats or ["Acesso", "Conta"])
        if self.q.get("tecnicos") in (True, "1", "true") and "Técnico" not in cats:
            cats.append("Técnico")
        self.categorias = [c for c in cats if c in CATEGORIAS]
        self.where = ["e.investigacao_id=%(inv)s", "e.time_ms >= %(ini)s", "e.time_ms < %(fim)s"]
        self.args: dict = {"inv": inv["id"], "ini": inv["inicio_ms"], "fim": inv["fim_ms"], "fuso": inv["fuso"],
                           "cats": self.categorias}
        self.where_ag = ["a.investigacao_id=%(inv)s"]
        self.vazio = False
        insts = {r["nome"]: r["id"] for r in cx.execute("SELECT id, nome FROM instancia")}
        if "instancia" in self.q:
            self.args["f_inst"] = insts.get(self.q["instancia"], -1)
            self.where.append("e.instancia_id = %(f_inst)s")
            self.where_ag.append("a.instancia_id = %(f_inst)s")
        if "realm" in self.q:
            self.args["f_realm"] = self.q["realm"]
            self.where.append("e.realm = %(f_realm)s")
            self.where_ag.append("a.realm = %(f_realm)s")
        if "cliente" in self.q:
            self.args["f_cli"] = self.q["cliente"]
            self.where.append("e.client_id = %(f_cli)s")
            self.where_ag.append("a.client_id = %(f_cli)s")
        self.where.append(f"{_case_categoria('e.type')} = ANY(%(cats)s)")
        self.where_ag.append(f"{_case_categoria('a.type')} = ANY(%(cats)s)")
        # só no eventos (não somam nos agregados)
        self.so_eventos = False
        self.extras: set[str] = set()
        if "tipo" in self.q:
            tipos = self.q["tipo"].split(",") if isinstance(self.q["tipo"], str) else list(self.q["tipo"])
            self.args["f_tipo"] = [t for t in tipos if t not in ("falhas", "logins")] + (
                list(FALHAS) if "falhas" in tipos else []) + (list(LOGINS) if "logins" in tipos else [])
            self.where.append("e.type = ANY(%(f_tipo)s)")
            self.so_eventos = True
            self.extras.add("tipo")
        for campo, classe, col in (("conta", "conta", "ps_conta"), ("ip", "ip", "ps_ip"), ("sessao", "sessao", "ps_sessao")):
            if campo in self.q:
                h = _hmac_do_rotulo(cx, inv["id"], classe, self.q[campo])
                if h is None:
                    self.vazio = True
                self.args[f"f_{campo}"] = h
                self.where.append(f"e.{col} = %(f_{campo})s")
                self.so_eventos = True
                self.extras.add(campo)
        for campo, op in (("de", ">="), ("ate", "<=")):
            if campo in self.q:
                self.args[f"f_{campo}"] = _ms(self.q[campo])
                self.where.append(f"e.time_ms {op} %(f_{campo})s")
                self.so_eventos = True
                self.extras.add(campo)
        d = self.q.get("destaque")
        if d == "fora_expediente":
            self.where.append(f"e.type = ANY(%(logins)s) AND {_SQL_FORA}")
            self.args["logins"] = list(LOGINS)
            self.so_eventos = True
            self.extras.add("destaque")
        elif d == "ip_novo":
            self.where.append("e.ps_ip IS NOT NULL AND NOT EXISTS (SELECT 1 FROM evento b WHERE b.investigacao_id="
                              "e.investigacao_id AND b.ps_ip=e.ps_ip AND b.time_ms < %(ini)s)")
            self.so_eventos = True
            self.extras.add("destaque")
        if "resultado" in self.q:
            self.where.append("e.error IS NULL" if self.q["resultado"] == "sucesso" else "e.error IS NOT NULL")
            self.so_eventos = True
            self.extras.add("resultado")

    @property
    def W(self) -> str:
        return " AND ".join(self.where)

    @property
    def WA(self) -> str:
        return " AND ".join(self.where_ag)

    def ativos(self) -> dict:
        return {k: v for k, v in self.q.items() if k not in ("apos", "limite")}


_SQL_FORA = ("(extract(isodow FROM to_timestamp(e.time_ms/1000.0) AT TIME ZONE %(fuso)s) >= 6 OR "
             f"extract(hour FROM to_timestamp(e.time_ms/1000.0) AT TIME ZONE %(fuso)s) NOT BETWEEN {EXPEDIENTE[0]} "
             f"AND {EXPEDIENTE[1] - 1})")
_SQL_FORA_HORA = ("(extract(isodow FROM a.hora AT TIME ZONE %(fuso)s) >= 6 OR "
                  f"extract(hour FROM a.hora AT TIME ZONE %(fuso)s) NOT BETWEEN {EXPEDIENTE[0]} AND {EXPEDIENTE[1] - 1})")
FROM_EV = "FROM evento e JOIN conta c ON c.id=e.conta_id AND c.incluida"


def _ms(v) -> int:
    if isinstance(v, (int, float)) or (isinstance(v, str) and v.isdigit()):
        return int(v)
    d = datetime.fromisoformat(str(v).replace("Z", "+00:00"))
    if d.tzinfo is None:
        d = d.replace(tzinfo=timezone.utc)
    return int(d.timestamp() * 1000)


def _iso(ms) -> str | None:
    return datetime.fromtimestamp(ms / 1000, timezone.utc).isoformat() if ms is not None else None


def _hmac_do_rotulo(cx, inv_id: int, classe: str, rotulo: str) -> str | None:
    n = str(rotulo).strip().rsplit(" ", 1)[-1]
    if not n.isdigit():
        return None
    r = cx.execute("SELECT hmac FROM pseudonimo WHERE investigacao_id=%s AND classe=%s AND rotulo=%s",
                   (inv_id, classe, int(n))).fetchone()
    return r["hmac"] if r else None


class Rotulos:
    def __init__(self, cx, inv_id: int):
        self.m = {(r["classe"], r["hmac"]): r["rotulo"] for r in cx.execute(
            "SELECT classe, hmac, rotulo FROM pseudonimo WHERE investigacao_id=%s", (inv_id,))}

    def __call__(self, classe: str, h: str | None) -> str | None:
        if not h:
            return None
        n = self.m.get((classe, h))
        nome = {"conta": "Conta", "ip": "IP", "sessao": "Sessão"}[classe]
        return f"{nome} {n}" if n else f"{nome} (numeração no fechamento)"

    @property
    def numerados(self) -> bool:
        return bool(self.m)


# ------------------------------------------------------------------ cálculo (worker)
def calcular(cx, inv_id: int) -> dict:
    """Refaz agregados e destaques da investigação (fechamento, recálculo por conta, preliminar durante a coleta)."""
    inv = cx.execute("SELECT * FROM investigacao WHERE id=%s", (inv_id,)).fetchone()
    with cx.transaction():
        cx.execute("SELECT pg_advisory_xact_lock(%s, %s)", (0x6B61, inv_id))
        cx.execute("DELETE FROM agregado_hora WHERE investigacao_id=%s", (inv_id,))
        cx.execute(f"""INSERT INTO agregado_hora (investigacao_id, hora, instancia_id, realm, client_id, type, ps_conta, n,
                   primeiro_ms, ultimo_ms)
            SELECT e.investigacao_id, date_trunc('hour', to_timestamp(e.time_ms/1000.0) AT TIME ZONE 'UTC')
                   AT TIME ZONE 'UTC', e.instancia_id, e.realm, coalesce(e.client_id, ''), e.type,
                   coalesce(e.ps_conta, ''), count(*), min(e.time_ms), max(e.time_ms)
            {FROM_EV} WHERE e.investigacao_id=%s AND e.time_ms >= %s AND e.time_ms < %s
            GROUP BY 1,2,3,4,5,6,7""", (inv_id, inv["inicio_ms"], inv["fim_ms"]))
        cx.execute("DELETE FROM agregado_ip WHERE investigacao_id=%s", (inv_id,))
        cx.execute(f"""WITH base AS (SELECT DISTINCT e.ps_ip {FROM_EV} WHERE e.investigacao_id=%(inv)s
                                 AND e.time_ms < %(ini)s AND e.ps_ip IS NOT NULL)
            INSERT INTO agregado_ip (investigacao_id, ps_ip, instancia_id, realm, client_id, type, ps_conta, novo, n,
                                     primeiro_ms, ultimo_ms)
            SELECT e.investigacao_id, e.ps_ip, e.instancia_id, e.realm, coalesce(e.client_id, ''), e.type,
                   coalesce(e.ps_conta, ''), b.ps_ip IS NULL AND %(com_base)s, count(*), min(e.time_ms), max(e.time_ms)
            {FROM_EV} LEFT JOIN base b ON b.ps_ip = e.ps_ip
            WHERE e.investigacao_id=%(inv)s AND e.time_ms >= %(ini)s AND e.time_ms < %(fim)s AND e.ps_ip IS NOT NULL
            GROUP BY 1,2,3,4,5,6,7,8""", {"inv": inv_id, "ini": inv["inicio_ms"], "fim": inv["fim_ms"],
                                       "com_base": bool((inv["parametros"] or {}).get("base_dias"))})
        n = cx.execute("SELECT coalesce(sum(n),0)::int AS n FROM agregado_hora WHERE investigacao_id=%s",
                       (inv_id,)).fetchone()["n"]
        cx.execute("DELETE FROM destaque WHERE investigacao_id=%s", (inv_id,))
        f = Filtros(cx, inv, {"categorias": list(CATEGORIAS)})
        ds = _destaques_brutos(cx, inv, f)
        for r in ds["rajadas"]:
            cx.execute("INSERT INTO destaque (investigacao_id, tipo, inicio_ms, fim_ms, instancia_id, realm, ps_conta, "
                       "n, dados) VALUES (%s,'rajada',%s,%s,%s,%s,%s,%s,%s)",
                       (inv_id, r["inicio_ms"], r["fim_ms"], r["instancia_id"], r["realm"], r["ps_conta"], r["n"],
                        Jsonb({"ps_ips": r["ps_ips"]})))
        for r in ds["ip_novo"] or []:
            cx.execute("INSERT INTO destaque (investigacao_id, tipo, inicio_ms, instancia_id, realm, ps_conta, ps_ip, n) "
                       "VALUES (%s,'ip_novo',%s,%s,%s,%s,%s,%s)",
                       (inv_id, r["primeiro"], r["instancia_id"], r["realm"], r["ps_conta"], r["ps_ip"], r["n"]))
        if ds["fora"]["n"]:
            cx.execute("INSERT INTO destaque (investigacao_id, tipo, inicio_ms, fim_ms, n) VALUES "
                       "(%s,'fora_expediente',%s,%s,%s)", (inv_id, ds["fora"]["primeiro"], ds["fora"]["ultimo"],
                                                           ds["fora"]["n"]))
        cx.execute("""INSERT INTO analise (investigacao_id, versao, calculado_em, eventos, recalculo_pedido_em)
            VALUES (%s, 1, now(), %s, NULL) ON CONFLICT (investigacao_id) DO UPDATE SET versao=analise.versao+1,
            calculado_em=now(), eventos=EXCLUDED.eventos,
            -- pedido feito depois do início deste cálculo continua pendente (o job refaz)
            recalculo_pedido_em=CASE WHEN analise.recalculo_pedido_em > now() THEN analise.recalculo_pedido_em END,
            motivo_recalculo=CASE WHEN analise.recalculo_pedido_em > now() THEN analise.motivo_recalculo END""",
                   (inv_id, n))
    return {"eventos": n, "rajadas": len(ds["rajadas"]), "ip_novo": len(ds["ip_novo"] or []),
            "fora_expediente": ds["fora"]["n"]}


def preliminar(cx) -> list[int]:
    """Durante a coleta: refaz os agregados das investigações coletando cujo cálculo tem mais de 30 s."""
    feitas = []
    for r in cx.execute("""SELECT i.id FROM investigacao i LEFT JOIN analise a ON a.investigacao_id=i.id
            WHERE i.status IN ('coletando','pausada') AND NOT i.lacrada
              AND (a.calculado_em IS NULL OR a.calculado_em < now() - make_interval(secs => %s))""",
                        (PRELIMINAR_S,)).fetchall():
        calcular(cx, r["id"])
        feitas.append(r["id"])
    # recálculo pedido sem job ativo (pedido que chegou no fim de um job): enfileira de novo
    cx.execute("""INSERT INTO job (investigacao_id, tipo, parametros)
        SELECT a.investigacao_id, 'recalcular', '{}'::jsonb FROM analise a WHERE a.recalculo_pedido_em IS NOT NULL
          AND NOT EXISTS (SELECT 1 FROM job j WHERE j.investigacao_id=a.investigacao_id AND j.tipo='recalcular'
                          AND j.status IN ('pendente','executando'))
        ON CONFLICT DO NOTHING""")
    return feitas


def pendente(cx, inv_id: int) -> bool:
    r = cx.execute("SELECT recalculo_pedido_em FROM analise WHERE investigacao_id=%s", (inv_id,)).fetchone()
    return bool(r and r["recalculo_pedido_em"])


def pedir_recalculo(cx, inv_id: int, motivo: str):
    cx.execute("""INSERT INTO analise (investigacao_id, recalculo_pedido_em, motivo_recalculo) VALUES (%s, now(), %s)
        ON CONFLICT (investigacao_id) DO UPDATE SET recalculo_pedido_em=now(), motivo_recalculo=EXCLUDED.motivo_recalculo""",
               (inv_id, motivo))
    cx.execute("INSERT INTO job (investigacao_id, tipo, parametros) VALUES (%s, 'recalcular', %s) "
               "ON CONFLICT DO NOTHING", (inv_id, Jsonb({})))   # um recálculo pendente já basta


# ------------------------------------------------------------------ destaques
def _destaques_brutos(cx, inv: dict, f: Filtros) -> dict:
    a = {**f.args, "logins": list(LOGINS), "falhas": list(FALHAS)}
    # rajadas: as falhas de cada conta numa lista só (na ordem de consolidar: time_ms, id), regra em rajadas()
    falhas = []
    for r in cx.execute(f"""SELECT e.instancia_id, e.realm, e.conta_id, min(e.ps_conta) AS ps_conta,
              array_agg(e.time_ms ORDER BY e.time_ms, e.id) AS ts, array_agg(e.ps_ip ORDER BY e.time_ms, e.id) AS ips
            {FROM_EV} WHERE {f.W} AND e.type = ANY(%(falhas)s) GROUP BY 1,2,3 HAVING count(*) >= 5""", a):
        falhas += [{"instancia_id": r["instancia_id"], "realm": r["realm"], "conta_id": r["conta_id"],
                    "ps_conta": r["ps_conta"], "time_ms": t, "ps_ip": ip} for t, ip in zip(r["ts"], r["ips"])]
    # fora do expediente: do agregado por hora (a hora local é exata nos fusos de hora inteira)
    fora = cx.execute(f"""SELECT coalesce(sum(n),0)::int n, min(a.primeiro_ms) primeiro, max(a.ultimo_ms) ultimo
        FROM agregado_hora a WHERE {f.WA} AND a.type = ANY(%(logins)s) AND {_SQL_FORA_HORA}""", a).fetchone()
    ip_novo = None
    if (inv["parametros"] or {}).get("base_dias"):
        ip_novo = cx.execute(f"""SELECT DISTINCT ON (a.ps_ip) a.ps_ip, a.primeiro_ms AS primeiro, a.instancia_id, a.realm,
                   nullif(a.ps_conta,'') AS ps_conta, sum(a.n) OVER (PARTITION BY a.ps_ip)::int AS n
            FROM agregado_ip a WHERE {f.WA} AND a.novo ORDER BY a.ps_ip, a.primeiro_ms""", a).fetchall()
        ip_novo.sort(key=lambda r: r["primeiro"])
    return {"rajadas": rajadas(falhas), "fora": fora, "ip_novo": ip_novo}


def destaques(cx, inv: dict, f: Filtros, rot: Rotulos, insts: dict) -> dict:
    d = _destaques_brutos(cx, inv, f)
    itens = []
    if d["fora"]["n"]:
        itens.append({"tipo": "fora_expediente", "titulo": "Logins fora do expediente", "n": d["fora"]["n"],
                      "inicio": _iso(d["fora"]["primeiro"]), "fim": _iso(d["fora"]["ultimo"]),
                      "filtro": {"destaque": "fora_expediente"}})
    for r in d["rajadas"][:50]:
        conta = rot("conta", r["ps_conta"])
        itens.append({"tipo": "rajada", "titulo": f"Rajada de {r['n']} falhas de login", "n": r["n"],
                      "inicio": _iso(r["inicio_ms"]), "fim": _iso(r["fim_ms"]), "conta": conta,
                      "instancia": insts.get(r["instancia_id"]), "realm": r["realm"],
                      "ips": [rot("ip", p) for p in r["ps_ips"]],
                      "filtro": {"tipo": "falhas", "de": r["inicio_ms"], "ate": r["fim_ms"],
                                 **({"conta": conta} if rot.numerados else {})}})
    for r in (d["ip_novo"] or [])[:50]:
        ip = rot("ip", r["ps_ip"])
        itens.append({"tipo": "ip_novo", "titulo": "IP sem uso no período de base", "n": r["n"],
                      "inicio": _iso(r["primeiro"]), "ip": ip, "instancia": insts.get(r["instancia_id"]),
                      "realm": r["realm"], "conta": rot("conta", r["ps_conta"]),
                      "filtro": {"ip": ip} if rot.numerados else {"destaque": "ip_novo"}})
    return {"itens": itens, "resumo": {"fora_expediente": d["fora"]["n"], "rajadas": len(d["rajadas"]),
                                       "ip_novo": None if d["ip_novo"] is None else len(d["ip_novo"])}}


# ------------------------------------------------------------------ dashboard
def dashboard(cx, inv: dict, q: dict) -> dict:
    f = Filtros(cx, inv, q)
    rot = Rotulos(cx, inv["id"])
    insts = {r["id"]: r["nome"] for r in cx.execute("SELECT id, nome FROM instancia")}
    a = {**f.args, "logins": list(LOGINS), "falhas": list(FALHAS), "gran": GRAN[inv["granularidade"]]}
    k = cx.execute(f"""SELECT coalesce(sum(n) FILTER (WHERE a.type = ANY(%(logins)s)),0)::int AS logins,
          coalesce(sum(n) FILTER (WHERE a.type = ANY(%(falhas)s)),0)::int AS falhas,
          count(DISTINCT nullif(a.client_id,'')) FILTER (WHERE a.type = ANY(%(logins)s)) AS aplicacoes,
          coalesce(sum(n),0)::int AS eventos FROM agregado_hora a WHERE {f.WA}""", a).fetchone()
    k2 = cx.execute(f"""SELECT min(a.primeiro_ms) FILTER (WHERE a.type = ANY(%(logins)s)) AS primeiro,
          max(a.ultimo_ms) FILTER (WHERE a.type = ANY(%(logins)s)) AS ultimo FROM agregado_hora a WHERE {f.WA}""",
                    a).fetchone()
    k2["ips"] = cx.execute(f"""SELECT count(DISTINCT a.ps_ip) AS n FROM agregado_ip a WHERE {f.WA}
        AND (a.type = ANY(%(logins)s) OR a.type = ANY(%(falhas)s))""", a).fetchone()["n"]
    serie = cx.execute(f"""SELECT date_trunc(%(gran)s, a.hora AT TIME ZONE %(fuso)s) AS janela,
          coalesce(sum(n) FILTER (WHERE a.type = ANY(%(logins)s)),0)::int AS logins,
          coalesce(sum(n) FILTER (WHERE a.type = ANY(%(falhas)s)),0)::int AS falhas,
          coalesce(sum(n),0)::int AS eventos
        FROM agregado_hora a WHERE {f.WA} GROUP BY 1 ORDER BY 1""", a).fetchall()
    por_app = cx.execute(f"""SELECT a.instancia_id, a.realm, nullif(a.client_id,'') AS cliente,
          coalesce(sum(n) FILTER (WHERE a.type = ANY(%(logins)s)),0)::int AS logins,
          coalesce(sum(n) FILTER (WHERE a.type = ANY(%(falhas)s)),0)::int AS falhas,
          coalesce(sum(n),0)::int AS eventos, min(a.hora) AS primeira_hora, max(a.hora) AS ultima_hora
        FROM agregado_hora a WHERE {f.WA} GROUP BY 1,2,3 ORDER BY 4 DESC, 6 DESC""", a).fetchall()
    calor = cx.execute(f"""SELECT extract(isodow FROM a.hora AT TIME ZONE %(fuso)s)::int AS dia_semana,
          extract(hour FROM a.hora AT TIME ZONE %(fuso)s)::int AS hora, sum(n)::int AS n
        FROM agregado_hora a WHERE {f.WA} AND a.type = ANY(%(logins)s) GROUP BY 1,2 ORDER BY 1,2""", a).fetchall()
    ips = cx.execute(f"""SELECT a.ps_ip, sum(a.n)::int AS n, coalesce(sum(a.n) FILTER (WHERE a.type = ANY(%(falhas)s)),0)::int
          AS falhas, min(a.primeiro_ms) AS primeiro, max(a.ultimo_ms) AS ultimo,
          count(DISTINCT nullif(a.ps_conta,'')) AS contas
        FROM agregado_ip a WHERE {f.WA} GROUP BY 1 ORDER BY 2 DESC, 1 LIMIT {TOPO}""", a).fetchall()
    dest = destaques(cx, inv, f, rot, insts)
    return {
        "preliminar": inv["status"] not in FINAIS,
        "rotulos_definitivos": rot.numerados,
        "filtros": f.ativos(), "categorias": f.categorias,
        "kpis": {**k, **{"ips": k2["ips"], "primeiro": _iso(k2["primeiro"]), "ultimo": _iso(k2["ultimo"])}},
        "serie": [{"janela": s["janela"].isoformat(), "logins": s["logins"], "falhas": s["falhas"],
                   "eventos": s["eventos"]} for s in serie],
        "granularidade": inv["granularidade"], "fuso": inv["fuso"],
        "por_aplicacao": [{"instancia": insts.get(r["instancia_id"]), "realm": r["realm"], "cliente": r["cliente"],
                           "logins": r["logins"], "falhas": r["falhas"], "eventos": r["eventos"]} for r in por_app],
        "mapa_calor": calor,
        "ranking_ips": [{"ip": rot("ip", r["ps_ip"]), "eventos": r["n"], "falhas": r["falhas"], "contas": r["contas"],
                         "primeiro": _iso(r["primeiro"]), "ultimo": _iso(r["ultimo"])} for r in ips],
        "ranking_aplicacoes": [{"instancia": insts.get(r["instancia_id"]), "realm": r["realm"],
                                "cliente": r["cliente"], "logins": r["logins"]}
                               for r in sorted(por_app, key=lambda r: -r["logins"])[:TOPO] if r["logins"]],
        "destaques": dest["itens"], "resumo_destaques": dest["resumo"],
        "saude_prova": saude_prova(cx, inv["id"]),
        "cobertura": selo_cobertura(cx, inv),
        "opcoes": opcoes_filtro(cx, inv["id"], insts),
        "analise": estado(cx, inv["id"]),
    }


def opcoes_filtro(cx, inv_id: int, insts: dict) -> dict:
    rs = cx.execute("SELECT DISTINCT instancia_id, realm, nullif(client_id,'') AS cliente FROM agregado_hora "
                    "WHERE investigacao_id=%s", (inv_id,)).fetchall()
    return {"instancias": sorted({insts.get(r["instancia_id"]) for r in rs if insts.get(r["instancia_id"])}),
            "realms": sorted({r["realm"] for r in rs}),
            "clientes": sorted({r["cliente"] for r in rs if r["cliente"]}), "categorias": list(CATEGORIAS)}


def estado(cx, inv_id: int) -> dict:
    a = cx.execute("SELECT * FROM analise WHERE investigacao_id=%s", (inv_id,)).fetchone()
    if not a:
        return {"versao": 0, "calculado_em": None, "recalculando": False, "motivo": None}
    return {"versao": a["versao"], "calculado_em": a["calculado_em"].isoformat() if a["calculado_em"] else None,
            "recalculando": a["recalculo_pedido_em"] is not None, "motivo": a["motivo_recalculo"]}


def saude_prova(cx, inv_id: int) -> dict:
    t = cx.execute("""SELECT count(*) AS fatias, count(*) FILTER (WHERE status='limite') AS em_limite,
          count(*) FILTER (WHERE releitura IS NOT NULL) AS relidas,
          count(*) FILTER (WHERE releitura IN ('divergente','divergente_conteudo','possivel_alteracao')) AS divergentes,
          count(*) FILTER (WHERE status IN ('falhou','sem_permissao')) AS falharam
        FROM tarefa WHERE investigacao_id=%s""", (inv_id,)).fetchone()
    s = cx.execute("SELECT count(DISTINCT tarefa_id) AS seladas, max(criado_em) AS ultimo FROM selo "
                   "WHERE investigacao_id=%s", (inv_id,)).fetchone()
    a = cx.execute("SELECT max(criado_em) AS q FROM ancora").fetchone()
    return {**t, "seladas": s["seladas"], "ultimo_selo": s["ultimo"].isoformat() if s["ultimo"] else None,
            "ultima_ancora": a["q"].isoformat() if a and a["q"] else None}


def selo_cobertura(cx, inv: dict) -> dict:
    cob = cx.execute("SELECT * FROM cobertura WHERE investigacao_id=%s", (inv["id"],)).fetchall()
    if not cob:
        return {"calculada": False}
    fr = fracoes(inv, cob)
    return {"calculada": True, "realms_cobertos": fr["realms"][0], "realms": fr["realms"][1],
            "dias_cobertos": fr["tempo"][0], "dias": fr["tempo"][1], "completa": fr["completa"]}


# ------------------------------------------------------------------ eventos (paginação por chave)
def _cursor(r: dict) -> str:
    return base64.urlsafe_b64encode(json.dumps([r["time_ms"], r["instancia_id"], r["realm"], r["id"]]).encode()).decode()


def ref_evento(r: dict) -> str:
    return base64.urlsafe_b64encode(json.dumps([r["instancia_id"], r["realm"], r["id"]]).encode()).decode().rstrip("=")


def abrir_ref(ref: str) -> tuple[int, str, str]:
    inst, realm, eid = json.loads(base64.urlsafe_b64decode(ref + "=" * (-len(ref) % 4)))
    return int(inst), str(realm), str(eid)


def eventos(cx, inv: dict, q: dict) -> dict:
    f = Filtros(cx, inv, q)
    rot = Rotulos(cx, inv["id"])
    insts = {r["id"]: r["nome"] for r in cx.execute("SELECT id, nome FROM instancia")}
    limite = max(1, min(int(q.get("limite") or 50), LIMITE_EVENTOS))
    a = dict(f.args)
    if f.vazio:
        total_f = 0
        linhas = []
    else:
        total_f = contar_eventos(cx, f)
        w = f.W
        if q.get("apos"):
            t, i, r, eid = json.loads(base64.urlsafe_b64decode(q["apos"]))
            a.update(c_t=t, c_i=i, c_r=r, c_id=eid)
            w += " AND (e.time_ms, e.instancia_id, e.realm, e.id) > (%(c_t)s, %(c_i)s, %(c_r)s, %(c_id)s)"
        linhas = cx.execute(f"""SELECT e.time_ms, e.instancia_id, e.realm, e.id, e.client_id, e.type, e.error,
              e.ps_conta, e.ps_ip, e.ps_sessao, c.via {FROM_EV} WHERE {w}
            ORDER BY e.time_ms, e.instancia_id, e.realm, e.id LIMIT {limite + 1}""", a).fetchall()
    total = cx.execute("SELECT coalesce(sum(n),0)::int n FROM agregado_hora WHERE investigacao_id=%s",
                       (inv["id"],)).fetchone()["n"]
    mais = len(linhas) > limite
    linhas = linhas[:limite]
    return {"total": total, "total_filtrado": total_f, "filtros": f.ativos(),
            "preliminar": inv["status"] not in FINAIS, "rotulos_definitivos": rot.numerados,
            "proximo": _cursor(linhas[-1]) if mais and linhas else None,
            "itens": [{"ref": ref_evento(r), "horario": _iso(r["time_ms"]), "instancia": insts.get(r["instancia_id"]),
                       "realm": r["realm"], "aplicacao": r["client_id"], "tipo": r["type"],
                       "tipo_nome": nome_evento(r["type"]), "categoria": categoria(r["type"]),
                       "conta": _conta_rot(rot, r), "ip": rot("ip", r["ps_ip"]), "sessao": rot("sessao", r["ps_sessao"]),
                       "resultado": "Sucesso" if not r["error"] else ERROS.get(r["error"], r["error"])}
                      for r in linhas]}


def contar_eventos(cx, f: "Filtros") -> int:
    """Total com filtro: dos agregados quando os filtros são só dimensões (e conta, IP ou tipo), senão do evento."""
    extra = f.extras
    if not extra - {"tipo", "conta"}:
        w = f.WA + (" AND a.type = ANY(%(f_tipo)s)" if "tipo" in extra else "") + (
            " AND a.ps_conta = %(f_conta)s" if "conta" in extra else "")
        return cx.execute(f"SELECT coalesce(sum(n),0)::int n FROM agregado_hora a WHERE {w}", f.args).fetchone()["n"]
    if not extra - {"tipo", "conta", "ip"}:
        w = f.WA + " AND a.ps_ip = %(f_ip)s" + (" AND a.type = ANY(%(f_tipo)s)" if "tipo" in extra else "") + (
            " AND a.ps_conta = %(f_conta)s" if "conta" in extra else "")
        return cx.execute(f"SELECT coalesce(sum(n),0)::int n FROM agregado_ip a WHERE {w}", f.args).fetchone()["n"]
    return cx.execute(f"SELECT count(*) n {FROM_EV} WHERE {f.W}", f.args).fetchone()["n"]


def _conta_rot(rot: Rotulos, r: dict) -> str | None:
    if r.get("via") == "varredura":
        return "Tentativas com o identificador"
    return rot("conta", r["ps_conta"])


def detalhe_evento(cx, inv: dict, ref: str, cofre, visao) -> dict:
    from .sigilo import abrir_evento, contas as contas_abertas
    inst, realm, eid = abrir_ref(ref)
    r = cx.execute(f"""SELECT e.*, c.via {FROM_EV} WHERE e.investigacao_id=%s AND e.instancia_id=%s AND e.realm=%s
        AND e.id=%s""", (inv["id"], inst, realm, eid)).fetchone()
    if not r:
        return {}
    rot = Rotulos(cx, inv["id"])
    e = abrir_evento(cofre, r)
    visao.conhecer(contas_abertas(cx, cofre), [e])   # valores pessoais conhecidos viram o pseudônimo nos textos
    selo = cx.execute("""SELECT s.id, s.raiz, s.versao, s.inicio_ms, s.fim_ms, s.n_eventos, s.criado_em, s.tarefa_id
        FROM selo s WHERE s.investigacao_id=%s AND s.conta_id=%s AND s.inicio_ms <= %s AND s.fim_ms > %s
        ORDER BY s.versao DESC, s.id DESC LIMIT 1""", (inv["id"], r["conta_id"], r["time_ms"], r["time_ms"])).fetchone()
    nome_inst = cx.execute("SELECT nome FROM instancia WHERE id=%s", (inst,)).fetchone()["nome"]
    bruto = dict(e.get("bruto") or {})
    for k in ("userId", "ipAddress", "sessionId"):
        bruto.pop(k, None)
    return {
        "ref": ref, "horario": _iso(r["time_ms"]), "instancia": nome_inst, "realm": realm, "aplicacao": r["client_id"],
        "tipo": r["type"], "tipo_nome": nome_evento(r["type"]), "categoria": categoria(r["type"]),
        "resultado": "Sucesso" if not r["error"] else ERROS.get(r["error"], r["error"]),
        "conta": _conta_rot(rot, r), "ip": rot("ip", r["ps_ip"]), "sessao": rot("sessao", r["ps_sessao"]),
        "detalhes": visao.json(e.get("details") or {}),
        "json": visao.json(bruto),
        "folha": r["folha"], "hash_conteudo": r["hash_conteudo"],
        "selo": ({"id": selo["id"], "raiz": selo["raiz"], "versao": selo["versao"], "eventos": selo["n_eventos"],
                  "inicio": _iso(selo["inicio_ms"]), "fim": _iso(selo["fim_ms"]),
                  "selado_em": selo["criado_em"].isoformat(), "tarefa": selo["tarefa_id"]} if selo else None),
        "requisicao": _requisicao(cx, inv["id"], inst, selo),
        "evento_id": eid,
    }


def _requisicao(cx, inv_id: int, inst: int, selo) -> dict | None:
    """A requisição de origem: a resposta da coleta daquela fatia (sha256 do corpo, já guardado minimizado)."""
    if not selo:
        return None
    t = cx.execute("SELECT inicio_ms, fim_ms FROM tarefa WHERE id=%s", (selo["tarefa_id"],)).fetchone()
    if not t:
        return None
    r = cx.execute("""SELECT id, metodo, status, inicio, ms, sha256 FROM requisicao WHERE investigacao_id=%s
        AND instancia_id=%s AND caminho LIKE '%%/events%%' AND inicio <= %s ORDER BY inicio DESC LIMIT 1""",
                   (inv_id, inst, selo["criado_em"])).fetchone()
    return ({"id": r["id"], "metodo": r["metodo"], "status": r["status"], "quando": r["inicio"].isoformat(),
             "ms": r["ms"], "sha256": r["sha256"]} if r else None)


# ------------------------------------------------------------------ contas
def contas(cx, inv: dict) -> list[dict]:
    rot = Rotulos(cx, inv["id"])
    insts = {r["id"]: r["nome"] for r in cx.execute("SELECT id, nome FROM instancia")}
    n_ev = {r["conta_id"]: r for r in cx.execute(
        "SELECT conta_id, count(*) n, min(time_ms) p, max(time_ms) u FROM evento WHERE investigacao_id=%s "
        "AND time_ms >= %s AND time_ms < %s GROUP BY 1", (inv["id"], inv["inicio_ms"], inv["fim_ms"]))}
    extras = {(r["conta_id"], r["tipo"]): r["n"] for r in cx.execute(
        "SELECT conta_id, tipo, count(*) n FROM conta_extra WHERE investigacao_id=%s GROUP BY 1,2", (inv["id"],))}
    dec = {}
    for r in cx.execute("SELECT DISTINCT ON (conta_id) * FROM conta_decisao WHERE investigacao_id=%s "
                        "ORDER BY conta_id, quando DESC", (inv["id"],)):
        dec[r["conta_id"]] = r
    rs = cx.execute("SELECT id, instancia_id, realm, via, origem, criado_ms, habilitada, incluida, ps_conta FROM conta "
                    "WHERE investigacao_id=%s ORDER BY instancia_id, realm, id", (inv["id"],)).fetchall()
    por_par: dict = {}
    for c in rs:
        if c["via"] not in ("varredura", "realm"):
            por_par.setdefault((c["instancia_id"], c["realm"]), []).append(c["id"])
    out = []
    for c in rs:
        e = n_ev.get(c["id"]) or {}
        d = dec.get(c["id"])
        out.append({"id": c["id"], "conta": _conta_rot(rot, c), "instancia": insts.get(c["instancia_id"]),
                    "realm": c["realm"], "via": c["via"], "origem": c["origem"], "habilitada": c["habilitada"],
                    "criada_em": _iso(c["criado_ms"]), "incluida": c["incluida"],
                    "duplicidade": len(por_par.get((c["instancia_id"], c["realm"]), [])) > 1,
                    "eventos": e.get("n", 0), "primeiro": _iso(e.get("p")), "ultimo": _iso(e.get("u")),
                    "sessoes_ativas": extras.get((c["id"], "sessao"), 0),
                    "alteracoes": extras.get((c["id"], "admin"), 0),
                    "decisao": ({"incluida": d["incluida"], "por": d["por"], "quando": d["quando"].isoformat(),
                                 "_motivo": d["motivo_cifrado"], "_id": d["id"]} if d else None)})
    return out


def extras(cx, inv: dict, conta_id: int, cofre, visao) -> dict:
    from .sigilo import abrir_extra, contas as contas_abertas
    visao.conhecer(contas_abertas(cx, cofre), [])
    sessoes, alteracoes = [], []
    for x in cx.execute("SELECT * FROM conta_extra WHERE investigacao_id=%s AND conta_id=%s ORDER BY id",
                        (inv["id"], conta_id)):
        d = abrir_extra(cofre, x)["dados"] or {}
        if x["tipo"] == "sessao":
            sessoes.append({"ip": visao.ip_valor(d.get("ipAddress")), "inicio": _iso(d.get("start")),
                            "ultimo_acesso": _iso(d.get("lastAccess")),
                            "aplicacoes": sorted((d.get("clients") or {}).values())})
        else:
            alteracoes.append({"quando": _iso(d.get("time")), "operacao": d.get("operationType"),
                               "recurso": visao.texto(d.get("resourcePath")),
                               "autor_ip": visao.ip_valor((d.get("authDetails") or {}).get("ipAddress")),
                               "dados": visao.json({k: v for k, v in d.items() if k not in ("authDetails",)})})
    return {"sessoes_ativas": sessoes, "alteracoes": alteracoes}


# ------------------------------------------------------------------ cobertura
CLASSES = {"coberto": "Coberto", "parcial": "Parcial", "sem_dados": "Sem dados"}


def cobertura(cx, inv: dict) -> dict:
    rot = Rotulos(cx, inv["id"])
    insts = {r["id"]: r["nome"] for r in cx.execute("SELECT id, nome FROM instancia")}
    cob = cx.execute("SELECT co.*, c.ps_conta, c.via FROM cobertura co LEFT JOIN conta c ON c.id=co.conta_id "
                     "WHERE co.investigacao_id=%s ORDER BY co.instancia_id, co.realm", (inv["id"],)).fetchall()
    tarefas = cx.execute("SELECT conta_id, inicio_ms, fim_ms, status, releitura FROM tarefa WHERE investigacao_id=%s "
                         "AND inicio_ms >= %s ORDER BY inicio_ms", (inv["id"], inv["inicio_ms"])).fetchall()
    por_conta: dict = {}
    for t in tarefas:
        por_conta.setdefault(t["conta_id"], []).append(t)
    linhas = []
    for c in cob:
        faixas = _faixas(por_conta.get(c["conta_id"], []), inv) if c["conta_id"] else (
            [{"de": _iso(inv["inicio_ms"]), "ate": _iso(inv["fim_ms"]), "classe": c["classe"]}])
        linhas.append({"instancia": insts.get(c["instancia_id"]), "realm": c["realm"],
                       "conta": _conta_rot(rot, c) if c["conta_id"] else None, "classe": c["classe"],
                       "classe_nome": CLASSES.get(c["classe"], c["classe"]), "situacao": c["status"],
                       "motivo": c["detalhe"], "acao": c["acao"], "desde": _iso(c["desde_ms"]), "faixas": faixas})
    return {"selo": selo_cobertura(cx, inv), "linhas": linhas, "de": _iso(inv["inicio_ms"]), "ate": _iso(inv["fim_ms"])}


def _faixas(ts: list[dict], inv: dict) -> list[dict]:
    """Fatias consecutivas com a mesma classe viram uma faixa (de, ate, classe)."""
    def classe(t):
        if t["status"] in ("falhou", "sem_permissao", "cancelada"):
            return "sem_dados"
        if t["status"] == "limite" or t["releitura"] in ("divergente", "divergente_conteudo", "possivel_alteracao"):
            return "parcial"
        if t["status"] in ("pendente", "executando"):
            return "pendente"
        return "coberto"
    out: list[dict] = []
    for t in ts:
        k = classe(t)
        if out and out[-1]["classe"] == k and out[-1]["_fim"] >= t["inicio_ms"]:
            out[-1]["_fim"] = max(out[-1]["_fim"], t["fim_ms"])
        else:
            out.append({"classe": k, "_ini": t["inicio_ms"], "_fim": t["fim_ms"]})
    return [{"de": _iso(f["_ini"]), "ate": _iso(min(f["_fim"], inv["fim_ms"])), "classe": f["classe"]} for f in out]


# ------------------------------------------------------------------ visão agregada (solicitante)
def visao_agregada(cx, inv: dict) -> dict:
    """Totais de logins e falhas, série por dia e aplicações por quantidade, mais a cobertura. Sem IPs, contas nem
    pseudônimos (§7.3)."""
    f = Filtros(cx, inv, {})
    a = {**f.args, "logins": list(LOGINS), "falhas": list(FALHAS)}
    k = cx.execute(f"""SELECT coalesce(sum(n) FILTER (WHERE a.type = ANY(%(logins)s)),0)::int AS logins,
          coalesce(sum(n) FILTER (WHERE a.type = ANY(%(falhas)s)),0)::int AS falhas,
          count(DISTINCT nullif(a.client_id,'')) FILTER (WHERE a.type = ANY(%(logins)s)) AS aplicacoes
        FROM agregado_hora a WHERE {f.WA}""", a).fetchone()
    dias = cx.execute(f"""SELECT date_trunc('day', a.hora AT TIME ZONE %(fuso)s) AS dia,
          coalesce(sum(n) FILTER (WHERE a.type = ANY(%(logins)s)),0)::int AS logins,
          coalesce(sum(n) FILTER (WHERE a.type = ANY(%(falhas)s)),0)::int AS falhas
        FROM agregado_hora a WHERE {f.WA} GROUP BY 1 ORDER BY 1""", a).fetchall()
    apps = cx.execute(f"""SELECT nullif(a.client_id,'') AS aplicacao, sum(n)::int AS logins FROM agregado_hora a
        WHERE {f.WA} AND a.type = ANY(%(logins)s) GROUP BY 1 ORDER BY 2 DESC""", a).fetchall()
    return {"kpis": k, "serie_dia": [{"dia": d["dia"].date().isoformat(), "logins": d["logins"],
                                      "falhas": d["falhas"]} for d in dias],
            "aplicacoes": [x for x in apps if x["aplicacao"]], "cobertura": selo_cobertura(cx, inv),
            "fuso": inv["fuso"]}


def agora() -> datetime:
    return datetime.now(timezone.utc)


__all__ = ["calcular", "preliminar", "pedir_recalculo", "dashboard", "eventos", "detalhe_evento", "contas", "extras",
           "cobertura", "visao_agregada", "rajadas", "fora_expediente", "timedelta"]

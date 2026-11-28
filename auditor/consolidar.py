"""Consolidação por janela de tempo, KPIs, destaques e cobertura — base do dashboard e da planilha."""
from __future__ import annotations

from datetime import datetime, timezone
from zoneinfo import ZoneInfo

from . import sigilo
from .db import conectar, percorrer
from .kc import ClienteKC, ErroKC

GLOSSARIO = {
    "LOGIN": ("Login", "Acesso"), "IDENTITY_PROVIDER_LOGIN": ("Login via provedor externo", "Acesso"),
    "LOGIN_ERROR": ("Falha de login", "Acesso"),
    "IDENTITY_PROVIDER_LOGIN_ERROR": ("Falha de login via provedor externo", "Acesso"),
    "LOGOUT": ("Logout", "Acesso"), "LOGOUT_ERROR": ("Falha de logout", "Acesso"),
    "CODE_TO_TOKEN": ("Emissão de token", "Técnico"), "CODE_TO_TOKEN_ERROR": ("Falha na emissão de token", "Técnico"),
    "REFRESH_TOKEN": ("Renovação de sessão", "Técnico"),
    "REFRESH_TOKEN_ERROR": ("Falha na renovação de sessão", "Técnico"),
    "TOKEN_EXCHANGE": ("Troca de token", "Técnico"), "TOKEN_EXCHANGE_ERROR": ("Falha na troca de token", "Técnico"),
    "UPDATE_PASSWORD": ("Alteração de senha", "Conta"), "RESET_PASSWORD": ("Redefinição de senha", "Conta"),
    "UPDATE_TOTP": ("Configuração de OTP", "Conta"), "REMOVE_TOTP": ("Remoção de OTP", "Conta"),
    "UPDATE_PROFILE": ("Alteração de perfil", "Conta"), "UPDATE_EMAIL": ("Alteração de e-mail", "Conta"),
}
ERROS = {"invalid_user_credentials": "Senha incorreta", "user_not_found": "Usuário inexistente",
         "user_disabled": "Conta desabilitada", "user_temporarily_disabled": "Bloqueio temporário",
         "invalid_redirect_uri": "Endereço de retorno inválido", "expired_code": "Código expirado"}
LOGINS = ("LOGIN", "IDENTITY_PROVIDER_LOGIN")
FALHAS = ("LOGIN_ERROR", "IDENTITY_PROVIDER_LOGIN_ERROR")
GRAN = {"hora": "hour", "dia": "day", "semana": "week", "mes": "month"}
EXPEDIENTE = (7, 19)  # seg–sex, horas locais


def nome_evento(t: str) -> str:
    return GLOSSARIO.get(t, (t, "Outro"))[0]


def categoria(t: str) -> str:
    return GLOSSARIO.get(t, (t, "Outro"))[1]


def _case_categoria() -> str:
    partes = " ".join(f"WHEN '{k}' THEN '{v[1]}'" for k, v in GLOSSARIO.items())
    return f"CASE e.type {partes} ELSE 'Outro' END"


def extras_conta(inv_id: int):
    """Sessões ativas (fotografia) e alterações administrativas na conta (admin events)."""
    with conectar() as cx:
        cx.execute("DELETE FROM conta_extra WHERE investigacao_id=%s", (inv_id,))
        inv = cx.execute("SELECT * FROM investigacao WHERE id=%s", (inv_id,)).fetchone()
        cf = sigilo.Cofre(inv_id, "fechar")
        contas = [c for c in sigilo.contas(cx, cf, "AND c.incluida") if c.get("user_id")]
        insts = {i["id"]: i for i in cx.execute("SELECT * FROM instancia")}
        clis = {}
        try:
            for c in contas:
                inst = insts[c["instancia_id"]]
                cli = clis.setdefault(inst["id"], ClienteKC(inst, inv_id, finalidade="fechar"))
                d1 = datetime.fromtimestamp(inv["inicio_ms"] / 1000, timezone.utc).strftime("%Y-%m-%d")
                for tipo, caminho, params in (
                        ("sessao", f"/admin/realms/{c['realm']}/users/{c['user_id']}/sessions", None),
                        ("admin", f"/admin/realms/{c['realm']}/admin-events",
                         {"resourcePath": f"users/{c['user_id']}*", "dateFrom": d1, "max": "500"})):
                    try:
                        for d in cli.get(caminho, params):
                            xid = cx.execute("SELECT nextval('conta_extra_id_seq') AS n").fetchone()["n"]
                            cx.execute("INSERT INTO conta_extra (id, investigacao_id, conta_id, tipo, cifrado) "
                                       "VALUES (%s,%s,%s,%s,%s)",
                                       (xid, inv_id, c["id"], tipo, cf.cifrar("conta_extra", "dados", xid, d)))
                    except ErroKC:
                        pass
        finally:
            for cli in clis.values():
                cli.fechar()


def consolidar(inv_id: int, filtros: dict | None = None, finalidade: str = "exportar", com_eventos: bool = True,
               amostra: int | None = None) -> dict:
    """Retorna todos os blocos do relatório. filtros: instancia, realm, cliente, categoria (lista).

    `com_eventos=False` (pacote v2, em streaming): os eventos são lidos por cursor e não ficam na memória; `eventos`
    traz só os `amostra` primeiros (para o dashboard HTML), `n_eventos` o total, e os destaques são calculados no
    mesmo percurso.

    Os agregados são calculados em SQL sobre os pseudônimos (ps_ip); conta, IP e sessão em claro só existem em
    memória, decifrados com a DEK. Cada linha traz o valor e o pseudônimo, e a visão (pseudonimos.Visao) decide o que
    aparece."""
    f = filtros or {}
    with conectar() as cx:
        inv = cx.execute("SELECT * FROM investigacao WHERE id=%s", (inv_id,)).fetchone()
        cf = sigilo.Cofre(inv_id, finalidade)
        tz = ZoneInfo(inv["fuso"])
        insts = {i["id"]: i["nome"] for i in cx.execute("SELECT id, nome FROM instancia")}
        where = ["e.investigacao_id=%(inv)s", "e.time_ms >= %(ini)s", "e.time_ms < %(fim)s",
                 "c.incluida"]
        args = {"inv": inv_id, "ini": inv["inicio_ms"], "fim": inv["fim_ms"], "fuso": inv["fuso"],
                "gran": GRAN[inv["granularidade"]]}
        if f.get("instancia"):
            where.append("i.nome = %(f_inst)s"); args["f_inst"] = f["instancia"]
        if f.get("realm"):
            where.append("e.realm = %(f_realm)s"); args["f_realm"] = f["realm"]
        if f.get("cliente"):
            where.append("e.client_id = %(f_cli)s"); args["f_cli"] = f["cliente"]
        cats = f.get("categorias") or ["Acesso", "Conta"]
        where.append(f"({_case_categoria()}) = ANY(%(cats)s)"); args["cats"] = cats
        W = " AND ".join(where)
        FROM = "FROM evento e JOIN conta c ON c.id=e.conta_id JOIN instancia i ON i.id=e.instancia_id"
        contas = sigilo.contas(cx, cf)
        por_id = {c["id"]: c for c in contas}

        k = cx.execute(f"""SELECT
              count(*) FILTER (WHERE e.type = ANY(%(logins)s)) AS logins,
              count(*) FILTER (WHERE e.type = ANY(%(falhas)s)) AS falhas,
              count(DISTINCT e.client_id) FILTER (WHERE e.type = ANY(%(logins)s)) AS aplicacoes,
              count(DISTINCT e.ps_ip) FILTER (WHERE e.type = ANY(%(logins)s) OR e.type = ANY(%(falhas)s)) AS ips,
              min(e.time_ms) FILTER (WHERE e.type = ANY(%(logins)s)) AS primeiro,
              max(e.time_ms) FILTER (WHERE e.type = ANY(%(logins)s)) AS ultimo,
              count(*) AS eventos
            {FROM} WHERE {W}""", {**args, "logins": list(LOGINS), "falhas": list(FALHAS)}).fetchone()

        janelas = cx.execute(f"""SELECT date_trunc(%(gran)s, to_timestamp(e.time_ms/1000.0) AT TIME ZONE %(fuso)s) AS janela,
              i.nome AS instancia, e.realm, e.client_id, e.type, count(*) AS n, count(DISTINCT e.ps_ip) AS ips
            {FROM} WHERE {W} GROUP BY 1,2,3,4,5 ORDER BY 1,2,3,4,5""", args).fetchall()
        por_app = cx.execute(f"""SELECT i.nome AS instancia, e.realm, e.client_id,
              count(*) FILTER (WHERE e.type = ANY(%(logins)s)) AS logins,
              count(*) FILTER (WHERE e.type = ANY(%(falhas)s)) AS falhas,
              min(e.time_ms) AS primeiro, max(e.time_ms) AS ultimo
            {FROM} WHERE {W} GROUP BY 1,2,3 ORDER BY 4 DESC""",
                             {**args, "logins": list(LOGINS), "falhas": list(FALHAS)}).fetchall()
        por_ip = cx.execute(f"""SELECT e.ps_ip, count(*) AS n,
              count(*) FILTER (WHERE e.type = ANY(%(falhas)s)) AS falhas,
              min(e.time_ms) AS primeiro, max(e.time_ms) AS ultimo,
              string_agg(DISTINCT i.nome || '/' || e.realm, ', ') AS onde
            {FROM} WHERE {W} GROUP BY 1 ORDER BY 2 DESC, 1""", {**args, "falhas": list(FALHAS)}).fetchall()
        heat = cx.execute(f"""SELECT extract(isodow FROM to_timestamp(e.time_ms/1000.0) AT TIME ZONE %(fuso)s)::int AS dow,
              extract(hour FROM to_timestamp(e.time_ms/1000.0) AT TIME ZONE %(fuso)s)::int AS hora, count(*) AS n
            {FROM} WHERE {W} AND e.type = ANY(%(logins)s) GROUP BY 1,2""",
                          {**args, "logins": list(LOGINS)}).fetchall()
        # ---- eventos (lista inteira, ou percurso por cursor) e destaques no mesmo passo
        base_dias = inv["parametros"].get("base_dias") or 0
        base_ips = {r["ps_ip"] for r in cx.execute(
            "SELECT DISTINCT e.ps_ip FROM evento e JOIN conta c ON c.id=e.conta_id AND c.incluida "
            "WHERE e.investigacao_id=%s AND e.time_ms < %s", (inv_id, inv["inicio_ms"]))} if base_dias else set()
        sql_ev = f"""SELECT e.time_ms, i.nome AS instancia, e.instancia_id, e.realm, e.conta_id, c.via, e.type,
              e.client_id, e.error, e.id, e.cifrado, e.ps_conta, e.ps_ip, e.ps_sessao,
              e.user_id, e.session_id, e.ip, e.details, e.bruto
            {FROM} WHERE {W} ORDER BY e.time_ms, e.id"""
        eventos, fora, falhas, ip_novo, vistos, valores, n_ev = [], [], [], [], set(), {}, 0
        linhas = cx.execute(sql_ev, args) if com_eventos else percorrer(cx, sql_ev, args)
        for r in linhas:
            e = sigilo.abrir_evento(cf, r)
            c = por_id[e["conta_id"]]
            e["username"], e["conta_ps"] = c.get("username"), c.get("ps_conta")
            e.pop("cifrado", None)
            if not com_eventos:   # streaming: só os campos que os destaques e o dashboard usam
                e.pop("bruto", None)
                if len(eventos) >= (amostra or 0):
                    e = _Leve(e)
            n_ev += 1
            if e["ps_ip"] and e["ip"]:
                valores[("ip", e["ps_ip"])] = e["ip"]
            if e["ps_sessao"] and e["session_id"]:
                valores[("sessao", e["ps_sessao"])] = e["session_id"]
            if com_eventos or len(eventos) < (amostra or 0):
                eventos.append(e)
            if e["type"] in LOGINS and _fora_expediente(e["time_ms"], tz):
                fora.append(e)
            elif e["type"] in FALHAS:
                falhas.append(e)
            if base_dias and e["ps_ip"] and e["ps_ip"] not in base_ips and e["ps_ip"] not in vistos:
                vistos.add(e["ps_ip"])
                ip_novo.append(e)
        for r in por_ip:
            r["ip"] = valores.get(("ip", r["ps_ip"]))
        rajadas = _rajadas(falhas)
        if not base_dias:
            ip_novo = None

        cob = cx.execute("""SELECT co.*, i.nome AS instancia FROM cobertura co
              JOIN instancia i ON i.id=co.instancia_id
              WHERE co.investigacao_id=%s ORDER BY i.nome, co.realm""", (inv_id,)).fetchall()
        for c in cob:
            conta = por_id.get(c["conta_id"]) or {}
            c.update(username=conta.get("username"), via=conta.get("via"), ps_conta=conta.get("ps_conta"),
                     user_id=conta.get("user_id"))
        if f.get("instancia"):
            cob = [c for c in cob if c["instancia"] == f["instancia"]]
        if f.get("realm"):
            cob = [c for c in cob if c["realm"] == f["realm"]]
        extras = []
        for x in cx.execute("SELECT x.*, c.realm, i.nome AS instancia FROM conta_extra x "
                            "JOIN conta c ON c.id=x.conta_id JOIN instancia i ON i.id=c.instancia_id "
                            "WHERE x.investigacao_id=%s ORDER BY x.id", (inv_id,)):
            x = sigilo.abrir_extra(cf, x)
            conta = por_id.get(x["conta_id"]) or {}
            x.update(username=conta.get("username"), via=conta.get("via"), ps_conta=conta.get("ps_conta"))
            extras.append(x)
        tarefas = cx.execute("SELECT status, releitura, count(*) n FROM tarefa WHERE investigacao_id=%s "
                             "GROUP BY 1,2", (inv_id,)).fetchall()
        reqs = cx.execute("SELECT count(*) n, avg(ms) media, percentile_cont(0.95) WITHIN GROUP (ORDER BY ms) p95 "
                          "FROM requisicao WHERE investigacao_id=%s", (inv_id,)).fetchone()

    fr = fracoes(inv, cob)
    return {"inv": inv, "kpis": k, "janelas": janelas, "por_app": por_app, "por_ip": por_ip, "heat": heat,
            "eventos": eventos, "n_eventos": n_ev, "valores": valores, "fora": fora, "rajadas": rajadas, "ip_novo": ip_novo, "cobertura": cob,
            "fracoes": fr, "contas": contas, "extras": extras, "tarefas": tarefas, "requisicoes": reqs,
            "filtros": {**f, "categorias": cats}, "instancias": insts, "cofre": cf}


_CAMPOS_DESTAQUE = ("time_ms", "instancia", "instancia_id", "realm", "conta_id", "via", "type", "client_id", "ps_ip",
                    "ip", "ps_sessao", "session_id", "username", "conta_ps", "user_id", "id")


class _Leve:
    """Evento guardado só para os destaques (streaming): os campos usados, em slots, sem o dict inteiro."""
    __slots__ = _CAMPOS_DESTAQUE

    def __init__(self, e: dict):
        for k in _CAMPOS_DESTAQUE:
            setattr(self, k, e.get(k))

    def __getitem__(self, k):
        return getattr(self, k)

    def get(self, k, padrao=None):
        return getattr(self, k, padrao)


def _fora_expediente(t: int, tz) -> bool:
    d = datetime.fromtimestamp(t / 1000, tz)
    return d.isoweekday() >= 6 or not (EXPEDIENTE[0] <= d.hour < EXPEDIENTE[1])


def _rajadas(falhas: list[dict], minimo=5, janela_ms=600_000) -> list[dict]:
    """>= 5 falhas de login em 10 minutos na mesma conta; rajadas sobrepostas são unidas."""
    out = []
    por_conta: dict = {}
    for e in falhas:
        por_conta.setdefault((e["instancia"], e["realm"], e["username"]), []).append(e)
    for chave, evs in por_conta.items():
        evs.sort(key=lambda x: x["time_ms"])
        i, atual = 0, None
        for j in range(len(evs)):
            while evs[j]["time_ms"] - evs[i]["time_ms"] > janela_ms:
                i += 1
            if j - i + 1 >= minimo:
                ini = evs[i]["time_ms"]
                if atual and ini <= atual["fim"]:
                    atual["fim"] = evs[j]["time_ms"]; atual["n"] = j - atual["_i"] + 1
                else:
                    atual = {"instancia": chave[0], "realm": chave[1], "username": chave[2], "inicio": ini,
                             "fim": evs[j]["time_ms"], "n": j - i + 1, "_i": i, "conta": evs[i],
                             "ips": sorted({(x["ps_ip"], x["ip"]) for x in evs[i:j + 1]}, key=lambda p: p[0] or "")}
                    out.append(atual)
    for r in out:
        r.pop("_i", None)
    return out


def fracoes(inv: dict, cob: list[dict]) -> dict:
    """Fração de realms (pares cobertos ÷ pesquisados) e de tempo (dias com dados em todas as contas)."""
    total = len(cob)
    cobertos = sum(1 for c in cob if c["classe"] == "coberto")
    dias_periodo = max(1, round((inv["fim_ms"] - inv["inicio_ms"]) / 86400_000))
    com_conta = [c for c in cob if c["conta_id"] is not None and c["classe"] != "sem_dados"]
    if com_conta:
        desde = max((c["desde_ms"] or inv["inicio_ms"]) for c in com_conta)
        dias_ok = max(0, round((inv["fim_ms"] - max(desde, inv["inicio_ms"])) / 86400_000))
        # dias com divergência/expiração/limite reduzem o tempo coberto
        perdidos = set()
        for c in com_conta:
            for parte in (c["detalhe"] or "").split("; "):
                if ":" in parte and ("divergente" in parte or "expirado" in parte):
                    perdidos |= {d.strip() for d in parte.split(":", 1)[1].split(",")}
        dias_ok = max(0, dias_ok - len(perdidos))
    else:
        dias_ok = dias_periodo if total and cobertos == total else 0
    return {"realms": (cobertos, total), "tempo": (min(dias_ok, dias_periodo), dias_periodo),
            "completa": cobertos == total and dias_ok >= dias_periodo}

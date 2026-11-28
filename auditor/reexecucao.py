"""Reexecução, complementação e comparação de execuções (W5, PROPOSTA_WEB §5.4 e §6.7).

* Reexecutar ou ampliar o período gera **nova investigação vinculada** (`execucao_anterior`); a original nunca é
  alterada. Mesmo escopo (repetir para confirmar): basta o registro com motivo, e a nova nasce aprovada, com as mesmas
  designações. Escopo maior (período que começa antes ou termina depois, instâncias novas): o pedido volta para
  aprovação.
* Rótulos herdados: no fechamento da nova, o servidor (que tem as duas DEKs) casa os itens pelo valor original e
  reaproveita o rótulo da investigação de origem; só itens novos ganham números novos. O valor nunca sai do servidor.
* Comparar execuções: eventos novos, eventos que deixaram de existir na origem (expirados ou apagados), eventos com
  conteúdo diferente, contas novas ou excluídas, mudança de cobertura. Casamento pelo id original do evento; no
  Keycloak ≤ 21 (id sintético = hash do conteúdo), os pares "faltando" + "novo" com mesmo horário, tipo e conta viram
  "possível alteração". O resultado só tem rótulos e contagens.
"""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from zoneinfo import ZoneInfo

from psycopg.types.json import Jsonb

from . import chaves, gestao, investigar, merkle, sigilo
from .acesso import Ator, Negado, funcoes, sem_acesso
from .db import conectar, percorrer, trilha

FINAIS = ("concluida", "concluida_com_lacunas", "parcial")


# ------------------------------------------------------------------ reexecutar
def reexecutar(ator: Ator, inv_id: int, motivo: str, de: str | None = None, ate: str | None = None,
               instancias: list[str] | None = None) -> dict:
    """Investigador designado ou solicitante dono. Devolve a nova investigação e se precisa de aprovação."""
    from .casos import _abrir_extras, _abrir_pedido, _gravar_extras, _inv, _motivo
    ator.exigir("investigador", "solicitante")
    ator.exigir_recente()
    _motivo(motivo)
    with conectar() as cx:
        i = _inv(cx, inv_id)
        f = funcoes(cx, inv_id, ator.sub)
        if not (("investigador" in f and ator.tem("investigador")) or
                ("solicitante" in f and ator.tem("solicitante") and i["solicitante_sub"] == ator.sub)):
            raise sem_acesso()
        if i["lacrada"]:
            raise Negado("estado", "Investigação lacrada", 409)
        if i["status"] not in FINAIS:
            raise Negado("estado", "Reexecução só de investigação concluída ou parcial", 409)
        desig = cx.execute("SELECT funcao, sub FROM designacao WHERE investigacao_id=%s", (inv_id,)).fetchall()
    tz_fuso = i["fuso"]
    d_ini = datetime.fromtimestamp(i["inicio_ms"] / 1000, ZoneInfo(tz_fuso))
    d_fim = datetime.fromtimestamp(i["fim_ms"] / 1000, ZoneInfo(tz_fuso))
    de = de or d_ini.strftime("%Y-%m-%dT%H:%M:%S")
    ate = ate or d_fim.strftime("%Y-%m-%dT%H:%M:%S")
    nomes = instancias or (i["parametros"] or {}).get("instancias")
    try:
        ini, fim = investigar.periodo(de, ate, tz_fuso)
    except ValueError as e:
        raise Negado("validacao", str(e), 422) from e
    antes = set((i["parametros"] or {}).get("instancias") or [])
    mesmo_escopo = ini >= i["inicio_ms"] and fim <= i["fim_ms"] and (not antes or set(nomes or []) <= antes) and \
        bool(antes) == bool(nomes)
    with chaves.como_usuario(ator.token):
        cf0 = sigilo.Cofre(inv_id, "consulta")
        dig = chaves.alvo(i, "consulta")
        just0 = sigilo.justificativa(cf0, i)
        extras = _abrir_extras(cf0, i)
        status = "aprovada" if mesmo_escopo else "aguardando_aprovacao"
        try:
            novo = investigar.abrir(ator.sub, f"{just0}\n[Reexecução da nº {inv_id}] {motivo}", i["tipo"], dig, de,
                                    ate, tz_fuso, i["granularidade"], nomes,
                                    bool((i["parametros"] or {}).get("varredura")),
                                    (i["parametros"] or {}).get("base_dias") or 0, anterior=inv_id, status=status,
                                    solicitante_sub=i["solicitante_sub"])
        except ValueError as e:
            raise Negado("validacao", str(e), 422) from e
        dek = sigilo.Cofre(novo, "consulta").dek
    with conectar() as cx:
        _gravar_extras(cx, novo, dek, i["tipo_processo"], extras.get("processo"), extras.get("contas_informadas"),
                       False)
        cx.execute("UPDATE investigacao SET sigilosa=%s WHERE id=%s", (i["sigilosa"], novo))
        copiar = desig if mesmo_escopo else [d for d in desig if d["funcao"] == "solicitante"]
        for d in copiar:
            cx.execute("INSERT INTO designacao (investigacao_id, funcao, sub, designado_por) VALUES (%s,%s,%s,%s) "
                       "ON CONFLICT DO NOTHING", (novo, d["funcao"], d["sub"], ator.sub))
        if not mesmo_escopo:
            _abrir_pedido(cx, novo, i["solicitante_sub"], False)
            gestao.avisar_pedido(cx, novo, i["solicitante_sub"], False)
        acao = "reexecutar_mesmo_escopo" if mesmo_escopo else "reexecutar_novo_escopo"
        trilha(cx, ator.sub, acao, inv_id, nova=novo, motivo=motivo, porta=ator.porta)
        trilha(cx, ator.sub, acao, novo, anterior=inv_id, motivo=motivo, porta=ator.porta)
        gestao.notificar(cx, [d["sub"] for d in copiar if d["sub"] != ator.sub], "reexecucao",
                         f"Investigação nº {novo}: reexecução da nº {inv_id}", novo)
    return {"investigacao": novo, "anterior": inv_id, "status": status, "aprovacao": not mesmo_escopo}


# ------------------------------------------------------------------ herança de rótulos (§5.4)
def _valores(cx, cf: sigilo.Cofre, inv_id: int) -> dict[str, dict[str, str]]:
    """{classe: {hmac: valor}} dos itens da investigação (contas, IPs e sessões), decifrados em memória."""
    out: dict[str, dict[str, str]] = {"conta": {}, "ip": {}, "sessao": {}}
    for c in sigilo.contas(cx, cf):
        if c.get("ps_conta") and c.get("user_id"):
            out["conta"][c["ps_conta"]] = c["user_id"]
    for r in percorrer(cx, "SELECT id, instancia_id, realm, cifrado, ps_ip, ps_sessao FROM evento "
                           "WHERE investigacao_id=%s AND cifrado IS NOT NULL", (inv_id,)):
        e = sigilo.abrir_evento(cf, r)
        if r["ps_ip"] and e["ip"]:
            out["ip"][r["ps_ip"]] = e["ip"]
        if r["ps_sessao"] and e["session_id"]:
            out["sessao"][r["ps_sessao"]] = e["session_id"]
    return out


def herdados(cx, cf: sigilo.Cofre, inv_id: int) -> dict[tuple[str, str], int]:
    """{(classe, hmac na nova): número do rótulo na origem}, casando pelo valor. Vazio se não há origem."""
    i = cx.execute("SELECT execucao_anterior FROM investigacao WHERE id=%s", (inv_id,)).fetchone()
    ant = i and i["execucao_anterior"]
    if not ant:
        return {}
    try:
        cf0 = sigilo.Cofre(ant, cf.finalidade)
    except Exception:  # noqa: BLE001 — origem expurgada (DEK destruída): a herança deixa de existir (RIPD)
        return {}
    rot0 = {(r["classe"], r["hmac"]): r["rotulo"] for r in cx.execute(
        "SELECT classe, hmac, rotulo FROM pseudonimo WHERE investigacao_id=%s", (ant,))}
    v0 = _valores(cx, cf0, ant)
    por_valor = {(classe, v): rot0[(classe, h)] for classe, hs in v0.items() for h, v in hs.items()
                 if (classe, h) in rot0}
    v1 = _valores(cx, cf, inv_id)
    return {(classe, h): por_valor[(classe, v)] for classe, hs in v1.items() for h, v in hs.items()
            if (classe, v) in por_valor}


# ------------------------------------------------------------------ comparar (§6.7)
def _conjunto(cx, cf: sigilo.Cofre, inv_id: int, rot: dict) -> dict:
    evs, contas = {}, {}
    por_id = {c["id"]: c for c in sigilo.contas(cx, cf)}
    for c in por_id.values():
        contas[(c["instancia_id"], c["realm"], c.get("user_id") or c.get("username") or f"#{c['id']}")] = c
    for r in percorrer(cx, "SELECT e.id, e.instancia_id, e.realm, e.cifrado, e.time_ms, e.type, e.conta_id, e.ps_ip, "
                           "e.ps_conta FROM evento e WHERE e.investigacao_id=%s AND e.cifrado IS NOT NULL", (inv_id,)):
        e = sigilo.abrir_evento(cf, r)
        b = e["bruto"]
        idk = b.get("id") or r["id"]
        c = por_id.get(r["conta_id"]) or {}
        evs[(r["instancia_id"], r["realm"], idk)] = {
            "h": hashlib.sha256(merkle.canonico(b)).hexdigest(), "t": r["time_ms"], "tipo": r["type"],
            "inst": r["instancia_id"], "realm": r["realm"], "user": b.get("userId"),
            "conta": rot.get(("conta", c.get("ps_conta"))) or ("Tentativas com o identificador"
                                                               if c.get("via") == "varredura" else "—"),
            "ip": rot.get(("ip", r["ps_ip"])), "sintetico": str(idk).startswith("sha256:")}
    return {"eventos": evs, "contas": contas}


def _item(e: dict, insts: dict) -> dict:
    return {"horario": datetime.fromtimestamp(e["t"] / 1000, timezone.utc).isoformat(), "tipo": e["tipo"],
            "instancia": insts.get(e["inst"]), "realm": e["realm"], "conta": e["conta"], "ip": e["ip"]}


def calcular_comparacao(cx, inv_id: int, finalidade: str = "consulta") -> dict:
    from .consolidar import fracoes
    from .pseudonimos import rotulos
    i = cx.execute("SELECT * FROM investigacao WHERE id=%s", (inv_id,)).fetchone()
    ant = i["execucao_anterior"]
    i0 = cx.execute("SELECT * FROM investigacao WHERE id=%s", (ant,)).fetchone()
    cf1, cf0 = sigilo.Cofre(inv_id, finalidade), sigilo.Cofre(ant, finalidade)
    insts = {r["id"]: r["nome"] for r in cx.execute("SELECT id, nome FROM instancia")}
    a = _conjunto(cx, cf0, ant, rotulos(cx, ant))
    b = _conjunto(cx, cf1, inv_id, rotulos(cx, inv_id))
    comum_ini, comum_fim = max(i["inicio_ms"], i0["inicio_ms"]), min(i["fim_ms"], i0["fim_ms"])
    novos = [k for k in b["eventos"] if k not in a["eventos"]]
    sumidos = [k for k in a["eventos"] if k not in b["eventos"]
               and comum_ini <= a["eventos"][k]["t"] < comum_fim]   # fora do período comum não é "sumiço"
    diferentes = [k for k in b["eventos"] if k in a["eventos"] and b["eventos"][k]["h"] != a["eventos"][k]["h"]]
    # Keycloak ≤ 21: pares faltando + novo com mesmo horário, tipo e conta
    possiveis = []
    chave = lambda e: (e["inst"], e["realm"], e["t"], e["tipo"], e["user"])  # noqa: E731
    idx_novos = {}
    for k in novos:
        e = b["eventos"][k]
        if e["sintetico"]:
            idx_novos.setdefault(chave(e), []).append(k)
    for k in list(sumidos):
        e = a["eventos"][k]
        if e["sintetico"] and idx_novos.get(chave(e)):
            kn = idx_novos[chave(e)].pop()
            novos.remove(kn)
            sumidos.remove(k)
            possiveis.append(kn)
    novos_no_periodo = [k for k in novos if comum_ini <= b["eventos"][k]["t"] < comum_fim]
    contas_novas = [k for k in b["contas"] if k not in a["contas"]]
    contas_sumidas = [k for k in a["contas"] if k not in b["contas"]]
    incl_mudou = [k for k in b["contas"] if k in a["contas"]
                  and bool(b["contas"][k]["incluida"]) != bool(a["contas"][k]["incluida"])]

    def cob(inv):
        rs = cx.execute("SELECT co.*, i.nome AS instancia FROM cobertura co JOIN instancia i ON i.id=co.instancia_id "
                        "WHERE co.investigacao_id=%s", (inv["id"],)).fetchall()
        return rs, fracoes(inv, rs)

    c0, f0 = cob(i0)
    c1, f1 = cob(i)
    m0 = {(r["instancia"], r["realm"], r["conta_id"] is not None): r["classe"] for r in c0}
    m1 = {(r["instancia"], r["realm"], r["conta_id"] is not None): r["classe"] for r in c1}
    mud_cob = [{"instancia": k[0], "realm": k[1], "antes": m0.get(k), "depois": m1.get(k)}
               for k in sorted(set(m0) | set(m1)) if m0.get(k) != m1.get(k)]

    def rot_conta(c):
        from .pseudonimos import NOMES
        r = cx.execute("SELECT rotulo FROM pseudonimo WHERE investigacao_id=%s AND classe='conta' AND hmac=%s",
                       (c["investigacao_id"], c.get("ps_conta"))).fetchone()
        return f"{NOMES['conta']} {r['rotulo']}" if r else ("Tentativas com o identificador"
                                                           if c.get("via") == "varredura" else "—")

    lim = 500
    return {
        "anterior": ant, "investigacao": inv_id, "calculado_em": datetime.now(timezone.utc).isoformat(),
        "periodo_comum": {"de": datetime.fromtimestamp(comum_ini / 1000, timezone.utc).isoformat(),
                          "ate": datetime.fromtimestamp(comum_fim / 1000, timezone.utc).isoformat()},
        "totais": {"anterior": len(a["eventos"]), "atual": len(b["eventos"]), "novos": len(novos),
                   "novos_no_periodo_comum": len(novos_no_periodo), "deixaram_de_existir": len(sumidos),
                   "conteudo_diferente": len(diferentes), "possivel_alteracao": len(possiveis)},
        "novos": [_item(b["eventos"][k], insts) for k in sorted(novos_no_periodo, key=lambda k: b["eventos"][k]["t"])][:lim],
        "deixaram_de_existir": [_item(a["eventos"][k], insts) for k in sorted(sumidos, key=lambda k: a["eventos"][k]["t"])][:lim],
        "conteudo_diferente": [_item(b["eventos"][k], insts) for k in diferentes][:lim],
        "possivel_alteracao": [_item(b["eventos"][k], insts) for k in possiveis][:lim],
        "contas": {"novas": [{"instancia": insts.get(k[0]), "realm": k[1], "conta": rot_conta(b["contas"][k])}
                             for k in contas_novas],
                   "nao_encontradas": [{"instancia": insts.get(k[0]), "realm": k[1], "conta": rot_conta(a["contas"][k])}
                                       for k in contas_sumidas],
                   "inclusao_mudou": [{"instancia": insts.get(k[0]), "realm": k[1], "conta": rot_conta(b["contas"][k]),
                                       "incluida": b["contas"][k]["incluida"]} for k in incl_mudou]},
        "cobertura": {"antes": {"realms": list(f0["realms"]), "tempo": list(f0["tempo"]), "completa": f0["completa"]},
                      "depois": {"realms": list(f1["realms"]), "tempo": list(f1["tempo"]), "completa": f1["completa"]},
                      "mudancas": mud_cob},
        "limite_listas": lim,
    }


def comparar(ator: Ator, inv_id: int, recalcular: bool = False) -> dict:
    """Só o investigador designado nas duas investigações; resultado em cache (tabela comparacao)."""
    from .casos import _inv
    ator.exigir("investigador")
    with conectar() as cx:
        i = _inv(cx, inv_id)
        ant = i["execucao_anterior"]
        if not ant:
            raise Negado("inexistente", "Esta investigação não é reexecução de outra", 404)
        if "investigador" not in funcoes(cx, inv_id, ator.sub) or "investigador" not in funcoes(cx, ant, ator.sub):
            raise sem_acesso()
        if i["status"] not in FINAIS:
            raise Negado("estado", "A comparação fica disponível quando a coleta terminar", 409)
        if not recalcular:
            c = cx.execute("SELECT resultado FROM comparacao WHERE investigacao_id=%s AND anterior_id=%s",
                           (inv_id, ant)).fetchone()
            if c:
                return c["resultado"]
        with chaves.como_usuario(ator.token):
            r = calcular_comparacao(cx, inv_id)
        cx.execute("INSERT INTO comparacao (investigacao_id, anterior_id, resultado) VALUES (%s,%s,%s) "
                   "ON CONFLICT (investigacao_id, anterior_id) DO UPDATE SET resultado=EXCLUDED.resultado, "
                   "calculado_em=now()", (inv_id, ant, Jsonb(json.loads(json.dumps(r, default=str)))))
        trilha(cx, ator.sub, "comparar_execucoes", inv_id, anterior=ant, porta=ator.porta, totais=r["totais"])
    return r

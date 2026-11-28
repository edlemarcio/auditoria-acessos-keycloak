"""Revelação controlada (W4, PROPOSTA_WEB §5.5, §4.4 e §7.5).

* **Sessão de análise**: o investigador designado inicia com um motivo da lista (texto obrigatório para "outro") e
  autenticação recente. Dura até 4 h, prorrogável duas vezes (+1 h cada), com teto de 8 h por usuário por dia (UTC).
  Expira no servidor: depois disso nenhum valor real sai da API.
* **Revelação por item** (conta, IP, sessão ou evento), dentro da sessão: o item fica revelado até o fim dela. Cota de
  30 itens por sessão e 100 por investigação; acima disso, ou para dado de terceiro, só com pedido aprovado por outra
  pessoa (quatro olhos). Revelação total da investigação, idem. Cada revelação vai para a trilha **pelo rótulo**
  (ex.: "IP 3"), nunca pelo valor.
* **Dado de terceiro**: o que vem da varredura de falhas sem conta (tentativas com o identificador, por outras pessoas).
* **Lista para ofício**: IPs pedidos de uma vez, aprovados em bloco; depois da aprovação, quem pediu gera a tabela do
  ofício (XLSX), e cada IP entregue vai para a trilha.
"""
from __future__ import annotations

import base64
import io
from datetime import datetime, timedelta, timezone

from psycopg.types.json import Jsonb

from . import analise, chaves, gestao
from .acesso import Ator, Negado, funcoes, sem_acesso
from .db import conectar, trilha

SESSAO = timedelta(hours=4)
PRORROGACAO = timedelta(hours=1)
MAX_PRORROGACOES = 2
TETO_DIA = timedelta(hours=8)
COTA_SESSAO = 30
COTA_INVESTIGACAO = 100
CLASSES = ("conta", "ip", "sessao", "evento")
MOTIVOS = {   # ligados às finalidades da base legal (§10.1)
    "identificar_autoria": "Identificar a autoria de acessos",
    "confirmar_titularidade": "Confirmar a titularidade de uma conta",
    "instruir_oficio": "Instruir ofício a provedor",
    "verificar_alteracao": "Verificar alteração ou acesso indevido à conta",
    "outro": "Outro (descrever)",
}
TIPOS_PEDIDO = ("revelacao_cota", "revelacao_terceiro", "revelacao_total", "lista_oficio")


def agora() -> datetime:
    return datetime.now(timezone.utc)


# ------------------------------------------------------------------ sessão
def _inv(cx, ator: Ator, inv_id: int) -> dict:
    from .casos_analise import _inv_investigador
    return _inv_investigador(cx, ator, inv_id)


def _fechar_vencidas(cx, inv_id: int | None = None, sub: str | None = None):
    for s in cx.execute("UPDATE sessao_analise SET encerrada_em=expira_em, encerrada_por='expiracao' WHERE "
                        "encerrada_em IS NULL AND expira_em <= now() AND (%s::int IS NULL OR investigacao_id=%s) AND "
                        "(%s::text IS NULL OR sub=%s) RETURNING id, investigacao_id, sub",
                        (inv_id, inv_id, sub, sub)).fetchall():
        trilha(cx, s["sub"], "sessao_analise_expirada", s["investigacao_id"], sessao=s["id"])


def ativa(cx, inv_id: int, sub: str) -> dict | None:
    _fechar_vencidas(cx, inv_id, sub)
    return cx.execute("SELECT * FROM sessao_analise WHERE investigacao_id=%s AND sub=%s AND encerrada_em IS NULL",
                      (inv_id, sub)).fetchone()


def _usado_hoje(cx, sub: str) -> timedelta:
    ini = agora().replace(hour=0, minute=0, second=0, microsecond=0)
    r = cx.execute("""SELECT coalesce(sum(extract(epoch FROM least(coalesce(encerrada_em, expira_em), expira_em)
                                 - greatest(inicio, %s))), 0) AS s
        FROM sessao_analise WHERE sub=%s AND coalesce(encerrada_em, expira_em) > %s""", (ini, sub, ini)).fetchone()
    return timedelta(seconds=float(r["s"]))


def iniciar(ator: Ator, inv_id: int, motivo_codigo: str, texto: str | None) -> dict:
    from .sigilo import Cofre
    if motivo_codigo not in MOTIVOS:
        raise Negado("motivo", f"Motivo da lista: {', '.join(MOTIVOS)}", 422)
    if motivo_codigo == "outro" and (not texto or len(texto.strip()) < 10):
        raise Negado("motivo", "Descreva o motivo (mínimo de 10 caracteres)", 422)
    ator.exigir_recente()
    with conectar() as cx:
        _inv(cx, ator, inv_id)
        if ativa(cx, inv_id, ator.sub):
            raise Negado("sessao_ativa", "Já há uma sessão de análise ativa nesta investigação", 409)
        resta = TETO_DIA - _usado_hoje(cx, ator.sub)
        if resta < timedelta(minutes=5):
            raise Negado("teto", "Teto diário de 8 h de sessão de análise atingido", 409)
        dur = min(SESSAO, resta)
        with chaves.como_usuario(ator.token), cx.transaction():
            sid = cx.execute("SELECT nextval('sessao_analise_id_seq') AS n").fetchone()["n"]
            cif = Cofre(inv_id, "consulta").cifrar("sessao_analise", "motivo", sid, texto.strip()) if texto else None
            cx.execute("INSERT INTO sessao_analise (id, investigacao_id, sub, motivo_codigo, motivo_cifrado, expira_em) "
                       "VALUES (%s,%s,%s,%s,%s, now() + %s)", (sid, inv_id, ator.sub, motivo_codigo, cif, dur))
            trilha(cx, ator.username, "iniciar_sessao_analise", inv_id, sessao=sid, motivo_codigo=motivo_codigo,
                   motivo=texto.strip() if texto else None, porta=ator.porta)
    return estado(ator, inv_id)


def prorrogar(ator: Ator, inv_id: int) -> dict:
    with conectar() as cx:
        _inv(cx, ator, inv_id)
        s = ativa(cx, inv_id, ator.sub)
        if not s:
            raise Negado("sem_sessao", "Nenhuma sessão de análise ativa", 409)
        if s["prorrogacoes"] >= MAX_PRORROGACOES:
            raise Negado("prorrogacao", "A sessão já foi prorrogada duas vezes", 409)
        resta = TETO_DIA - _usado_hoje(cx, ator.sub) + (s["expira_em"] - agora())
        mais = min(PRORROGACAO, resta - (s["expira_em"] - agora()))
        if mais < timedelta(minutes=1):
            raise Negado("teto", "Teto diário de 8 h de sessão de análise atingido", 409)
        cx.execute("UPDATE sessao_analise SET expira_em=expira_em + %s, prorrogacoes=prorrogacoes+1 WHERE id=%s",
                   (mais, s["id"]))
        trilha(cx, ator.username, "prorrogar_sessao_analise", inv_id, sessao=s["id"], porta=ator.porta)
    return estado(ator, inv_id)


def encerrar(ator: Ator, inv_id: int) -> dict:
    with conectar() as cx:
        _inv(cx, ator, inv_id)
        s = ativa(cx, inv_id, ator.sub)
        if s:
            cx.execute("UPDATE sessao_analise SET encerrada_em=now(), encerrada_por='usuario' WHERE id=%s", (s["id"],))
            trilha(cx, ator.username, "encerrar_sessao_analise", inv_id, sessao=s["id"], porta=ator.porta)
    return estado(ator, inv_id)


def encerrar_do_usuario(sub: str, por: str = "logout"):
    """Logout (inclusive pelo canal de retorno do OIDC): encerra as sessões de análise e as revelações ativas."""
    with conectar() as cx:
        for s in cx.execute("UPDATE sessao_analise SET encerrada_em=now(), encerrada_por=%s WHERE sub=%s AND "
                            "encerrada_em IS NULL RETURNING id, investigacao_id", (por, sub)).fetchall():
            trilha(cx, sub, "encerrar_sessao_analise", s["investigacao_id"], sessao=s["id"], motivo_codigo=por)


# ------------------------------------------------------------------ valores
def _chave(cx, inv_id: int, classe: str, rotulo: str) -> str:
    if classe == "evento":
        try:
            analise.abrir_ref(rotulo)
        except Exception as e:  # noqa: BLE001
            raise Negado("ref", "Referência de evento inválida", 422) from e
        return rotulo
    h = analise._hmac_do_rotulo(cx, inv_id, classe, rotulo)
    if not h:
        raise Negado("rotulo", f"Rótulo '{rotulo}' não existe nesta investigação (os rótulos saem no fechamento)", 404)
    return h


def _rotulo(cx, inv_id: int, classe: str, chave: str) -> str:
    if classe == "evento":
        return "evento"
    return analise.Rotulos(cx, inv_id)(classe, chave) or classe


def terceiro(cx, inv_id: int, classe: str, chave: str) -> bool:
    """Item só visto na varredura de falhas sem conta (tentativas de outras pessoas com o identificador)."""
    if classe == "conta":
        r = cx.execute("SELECT bool_and(via='varredura') AS t FROM conta WHERE investigacao_id=%s AND ps_conta=%s",
                       (inv_id, chave)).fetchone()
        return bool(r and r["t"])
    if classe == "evento":
        inst, realm, eid = analise.abrir_ref(chave)
        r = cx.execute("SELECT c.via FROM evento e JOIN conta c ON c.id=e.conta_id WHERE e.investigacao_id=%s AND "
                       "e.instancia_id=%s AND e.realm=%s AND e.id=%s", (inv_id, inst, realm, eid)).fetchone()
        return bool(r and r["via"] == "varredura")
    col = {"ip": "ps_ip", "sessao": "ps_sessao"}[classe]
    r = cx.execute(f"SELECT bool_and(c.via='varredura') AS t FROM evento e JOIN conta c ON c.id=e.conta_id "
                   f"WHERE e.investigacao_id=%s AND e.{col}=%s", (inv_id, chave)).fetchone()
    return bool(r and r["t"])


def valor(cx, cf, inv_id: int, classe: str, chave: str):
    """O valor real (só em memória, só para a resposta)."""
    from .sigilo import abrir_conta, abrir_evento
    if classe == "conta":
        c = cx.execute("SELECT * FROM conta WHERE investigacao_id=%s AND ps_conta=%s ORDER BY id LIMIT 1",
                       (inv_id, chave)).fetchone()
        c = abrir_conta(cf, c) if c else {}
        return {"username": c.get("username"), "email": c.get("email"), "user_id": c.get("user_id")}
    if classe == "evento":
        inst, realm, eid = analise.abrir_ref(chave)
        r = cx.execute("SELECT * FROM evento WHERE investigacao_id=%s AND instancia_id=%s AND realm=%s AND id=%s",
                       (inv_id, inst, realm, eid)).fetchone()
        return (abrir_evento(cf, r).get("bruto") if r else None)
    col, campo = {"ip": ("ps_ip", "ip"), "sessao": ("ps_sessao", "session_id")}[classe]
    r = cx.execute(f"SELECT * FROM evento WHERE investigacao_id=%s AND {col}=%s AND cifrado IS NOT NULL LIMIT 1",
                   (inv_id, chave)).fetchone()
    return abrir_evento(cf, r).get(campo) if r else None


def _usadas(cx, inv_id: int, sessao_id: int) -> tuple[int, int]:
    """Itens que contam na cota (os liberados por aprovação não contam)."""
    s = cx.execute("SELECT count(*) n FROM revelacao WHERE sessao_id=%s AND pedido_id IS NULL", (sessao_id,)).fetchone()["n"]
    i = cx.execute("SELECT count(DISTINCT (classe, chave)) n FROM revelacao WHERE investigacao_id=%s AND pedido_id IS NULL",
                   (inv_id,)).fetchone()["n"]
    return s, i


def _liberado(cx, s: dict, classe: str, chave: str) -> int | None:
    """Pedido aprovado nesta sessão que cobre o item (acima da cota ou de terceiro)."""
    for p in cx.execute("SELECT id, parametros FROM pedido WHERE investigacao_id=%s AND solicitante_sub=%s AND "
                        "status='aprovado' AND tipo IN ('revelacao_cota','revelacao_terceiro') AND "
                        "(parametros->>'sessao')::bigint = %s", (s["investigacao_id"], s["sub"], s["id"])):
        if any(x["classe"] == classe and x["chave"] == chave for x in p["parametros"].get("itens", [])):
            return p["id"]
    return None


def revelar(ator: Ator, inv_id: int, classe: str, rotulo: str) -> dict:
    from .sigilo import Cofre
    if classe not in CLASSES:
        raise Negado("classe", f"Classe: {', '.join(CLASSES)}", 422)
    with conectar() as cx:
        _inv(cx, ator, inv_id)
        s = ativa(cx, inv_id, ator.sub)
        if not s:
            raise Negado("sem_sessao", "Inicie uma sessão de análise para revelar", 409)
        chave = _chave(cx, inv_id, classe, rotulo)
        rot = rotulo if classe != "evento" else "evento"
        ja = cx.execute("SELECT * FROM revelacao WHERE sessao_id=%s AND classe=%s AND chave=%s",
                        (s["id"], classe, chave)).fetchone()
        if not ja:
            terc = terceiro(cx, inv_id, classe, chave)
            pedido = None if s["total"] and not terc else _liberado(cx, s, classe, chave)
            if pedido is None and not (s["total"] and not terc):
                if terc:
                    raise Negado("terceiro", "Dado de terceiro: a revelação precisa de aprovação", 409)
                us, ui = _usadas(cx, inv_id, s["id"])
                if us >= COTA_SESSAO:
                    raise Negado("cota", f"Você atingiu {COTA_SESSAO} revelações nesta sessão. Para continuar, peça "
                                         "aprovação.", 409)
                if ui >= COTA_INVESTIGACAO:
                    raise Negado("cota", f"A investigação atingiu {COTA_INVESTIGACAO} revelações. Para continuar, peça "
                                         "aprovação.", 409)
            cx.execute("INSERT INTO revelacao (sessao_id, investigacao_id, sub, classe, chave, rotulo, terceiro, "
                       "pedido_id) VALUES (%s,%s,%s,%s,%s,%s,%s,%s) ON CONFLICT DO NOTHING",
                       (s["id"], inv_id, ator.sub, classe, chave, rot, terc, pedido))
            trilha(cx, ator.username, "revelar", inv_id, sessao=s["id"], classe=classe, rotulo=rot,
                   **({"pedido": pedido} if pedido else {}), porta=ator.porta)
        with chaves.como_usuario(ator.token):
            v = valor(cx, Cofre(inv_id, "consulta"), inv_id, classe, chave)
        us, ui = _usadas(cx, inv_id, s["id"])
    return {"classe": classe, "rotulo": rot, "valor": v, "expira_em": s["expira_em"].isoformat(),
            "cota": {"sessao": us, "sessao_limite": COTA_SESSAO, "investigacao": ui,
                     "investigacao_limite": COTA_INVESTIGACAO}}


def estado(ator: Ator, inv_id: int, com_valores: bool = True) -> dict:
    from .sigilo import Cofre
    with conectar() as cx:
        _inv(cx, ator, inv_id)
        s = ativa(cx, inv_id, ator.sub)
        usado = _usado_hoje(cx, ator.sub)
        pedidos = [{"pedido": p["id"], "tipo": p["tipo"], "status": p["status"], "quantidade":
                    len(p["parametros"].get("itens", [])), "criado_em": p["criado_em"].isoformat(),
                    "decidido_em": p["decidido_em"].isoformat() if p["decidido_em"] else None}
                   for p in cx.execute("SELECT * FROM pedido WHERE investigacao_id=%s AND solicitante_sub=%s AND "
                                       "tipo = ANY(%s) ORDER BY id DESC LIMIT 20", (inv_id, ator.sub, list(TIPOS_PEDIDO)))]
        out = {"motivos": MOTIVOS, "sessao": None, "revelados": [], "pedidos": pedidos,
               "teto_dia": {"usado_s": int(usado.total_seconds()), "limite_s": int(TETO_DIA.total_seconds())},
               "cota": {"sessao": 0, "sessao_limite": COTA_SESSAO, "investigacao": _usadas(cx, inv_id, -1)[1],
                        "investigacao_limite": COTA_INVESTIGACAO}}
        if not s:
            return out
        us, ui = _usadas(cx, inv_id, s["id"])
        out["cota"].update(sessao=us, investigacao=ui)
        out["sessao"] = {"id": s["id"], "inicio": s["inicio"].isoformat(), "expira_em": s["expira_em"].isoformat(),
                         "prorrogacoes": s["prorrogacoes"], "pode_prorrogar": s["prorrogacoes"] < MAX_PRORROGACOES,
                         "motivo_codigo": s["motivo_codigo"], "motivo": MOTIVOS[s["motivo_codigo"]],
                         "total": s["total"], "agora": agora().isoformat()}
        revs = cx.execute("SELECT * FROM revelacao WHERE sessao_id=%s ORDER BY id", (s["id"],)).fetchall()
        if revs and com_valores:
            with chaves.como_usuario(ator.token):
                cf = Cofre(inv_id, "consulta")
                out["revelados"] = [{"classe": r["classe"], "rotulo": r["rotulo"], "chave": r["chave"] if r["classe"] ==
                                     "evento" else None, "valor": valor(cx, cf, inv_id, r["classe"], r["chave"]),
                                     "terceiro": r["terceiro"], "quando": r["quando"].isoformat()} for r in revs]
        return out


def mapa_revelado(ator: Ator, inv_id: int) -> dict[tuple[str, str], object]:
    """(classe, rótulo) → valor dos itens revelados na sessão ativa (para a coluna "Valor revelado")."""
    from .sigilo import Cofre
    with conectar() as cx:
        s = ativa(cx, inv_id, ator.sub)
        if not s:
            return {}
        revs = cx.execute("SELECT classe, chave, rotulo FROM revelacao WHERE sessao_id=%s AND classe <> 'evento'",
                          (s["id"],)).fetchall()
        if not revs:
            return {}
        with chaves.como_usuario(ator.token):
            cf = Cofre(inv_id, "consulta")
            return {(r["classe"], r["rotulo"]): valor(cx, cf, inv_id, r["classe"], r["chave"]) for r in revs}


# ------------------------------------------------------------------ pedidos (quatro olhos)
def pedir(ator: Ator, inv_id: int, tipo: str, itens: list[dict], motivo: str, fundamento: str | None = None,
          destinatario: str | None = None) -> dict:
    from .sigilo import Cofre
    if tipo not in TIPOS_PEDIDO:
        raise Negado("tipo", f"Tipo: {', '.join(TIPOS_PEDIDO)}", 422)
    if not motivo or len(motivo.strip()) < 10:
        raise Negado("motivo", "Motivo obrigatório (mínimo de 10 caracteres)", 422)
    if tipo == "lista_oficio" and (not fundamento or len(fundamento.strip()) < 10):
        raise Negado("fundamento", "Informe o fundamento (ordem judicial ou competência legal do requisitante)", 422)
    with conectar() as cx:
        _inv(cx, ator, inv_id)
        s = ativa(cx, inv_id, ator.sub)
        if tipo != "lista_oficio" and not s:
            raise Negado("sem_sessao", "O pedido vale para a sessão de análise ativa: inicie uma", 409)
        if tipo == "lista_oficio":
            itens = [{"classe": "ip", "rotulo": x["rotulo"]} for x in itens]
        if tipo != "revelacao_total" and not itens:
            raise Negado("itens", "Informe os itens", 422)
        res = []
        for x in itens:
            if x.get("classe") not in CLASSES:
                raise Negado("classe", f"Classe: {', '.join(CLASSES)}", 422)
            ch = _chave(cx, inv_id, x["classe"], x["rotulo"])
            res.append({"classe": x["classe"], "chave": ch, "rotulo": x["rotulo"] if x["classe"] != "evento" else "evento",
                        "terceiro": terceiro(cx, inv_id, x["classe"], ch)})
        with chaves.como_usuario(ator.token), cx.transaction():
            cf = Cofre(inv_id, "consulta")
            pid = cx.execute("SELECT nextval('pedido_id_seq') AS n").fetchone()["n"]
            livres = {"motivo": motivo.strip(), "fundamento": (fundamento or "").strip() or None,
                      "destinatario": (destinatario or "").strip() or None}
            par = {"sessao": s["id"] if s else None, "itens": res,
                   "livres": base64.b64encode(cf.cifrar("pedido", "livres", pid, livres)).decode()}
            cx.execute("INSERT INTO pedido (id, investigacao_id, tipo, solicitante_sub, parametros) VALUES "
                       "(%s,%s,%s,%s,%s)", (pid, inv_id, tipo, ator.sub, Jsonb(par)))
            trilha(cx, ator.username, f"pedir_{tipo}", inv_id, pedido=pid, quantidade=len(res), motivo=motivo.strip(),
                   porta=ator.porta)
            aprovs = [u for u in gestao.com_papel(cx, "aprovador", exceto=(ator.sub,))
                      if not funcoes(cx, inv_id, u) & {"investigador", "solicitante"}]
            gestao.notificar(cx, aprovs, "pedido_revelacao", f"Pedido de {NOMES[tipo]} na investigação nº {inv_id}",
                             inv_id)
    return {"pedido": pid, "tipo": tipo, "status": "aguardando", "quantidade": len(res)}


NOMES = {"revelacao_cota": "revelação acima da cota", "revelacao_terceiro": "revelação de dado de terceiro",
         "revelacao_total": "revelação total", "lista_oficio": "lista para ofício"}


def _pedido_para_decidir(cx, ator: Ator, pedido_id: int, lock: bool = False) -> dict:
    p = cx.execute("SELECT * FROM pedido WHERE id=%s AND tipo = ANY(%s)" + (" FOR UPDATE" if lock else ""),
                   (pedido_id, list(TIPOS_PEDIDO))).fetchone()
    if not p:
        raise Negado("inexistente", "Pedido inexistente", 404)
    f = funcoes(cx, p["investigacao_id"], ator.sub)
    if p["solicitante_sub"] == ator.sub or f & {"investigador", "solicitante"}:
        raise Negado("segregacao", "Quatro olhos: quem pediu, investiga ou solicitou não decide a revelação")
    return p


def detalhe_pedido(ator: Ator, pedido_id: int) -> dict:
    """O que o aprovador vê para decidir (§4.4): quantidade e classe, motivo da sessão e do pedido, histórico de
    revelações do investigador na investigação. Nunca os valores."""
    from .sigilo import Cofre
    ator.exigir("aprovador")
    with conectar() as cx:
        p = _pedido_para_decidir(cx, ator, pedido_id)
        inv = p["investigacao_id"]
        with chaves.como_usuario(ator.token):
            cf = Cofre(inv, "decisao")
            livres = cf.decifrar("pedido", "livres", p["id"], base64.b64decode(p["parametros"]["livres"]))
            s = cx.execute("SELECT * FROM sessao_analise WHERE id=%s", (p["parametros"].get("sessao"),)).fetchone() \
                if p["parametros"].get("sessao") else None
            motivo_sessao = None
            if s:
                motivo_sessao = MOTIVOS[s["motivo_codigo"]] + (
                    f": {cf.decifrar('sessao_analise', 'motivo', s['id'], s['motivo_cifrado'])}" if s["motivo_cifrado"] else "")
        hist = cx.execute("""SELECT r.classe, count(*) n, count(*) FILTER (WHERE r.terceiro) terceiros,
              array_agg(DISTINCT sa.motivo_codigo) motivos FROM revelacao r JOIN sessao_analise sa ON sa.id=r.sessao_id
            WHERE r.investigacao_id=%s AND r.sub=%s GROUP BY 1 ORDER BY 1""", (inv, p["solicitante_sub"])).fetchall()
        quem = cx.execute("SELECT username FROM usuario WHERE sub=%s", (p["solicitante_sub"],)).fetchone()
        n_ev = cx.execute("SELECT coalesce(sum(n),0)::int n FROM agregado_hora WHERE investigacao_id=%s", (inv,)).fetchone()["n"]
        por_classe: dict[str, int] = {}
        for x in p["parametros"].get("itens", []):
            por_classe[x["classe"]] = por_classe.get(x["classe"], 0) + 1
        avisos = []
        if p["tipo"] == "lista_oficio":
            comp = cx.execute("""SELECT count(*) n FROM (SELECT a.ps_ip FROM agregado_ip a WHERE a.investigacao_id=%s
                AND a.ps_ip = ANY(%s) GROUP BY 1 HAVING count(DISTINCT nullif(a.ps_conta,'')) > 1) x""",
                              (inv, [x["chave"] for x in p["parametros"]["itens"]])).fetchone()["n"]
            if comp:
                avisos.append(f"{comp} IP(s) usados por mais de uma conta: possível rede compartilhada")
        return {"pedido": p["id"], "tipo": p["tipo"], "nome": NOMES[p["tipo"]], "investigacao": inv,
                "status": p["status"], "criado_em": p["criado_em"].isoformat(), "investigador": quem and quem["username"],
                "quantidade": len(p["parametros"].get("itens", [])), "por_classe": por_classe,
                "terceiros": sum(1 for x in p["parametros"].get("itens", []) if x.get("terceiro")),
                "rotulos": [x["rotulo"] for x in p["parametros"].get("itens", [])][:200],
                "motivo": livres.get("motivo"), "fundamento": livres.get("fundamento"),
                "destinatario": livres.get("destinatario"), "motivo_sessao": motivo_sessao,
                "volume_investigacao": n_ev, "historico": hist, "avisos": avisos}


def decidir(ator: Ator, pedido_id: int, aprovar_: bool, motivo: str) -> dict:
    ator.exigir("aprovador")
    ator.exigir_recente()
    if not motivo or len(motivo.strip()) < 5:
        raise Negado("motivo", "Motivo obrigatório (mínimo de 5 caracteres)", 422)
    with conectar() as cx, cx.transaction():
        p = _pedido_para_decidir(cx, ator, pedido_id, lock=True)
        if p["status"] != "aguardando":
            raise Negado("estado", f"Pedido está '{p['status']}'", 409)
        st = "aprovado" if aprovar_ else "recusado"
        cx.execute("UPDATE pedido SET status=%s, decidido_por=%s, decidido_em=now() WHERE id=%s", (st, ator.sub, pedido_id))
        if aprovar_ and p["tipo"] == "revelacao_total" and p["parametros"].get("sessao"):
            cx.execute("UPDATE sessao_analise SET total=true WHERE id=%s AND encerrada_em IS NULL",
                       (p["parametros"]["sessao"],))
        trilha(cx, ator.username, f"{'aprovar' if aprovar_ else 'recusar'}_{p['tipo']}", p["investigacao_id"],
               pedido=pedido_id, motivo=motivo.strip(), porta=ator.porta)
        gestao.notificar(cx, [p["solicitante_sub"]], "decisao_revelacao",
                         f"Pedido nº {pedido_id} de {NOMES[p['tipo']]} {st}", p["investigacao_id"])
    return {"pedido": pedido_id, "status": st}


# ------------------------------------------------------------------ tabela do ofício
def tabela_oficio(ator: Ator, inv_id: int, pedido_id: int, formato: str = "xlsx") -> tuple[str, bytes]:
    """XLSX ou PDF/A do ofício (lista aprovada em bloco): IP, horários em UTC, quantidade; cada IP entregue vai para a
    trilha."""
    from openpyxl import Workbook
    from openpyxl.styles import Font

    from .sigilo import Cofre, abrir_evento
    with conectar() as cx:
        i = _inv(cx, ator, inv_id)
        p = cx.execute("SELECT * FROM pedido WHERE id=%s AND investigacao_id=%s AND tipo='lista_oficio'",
                       (pedido_id, inv_id)).fetchone()
        if not p or p["solicitante_sub"] != ator.sub:
            raise sem_acesso()
        if p["status"] != "aprovado":
            raise Negado("estado", "A lista ainda não foi aprovada", 409)
        with chaves.como_usuario(ator.token):
            cf = Cofre(inv_id, "consulta")
            livres = cf.decifrar("pedido", "livres", p["id"], base64.b64decode(p["parametros"]["livres"]))
            wb = Workbook()
            ws = wb.active
            ws.title = "Ofício"
            ws.append([f"Investigação nº {inv_id} · lista para ofício nº {pedido_id} · aprovada em "
                       f"{p['decidido_em']:%d/%m/%Y %H:%M} UTC"])
            ws.append([f"Fundamento: {livres.get('fundamento') or '—'}"])
            ws.append([f"Destinatário: {livres.get('destinatario') or '—'}"])
            ws.append([])
            ws.append(["IP", "Horário (UTC)", "Porta", "Provedor (ASN)", "Aplicação", "Realm"])
            for c in ws[5]:
                c.font = Font(bold=True)
            resumo = wb.create_sheet("Resumo por IP")
            resumo.append(["IP", "Quantidade", "Primeiro (UTC)", "Último (UTC)"])
            for x in p["parametros"]["itens"]:
                evs = cx.execute("SELECT * FROM evento WHERE investigacao_id=%s AND ps_ip=%s AND time_ms >= %s AND "
                                 "time_ms < %s AND cifrado IS NOT NULL ORDER BY time_ms", (inv_id, x["chave"],
                                                                                        i["inicio_ms"], i["fim_ms"])).fetchall()
                ip = None
                for r in evs:
                    e = abrir_evento(cf, r)
                    ip = ip or e.get("ip")
                    t = datetime.fromtimestamp(r["time_ms"] / 1000, timezone.utc).replace(tzinfo=None)
                    ws.append([e.get("ip"), t, "não registrada pelo Keycloak", "a identificar", r["client_id"], r["realm"]])
                if evs:
                    resumo.append([ip, len(evs), datetime.fromtimestamp(evs[0]["time_ms"] / 1000, timezone.utc).replace(tzinfo=None),
                                   datetime.fromtimestamp(evs[-1]["time_ms"] / 1000, timezone.utc).replace(tzinfo=None)])
                trilha(cx, ator.username, "revelar_oficio", inv_id, pedido=pedido_id, classe="ip", rotulo=x["rotulo"],
                       porta=ator.porta)
            for w in (ws, resumo):
                for col in w.columns:
                    w.column_dimensions[col[0].column_letter].width = 22
            if formato == "pdf":
                from . import relatorio
                linhas = [[("—" if v is None else v.strftime("%d/%m/%Y %H:%M:%S") if isinstance(v, datetime) else v)
                           for v in row] for row in ws.iter_rows(min_row=6, values_only=True)]
                dados = relatorio.tabela_oficio(inv_id, pedido_id, linhas, ["IP", "Horário (UTC)", "Porta",
                                                                            "Provedor (ASN)", "Aplicação", "Realm"],
                                                {"Aprovada em": f"{p['decidido_em']:%d/%m/%Y %H:%M} UTC",
                                                 "Fundamento": livres.get("fundamento") or "—",
                                                 "Destinatário": livres.get("destinatario") or "—"})
            else:
                b = io.BytesIO()
                wb.save(b)
                dados = b.getvalue()
        trilha(cx, ator.username, "gerar_tabela_oficio", inv_id, pedido=pedido_id, quantidade=len(p["parametros"]["itens"]),
               porta=ator.porta, formato=formato)
    return f"oficio_{inv_id}_{pedido_id}.{'pdf' if formato == 'pdf' else 'xlsx'}", dados

"""Casos de uso da análise (W3): quem pode ver o quê, e o que vai para a trilha.

* Dashboard, Eventos, Contas e Cobertura: só o **investigador designado** (§4.1), a partir do início da coleta; coleta
  lacrada responde 409. No banco, a RLS da migração 0011 repete a regra (papel kc_api).
* Visão agregada: o solicitante dono do pedido (depois da conclusão) e o investigador designado; sem IPs, contas
  nem pseudônimos.
* Detalhe de evento e dados de conta (sessões, alterações) decifram com a DEK (finalidade "consulta", pelo chaveiro
  em nome do usuário no modo vault) e saem pela visão mascarada; o acesso vai para a trilha.
* Incluir/excluir conta: motivo obrigatório, cifrado com a DEK; recálculo dos agregados por job, com aviso na tela.
"""
from __future__ import annotations

from . import analise, chaves
from .acesso import Ator, Negado, funcoes, sem_acesso
from .db import conectar, trilha

ESTADOS = analise.ESTADOS_COM_DADOS


def _inv_investigador(cx, ator: Ator, inv_id: int) -> dict:
    ator.exigir("investigador")
    i = cx.execute("SELECT * FROM investigacao WHERE id=%s", (inv_id,)).fetchone()
    if not i or "investigador" not in funcoes(cx, inv_id, ator.sub):
        raise sem_acesso()
    if i["lacrada"]:
        raise Negado("lacrada", "Coleta lacrada (preservação urgente): os dados só abrem depois da aprovação do "
                                "pedido completo", 409)
    if i["status"] not in ESTADOS:
        raise Negado("sem_dados", "A análise abre quando a coleta começa", 409)
    return i


def _visao(i: dict, cofre):
    from .identificador import mascarar_texto
    from .pseudonimos import Visao, rotulos
    dig = chaves.alvo(i, "consulta")
    with conectar() as cx:
        rot = rotulos(cx, i["id"])
    return Visao(False, lambda s: mascarar_texto(s, i["tipo"], dig), rot, cofre)


def dashboard(ator: Ator, inv_id: int, q: dict) -> dict:
    with conectar() as cx:
        i = _inv_investigador(cx, ator, inv_id)
        return analise.dashboard(cx, i, q)


def _com_revelados(ator: Ator, inv_id: int, linhas: list[dict]):
    """Valor revelado ao lado do pseudônimo (nunca no lugar), só com sessão de análise ativa (§7.5)."""
    from .revelacao import mapa_revelado
    m = mapa_revelado(ator, inv_id)
    if not m:
        return False
    for r in linhas:
        rev = {campo: m[(campo, r.get(campo))] for campo in ("conta", "ip", "sessao") if (campo, r.get(campo)) in m}
        if rev:
            r["revelado"] = rev
    return True


def eventos(ator: Ator, inv_id: int, q: dict) -> dict:
    with conectar() as cx:
        i = _inv_investigador(cx, ator, inv_id)
        p = analise.eventos(cx, i, q)
    p["sessao_ativa"] = _com_revelados(ator, inv_id, p["itens"])
    return p


def evento(ator: Ator, inv_id: int, ref: str) -> dict:
    from .sigilo import Cofre
    with conectar() as cx:
        i = _inv_investigador(cx, ator, inv_id)
        try:
            analise.abrir_ref(ref)
        except Exception as e:  # noqa: BLE001
            raise Negado("ref", "Referência de evento inválida", 422) from e
        with chaves.como_usuario(ator.token):
            cf = Cofre(inv_id, "consulta")
            d = analise.detalhe_evento(cx, i, ref, cf, _visao(i, cf))
        if not d:
            raise Negado("inexistente", "Evento não encontrado nesta investigação", 404)
        trilha(cx, ator.username, "consultar_evento", inv_id, porta=ator.porta)
    _com_revelados(ator, inv_id, [d])
    return d


def contas(ator: Ator, inv_id: int) -> dict:
    from .sigilo import Cofre
    with conectar() as cx:
        i = _inv_investigador(cx, ator, inv_id)
        cs = analise.contas(cx, i)
        _com_revelados(ator, inv_id, cs)
        com_motivo = [c for c in cs if c["decisao"]]
        if com_motivo:
            with chaves.como_usuario(ator.token):
                cf = Cofre(inv_id, "consulta")
                for c in com_motivo:
                    d = c["decisao"]
                    d["motivo"] = cf.decifrar("conta_decisao", "motivo_cifrado", d.pop("_id"), bytes(d.pop("_motivo")))
        return {"contas": cs, "analise": analise.estado(cx, inv_id), "preliminar": i["status"] not in analise.FINAIS}


def decidir_conta(ator: Ator, inv_id: int, conta_id: int, incluir: bool, motivo: str) -> dict:
    from .sigilo import Cofre
    if not motivo or len(motivo.strip()) < 10:
        raise Negado("motivo", "Justificativa obrigatória (mínimo de 10 caracteres)", 422)
    with conectar() as cx:
        i = _inv_investigador(cx, ator, inv_id)
        if i["status"] not in analise.FINAIS:
            raise Negado("estado", "Incluir ou excluir conta só depois da conclusão da coleta", 409)
        c = cx.execute("SELECT id, incluida, via FROM conta WHERE id=%s AND investigacao_id=%s",
                       (conta_id, inv_id)).fetchone()
        if not c:
            raise Negado("inexistente", "Conta não encontrada nesta investigação", 404)
        if c["incluida"] == incluir:
            raise Negado("estado", f"A conta já está {'incluída' if incluir else 'excluída'}", 409)
        with chaves.como_usuario(ator.token):
            cf = Cofre(inv_id, "consulta")
            with cx.transaction():
                did = cx.execute("SELECT nextval('conta_decisao_id_seq') AS n").fetchone()["n"]
                cx.execute("INSERT INTO conta_decisao (id, investigacao_id, conta_id, incluida, motivo_cifrado, por) "
                           "VALUES (%s,%s,%s,%s,%s,%s)", (did, inv_id, conta_id, incluir,
                                                          cf.cifrar("conta_decisao", "motivo_cifrado", did, motivo),
                                                          ator.sub))
                cx.execute("UPDATE conta SET incluida=%s WHERE id=%s", (incluir, conta_id))
                rotulo = analise.Rotulos(cx, inv_id)("conta", cx.execute(
                    "SELECT ps_conta FROM conta WHERE id=%s", (conta_id,)).fetchone()["ps_conta"])
                analise.pedir_recalculo(cx, inv_id, f"{'inclusão' if incluir else 'exclusão'} de {rotulo or 'conta'}")
                trilha(cx, ator.username, "incluir_conta" if incluir else "excluir_conta", inv_id, conta=conta_id,
                       motivo=motivo, porta=ator.porta)
        return {"conta": conta_id, "incluida": incluir, "analise": analise.estado(cx, inv_id)}


def extras_conta(ator: Ator, inv_id: int, conta_id: int) -> dict:
    from .sigilo import Cofre
    with conectar() as cx:
        i = _inv_investigador(cx, ator, inv_id)
        if not cx.execute("SELECT 1 FROM conta WHERE id=%s AND investigacao_id=%s", (conta_id, inv_id)).fetchone():
            raise Negado("inexistente", "Conta não encontrada nesta investigação", 404)
        with chaves.como_usuario(ator.token):
            cf = Cofre(inv_id, "consulta")
            d = analise.extras(cx, i, conta_id, cf, _visao(i, cf))
        trilha(cx, ator.username, "consultar_conta", inv_id, conta=conta_id, porta=ator.porta)
        return d


def cobertura(ator: Ator, inv_id: int) -> dict:
    with conectar() as cx:
        i = _inv_investigador(cx, ator, inv_id)
        return analise.cobertura(cx, i)


def visao_agregada(ator: Ator, inv_id: int) -> dict:
    ator.exigir("solicitante", "investigador")
    with conectar() as cx:
        i = cx.execute("SELECT * FROM investigacao WHERE id=%s", (inv_id,)).fetchone()
        f = funcoes(cx, inv_id, ator.sub) if i else set()
        dono = i and "solicitante" in f and ator.tem("solicitante") and i["solicitante_sub"] == ator.sub
        inv = i and "investigador" in f and ator.tem("investigador")
        if not (dono or inv):
            raise sem_acesso()
        if i["lacrada"]:
            raise Negado("lacrada", "Coleta lacrada (preservação urgente)", 409)
        if i["status"] not in analise.FINAIS and not inv:
            raise Negado("estado", "A visão agregada fica disponível quando a coleta termina", 409)
        return analise.visao_agregada(cx, i)

"""Casos de uso com autorização (W1, PROPOSTA_WEB §4.2 e §8.1): a única porta da API e, por ela, da CLI de produção.

Cada função recebe o `Ator` (usuário autenticado no realm dedicado, com MFA) e confere, no servidor: perfil,
designação na investigação, segregação de funções (solicitante ≠ aprovador ≠ investigador; no pedido externo,
aprovador ≠ investigador), quatro olhos e autenticação recente (step-up) nas ações sensíveis. Tudo vai para a trilha.
"""
from __future__ import annotations

import hashlib
import secrets
from datetime import datetime, timedelta, timezone
from pathlib import Path

from psycopg.types.json import Jsonb

from . import chaves, investigar, servicos, siem
from .acesso import Ator, Negado, conferir_papeis, funcoes
from .db import conectar, trilha

PASTA_PACOTES = Path("saida/pacotes")
VALIDADE_SEM_MASCARA = timedelta(hours=24)
VALIDADE_LINK = timedelta(minutes=10)
FINAIS = ("concluida", "concluida_com_lacunas", "parcial")


def _inv(cx, inv_id: int) -> dict:
    i = cx.execute("SELECT * FROM investigacao WHERE id=%s", (inv_id,)).fetchone()
    if not i:
        raise Negado("inexistente", f"Investigação {inv_id} inexistente", 404)
    return i


def _motivo(m: str | None):
    if not m or len(m.strip()) < 5:
        raise Negado("motivo", "Motivo obrigatório (mínimo de 5 caracteres)", 422)


# ------------------------------------------------------------------ sessão
def registrar_login(ator: Ator) -> dict:
    conferir_papeis(ator.papeis)
    with conectar() as cx:
        cx.execute("INSERT INTO usuario (sub, username, nome, unidade, papeis) VALUES (%s,%s,%s,%s,%s) "
                   "ON CONFLICT (sub) DO UPDATE SET username=EXCLUDED.username, nome=EXCLUDED.nome, "
                   "unidade=EXCLUDED.unidade, papeis=EXCLUDED.papeis, ultimo_login=now()",
                   (ator.sub, ator.username, ator.nome, ator.unidade, sorted(ator.papeis)))
        trilha(cx, ator.sub, "login", None, porta=ator.porta, papeis=sorted(ator.papeis))
    return eu(ator)


def eu(ator: Ator) -> dict:
    return {"sub": ator.sub, "usuario": ator.username, "nome": ator.nome, "unidade": ator.unidade,
            "papeis": sorted(ator.papeis), "porta": ator.porta}


# ------------------------------------------------------------------ pedido
def pedir(ator: Ator, tipo: str, valor: str, de: str, ate: str, justificativa: str, fuso: str = "America/Bahia",
          granularidade: str = "dia", instancias: list[str] | None = None, varredura: bool = False,
          base_dias: int = 0, origem: dict | None = None) -> dict:
    """Solicitante pede; investigador registra pedido externo (ofício), com órgão, documento e fundamento."""
    if origem:
        ator.exigir("investigador", "solicitante")
        faltam = [k for k in ("orgao", "documento", "fundamento") if not (origem.get(k) or "").strip()]
        if faltam:
            raise Negado("origem", f"Pedido externo exige {', '.join(faltam)}", 422)
    else:
        ator.exigir("solicitante")
    _motivo(justificativa)
    with chaves.como_usuario(ator.token):
        inv = investigar.abrir(ator.sub, justificativa, tipo, valor, de, ate, fuso, granularidade, instancias,
                               varredura, base_dias, status="aguardando_aprovacao", solicitante_sub=ator.sub,
                               origem=origem)
    with conectar() as cx:
        cx.execute("INSERT INTO designacao (investigacao_id, funcao, sub, designado_por) VALUES (%s,'solicitante',%s,%s)",
                   (inv, ator.sub, ator.sub))
        cx.execute("INSERT INTO pedido (investigacao_id, tipo, solicitante_sub) VALUES (%s,'investigacao',%s)",
                   (inv, ator.sub))
        trilha(cx, ator.sub, "pedir_investigacao", inv, externo=bool(origem), porta=ator.porta)
    return {"investigacao": inv, "status": "aguardando_aprovacao"}


def _visao(cx, ator: Ator, i: dict) -> dict:
    """O que cada perfil vê do cabeçalho. Auditor interno: só metadados, nunca o identificador mascarado."""
    f = funcoes(cx, i["id"], ator.sub)
    base = {"id": i["id"], "status": i["status"], "criado_em": i["criado_em"].isoformat(),
            "inicio_ms": i["inicio_ms"], "fim_ms": i["fim_ms"], "externo": i["origem_externa"],
            "sigilosa": i["sigilosa"], "minhas_funcoes": sorted(f)}
    if ator.tem("auditor_interno") and not f:
        return {**base, "designados": [dict(r) for r in cx.execute(
            "SELECT funcao, sub FROM designacao WHERE investigacao_id=%s ORDER BY funcao", (i["id"],))]}
    return {**base, "alvo": i["alvo_mascarado"], "tipo": i["tipo"], "fuso": i["fuso"],
            "granularidade": i["granularidade"]}


def _pode_ver(cx, ator: Ator, i: dict) -> bool:
    if funcoes(cx, i["id"], ator.sub):
        return True
    if ator.tem("auditor_interno"):
        return True
    return ator.tem("aprovador") and i["status"] == "aguardando_aprovacao" and i["solicitante_sub"] != ator.sub


def listar(ator: Ator) -> list[dict]:
    ator.exigir("solicitante", "investigador", "aprovador", "auditor_interno")
    with conectar() as cx:
        invs = cx.execute("SELECT * FROM investigacao WHERE status <> 'abrindo' ORDER BY id DESC").fetchall()
        return [_visao(cx, ator, i) for i in invs if _pode_ver(cx, ator, i)]


def ver(ator: Ator, inv_id: int) -> dict:
    ator.exigir("solicitante", "investigador", "aprovador", "auditor_interno")
    with conectar() as cx:
        i = _inv(cx, inv_id)
        if not _pode_ver(cx, ator, i):
            raise Negado("designacao", "Sem designação nesta investigação", 404)
        v = _visao(cx, ator, i)
        v["linha_do_tempo"] = [{"quando": r["quando"].isoformat(), "acao": r["acao"]} for r in cx.execute(
            "SELECT quando, acao FROM trilha_auditoria WHERE cadeia=%s AND acao NOT IN ('entregar_dek','selar_fatia',"
            "'evento_divergente') ORDER BY seq", (inv_id,))]
        decide = ator.tem("aprovador") and i["status"] == "aguardando_aprovacao" and i["solicitante_sub"] != ator.sub
        f = funcoes(cx, inv_id, ator.sub)
    if decide or "solicitante" in f or "investigador" in f:
        # justificativa e origem: decifradas com a DEK, pedida em nome do usuário (no modo vault o chaveiro confere)
        from .sigilo import Cofre, justificativa
        with chaves.como_usuario(ator.token):
            cf = Cofre(inv_id, "decisao" if decide else "consulta")
            v["justificativa"] = justificativa(cf, i)
            if i["origem_cifrada"]:
                v["origem"] = cf.decifrar("investigacao", "origem", inv_id, i["origem_cifrada"])
    return v


def progresso(ator: Ator, inv_id: int) -> dict:
    with conectar() as cx:
        i = _inv(cx, inv_id)
        f = funcoes(cx, inv_id, ator.sub)
        if not (f or ator.tem("auditor_interno")):
            ator.exigir("investigador", "solicitante", "auditor_interno")
            raise Negado("designacao", "Sem designação nesta investigação", 404)
        t = {r["status"]: r["n"] for r in cx.execute(
            "SELECT status, count(*) n FROM tarefa WHERE investigacao_id=%s GROUP BY 1", (inv_id,))}
    return {"id": inv_id, "status": i["status"], "tarefas": t}


# ------------------------------------------------------------------ decisão (aprovador)
def _decidir(ator: Ator, inv_id: int, motivo: str):
    ator.exigir("aprovador")
    ator.exigir_recente()
    _motivo(motivo)
    cx = conectar()
    i = _inv(cx, inv_id)
    if i["solicitante_sub"] == ator.sub:
        cx.close()
        raise Negado("segregacao", "Quem pediu não decide o próprio pedido")
    return cx, i


def aprovar(ator: Ator, inv_id: int, investigador: str, motivo: str, sigilosa: bool = False) -> dict:
    cx, i = _decidir(ator, inv_id, motivo)
    with cx:
        u = cx.execute("SELECT * FROM usuario WHERE sub=%s OR username=%s", (investigador, investigador)).fetchone()
        if not u or "investigador" not in u["papeis"]:
            raise Negado("designacao", "O designado precisa ter o perfil investigador e ter entrado no auditor ao "
                         "menos uma vez", 422)
        if u["sub"] == ator.sub:
            raise Negado("segregacao", "O aprovador não pode ser o investigador da mesma investigação")
        if u["sub"] == i["solicitante_sub"] and not i["origem_externa"]:
            raise Negado("segregacao", "O solicitante não pode ser o investigador (só no pedido externo)")
        with cx.transaction():
            st = cx.execute("SELECT status FROM investigacao WHERE id=%s FOR UPDATE", (inv_id,)).fetchone()["status"]
            if st != "aguardando_aprovacao":
                raise Negado("estado", f"Investigação está '{st}'", 409)
            cx.execute("UPDATE investigacao SET status='aprovada', sigilosa=%s WHERE id=%s", (sigilosa, inv_id))
            for funcao, sub in (("aprovador", ator.sub), ("investigador", u["sub"])):
                cx.execute("INSERT INTO designacao (investigacao_id, funcao, sub, designado_por) VALUES (%s,%s,%s,%s) "
                           "ON CONFLICT DO NOTHING", (inv_id, funcao, sub, ator.sub))
            cx.execute("UPDATE pedido SET status='aprovado', decidido_por=%s, decidido_em=now() WHERE "
                       "investigacao_id=%s AND tipo='investigacao' AND status='aguardando'", (ator.sub, inv_id))
            trilha(cx, ator.sub, "aprovar_investigacao", inv_id, investigador=u["sub"], sigilosa=sigilosa,
                   motivo=motivo, porta=ator.porta)
    return {"investigacao": inv_id, "status": "aprovada", "investigador": u["username"]}


def devolver(ator: Ator, inv_id: int, motivo: str) -> dict:
    return _mudar_pedido(ator, inv_id, motivo, "devolvida", "devolvido", "devolver_investigacao")


def recusar(ator: Ator, inv_id: int, motivo: str) -> dict:
    return _mudar_pedido(ator, inv_id, motivo, "recusada", "recusado", "recusar_investigacao")


def _mudar_pedido(ator, inv_id, motivo, status, st_pedido, acao) -> dict:
    cx, i = _decidir(ator, inv_id, motivo)
    with cx, cx.transaction():
        st = cx.execute("SELECT status FROM investigacao WHERE id=%s FOR UPDATE", (inv_id,)).fetchone()["status"]
        if st != "aguardando_aprovacao":
            raise Negado("estado", f"Investigação está '{st}'", 409)
        cx.execute("UPDATE investigacao SET status=%s WHERE id=%s", (status, inv_id))
        cx.execute("UPDATE pedido SET status=%s, decidido_por=%s, decidido_em=now() WHERE investigacao_id=%s AND "
                   "tipo='investigacao' AND status='aguardando'", (st_pedido, ator.sub, inv_id))
        trilha(cx, ator.sub, acao, inv_id, motivo=motivo, porta=ator.porta)
    return {"investigacao": inv_id, "status": status}


def reenviar(ator: Ator, inv_id: int, motivo: str) -> dict:
    ator.exigir("solicitante", "investigador")
    _motivo(motivo)
    with conectar() as cx, cx.transaction():
        i = _inv(cx, inv_id)
        if i["solicitante_sub"] != ator.sub:
            raise Negado("designacao", "Só quem pediu reenvia", 404)
        if i["status"] != "devolvida":
            raise Negado("estado", f"Investigação está '{i['status']}'", 409)
        cx.execute("UPDATE investigacao SET status='aguardando_aprovacao' WHERE id=%s", (inv_id,))
        cx.execute("INSERT INTO pedido (investigacao_id, tipo, solicitante_sub) VALUES (%s,'investigacao',%s)",
                   (inv_id, ator.sub))
        trilha(cx, ator.sub, "reenviar_investigacao", inv_id, motivo=motivo, porta=ator.porta)
    return {"investigacao": inv_id, "status": "aguardando_aprovacao"}


def aguardando_decisao(ator: Ator) -> list[dict]:
    ator.exigir("aprovador")
    with conectar() as cx:
        return [{"pedido": r["id"], "tipo": r["tipo"], "investigacao": r["investigacao_id"],
                 "criado_em": r["criado_em"].isoformat(), **({"parametros": r["parametros"]} if r["tipo"] != "investigacao"
                                                             else {})}
                for r in cx.execute("SELECT * FROM pedido WHERE status='aguardando' AND solicitante_sub<>%s "
                                    "ORDER BY id", (ator.sub,))
                if not _designado_como(cx, r["investigacao_id"], ator.sub, "investigador")]


def _designado_como(cx, inv_id, sub, funcao) -> bool:
    return funcao in funcoes(cx, inv_id, sub)


# ------------------------------------------------------------------ coleta (investigador designado)
def _investigador(ator: Ator, inv_id: int) -> dict:
    ator.exigir("investigador")
    with conectar() as cx:
        i = _inv(cx, inv_id)
        if "investigador" not in funcoes(cx, inv_id, ator.sub):
            raise Negado("designacao", "Sem designação como investigador nesta investigação", 404)
    return i


def iniciar_coleta(ator: Ator, inv_id: int) -> dict:
    i = _investigador(ator, inv_id)
    if i["status"] != "aprovada":
        raise Negado("estado", f"Investigação está '{i['status']}'", 409)
    with conectar() as cx:
        if cx.execute("UPDATE investigacao SET status='na_fila' WHERE id=%s AND status='aprovada'",
                      (inv_id,)).rowcount != 1:
            raise Negado("estado", "Investigação mudou de estado", 409)
        trilha(cx, ator.sub, "iniciar_coleta_pedida", inv_id, porta=ator.porta)
    servicos.enfileirar(inv_id, ator.sub)
    return {"investigacao": inv_id, "status": "na_fila"}


def pausar(ator: Ator, inv_id: int) -> dict:
    _investigador(ator, inv_id)
    _transicao(lambda: servicos.pausar(inv_id, ator.sub))
    return {"investigacao": inv_id, "status": "pausada"}


def retomar(ator: Ator, inv_id: int) -> dict:
    _investigador(ator, inv_id)
    _transicao(lambda: servicos.retomar(inv_id, ator.sub))
    return {"investigacao": inv_id, "status": "coletando"}


def cancelar(ator: Ator, inv_id: int, motivo: str) -> dict:
    """Investigador designado cancela a coleta; o solicitante cancela o próprio pedido ainda não aprovado."""
    _motivo(motivo)
    with conectar() as cx:
        i = _inv(cx, inv_id)
        f = funcoes(cx, inv_id, ator.sub)
    if "solicitante" in f and i["status"] in ("aguardando_aprovacao", "devolvida"):
        with conectar() as cx, cx.transaction():
            cx.execute("UPDATE investigacao SET status='cancelada' WHERE id=%s", (inv_id,))
            cx.execute("UPDATE pedido SET status='cancelado' WHERE investigacao_id=%s AND status='aguardando'",
                       (inv_id,))
            trilha(cx, ator.sub, "cancelar_pedido", inv_id, motivo=motivo, porta=ator.porta)
        return {"investigacao": inv_id, "status": "cancelada"}
    _investigador(ator, inv_id)
    _transicao(lambda: servicos.cancelar(inv_id, ator.sub, motivo))
    return {"investigacao": inv_id, "status": "cancelada"}


def _transicao(f):
    try:
        f()
    except servicos.TransicaoInvalida as e:
        raise Negado("estado", str(e), 409) from e


# ------------------------------------------------------------------ pacotes
def pedir_pacote(ator: Ator, inv_id: int, sem_mascara: bool = False, destino: str | None = None) -> dict:
    """Mascarado: gerado direto pelo worker de pacotes. Sem máscara: pedido a um aprovador (quatro olhos), com o
    destino formal declarado."""
    i = _investigador(ator, inv_id)
    if i["status"] not in FINAIS:
        raise Negado("estado", f"Investigação está '{i['status']}': pacote só depois da coleta", 409)
    with conectar() as cx:
        if sem_mascara:
            ator.exigir_recente()
            _motivo(destino)
            p = cx.execute("INSERT INTO pedido (investigacao_id, tipo, solicitante_sub, parametros) "
                           "VALUES (%s,'pacote_sem_mascara',%s,%s) RETURNING id",
                           (inv_id, ator.sub, Jsonb({"destino_declarado": True}))).fetchone()["id"]
            trilha(cx, ator.sub, "pedir_pacote_sem_mascara", inv_id, pedido=p, motivo=destino, porta=ator.porta)
            return {"pedido": p, "status": "aguardando"}
        return _gerar(cx, ator.sub, inv_id, False, None)


def _gerar(cx, sub: str, inv_id: int, sem_mascara: bool, pedido_id) -> dict:
    pid = cx.execute("INSERT INTO pacote (investigacao_id, sem_mascara, pedido_por, pedido_id) VALUES (%s,%s,%s,%s) "
                     "RETURNING id", (inv_id, sem_mascara, sub, pedido_id)).fetchone()["id"]
    cx.execute("INSERT INTO job (tipo, investigacao_id, parametros) VALUES ('exportar', %s, %s)",
               (inv_id, Jsonb({"pacote": pid})))
    trilha(cx, sub, "pedir_pacote", inv_id, pacote=pid, sem_mascara=sem_mascara)
    return {"pacote": pid, "status": "gerando"}


def decidir_pacote(ator: Ator, pedido_id: int, aprovar_: bool, motivo: str) -> dict:
    ator.exigir("aprovador")
    ator.exigir_recente()
    _motivo(motivo)
    with conectar() as cx, cx.transaction():
        p = cx.execute("SELECT * FROM pedido WHERE id=%s AND tipo='pacote_sem_mascara' FOR UPDATE",
                       (pedido_id,)).fetchone()
        if not p:
            raise Negado("inexistente", "Pedido inexistente", 404)
        if p["status"] != "aguardando":
            raise Negado("estado", f"Pedido está '{p['status']}'", 409)
        f = funcoes(cx, p["investigacao_id"], ator.sub)
        if p["solicitante_sub"] == ator.sub or "investigador" in f or "solicitante" in f:
            raise Negado("segregacao", "Quatro olhos: quem pediu, investiga ou solicitou não aprova o pacote")
        cx.execute("UPDATE pedido SET status=%s, decidido_por=%s, decidido_em=now() WHERE id=%s",
                   ("aprovado" if aprovar_ else "recusado", ator.sub, pedido_id))
        trilha(cx, ator.sub, "aprovar_pacote_sem_mascara" if aprovar_ else "recusar_pacote_sem_mascara",
               p["investigacao_id"], pedido=pedido_id, motivo=motivo, porta=ator.porta)
        if aprovar_:
            return _gerar(cx, p["solicitante_sub"], p["investigacao_id"], True, pedido_id)
    return {"pedido": pedido_id, "status": "recusado"}


def pacotes(ator: Ator, inv_id: int) -> list[dict]:
    _investigador(ator, inv_id)
    with conectar() as cx:
        return [{"pacote": r["id"], "sem_mascara": r["sem_mascara"], "status": r["status"], "sha256": r["sha256"],
                 "criado_em": r["criado_em"].isoformat(), "expira_em": r["expira_em"] and r["expira_em"].isoformat()}
                for r in cx.execute("SELECT * FROM pacote WHERE investigacao_id=%s ORDER BY id", (inv_id,))]


def link_download(ator: Ator, pacote_id: int) -> dict:
    """Link de uso único, válido por 10 min, amarrado a quem pediu (§6.4)."""
    with conectar() as cx:
        p = cx.execute("SELECT * FROM pacote WHERE id=%s", (pacote_id,)).fetchone()
        if not p:
            raise Negado("inexistente", "Pacote inexistente", 404)
    _investigador(ator, p["investigacao_id"])
    if p["pedido_por"] != ator.sub:
        raise Negado("designacao", "Só quem pediu o pacote baixa", 404)
    if p["sem_mascara"]:
        ator.exigir_recente()
    agora = datetime.now(timezone.utc)
    if p["status"] != "pronto" or (p["expira_em"] and p["expira_em"] < agora):
        raise Negado("estado", f"Pacote {p['status'] if p['status'] != 'pronto' else 'expirado'}", 409)
    tok = secrets.token_urlsafe(32)
    with conectar() as cx:
        cx.execute("INSERT INTO link_download (token_hash, pacote_id, sub, expira_em) VALUES (%s,%s,%s,%s)",
                   (hashlib.sha256(tok.encode()).hexdigest(), pacote_id, ator.sub, agora + VALIDADE_LINK))
    return {"link": f"/api/download/{tok}", "expira_em": (agora + VALIDADE_LINK).isoformat()}


def baixar(ator: Ator, tok: str) -> tuple[str, bytes]:
    h = hashlib.sha256(tok.encode()).hexdigest()
    with conectar() as cx, cx.transaction():
        l = cx.execute("SELECT * FROM link_download WHERE token_hash=%s FOR UPDATE", (h,)).fetchone()
        if not l or l["usado_em"] or l["expira_em"] < datetime.now(timezone.utc) or l["sub"] != ator.sub:
            raise Negado("link", "Link inválido, expirado, já usado ou de outra pessoa", 404)
        p = cx.execute("SELECT * FROM pacote WHERE id=%s", (l["pacote_id"],)).fetchone()
        dados = Path(p["arquivo"]).read_bytes()
        sha = hashlib.sha256(dados).hexdigest()
        cx.execute("UPDATE link_download SET usado_em=now() WHERE token_hash=%s", (h,))
        cx.execute("INSERT INTO download (pacote_id, sub, sha256) VALUES (%s,%s,%s)", (p["id"], ator.sub, sha))
        trilha(cx, ator.sub, "baixar_pacote", p["investigacao_id"], pacote=p["id"], sha256=sha,
               sem_mascara=p["sem_mascara"], porta=ator.porta)
    return Path(p["arquivo"]).name, dados


def gerar_pacote_job(pacote_id: int):
    """Executado pelo worker de pacotes (identidade `pacotes` no chaveiro). Nada solto em disco: só o zip, na área
    do worker; o sem máscara expira em 24 h."""
    from .exportar import exportar
    with conectar() as cx:
        p = cx.execute("SELECT * FROM pacote WHERE id=%s", (pacote_id,)).fetchone()
    try:
        r = exportar(p["investigacao_id"], PASTA_PACOTES / str(pacote_id), p["pedido_por"],
                     sem_mascara=p["sem_mascara"], soltos=False)
        sha = hashlib.sha256(Path(r["pacote"]).read_bytes()).hexdigest()
        with conectar() as cx:
            cx.execute("UPDATE pacote SET status='pronto', arquivo=%s, sha256=%s, pronto_em=now(), expira_em=%s "
                       "WHERE id=%s", (r["pacote"], sha, datetime.now(timezone.utc) + VALIDADE_SEM_MASCARA
                                       if p["sem_mascara"] else None, pacote_id))
    except Exception as e:  # noqa: BLE001
        from .redigir import erro
        with conectar() as cx:
            cx.execute("UPDATE pacote SET status='falhou', erro=%s WHERE id=%s", (erro(f"{type(e).__name__}: {e}"),
                                                                                  pacote_id))
        raise


# ------------------------------------------------------------------ fiscalização (auditor interno)
def trilha_investigacao(ator: Ator, inv_id: int | None = None) -> list[dict]:
    ator.exigir("auditor_interno")
    with conectar() as cx:
        q = "WHERE cadeia=%s" if inv_id is not None else "WHERE cadeia IS NOT NULL"
        rs = cx.execute(f"SELECT cadeia, seq, quando, operador, acao, investigacao_id, detalhe, hash FROM "
                        f"trilha_auditoria {q} ORDER BY cadeia, seq LIMIT 5000",
                        (inv_id,) if inv_id is not None else ()).fetchall()
        trilha(cx, ator.sub, "consultar_trilha", inv_id, porta=ator.porta)
    return [{**r, "quando": r["quando"].isoformat()} for r in rs]


def verificar_cadeia(ator: Ator, inv_id: int | None = None) -> dict:
    ator.exigir("auditor_interno")
    from .db import verificar_cadeia as v
    with conectar() as cx:
        probs = v(cx, inv_id)
    return {"cadeias": len(probs), "integras": sum(1 for p in probs.values() if not p),
            "problemas": {str(k): p[:10] for k, p in probs.items() if p}}


# ------------------------------------------------------------------ administração técnica
def instancias(ator: Ator) -> list[dict]:
    ator.exigir("admin_tecnico")
    with conectar() as cx:
        return [{"nome": r["nome"], "url": r["url"], "versao": r["versao_declarada"], "concorrencia": r["concorrencia"],
                 "req_por_s": r["req_por_s"], "modo": (r["sondas"] or {}).get("modo"),
                 "sondas_em": r["sondas_em"] and r["sondas_em"].isoformat()}
                for r in cx.execute("SELECT * FROM instancia ORDER BY nome")]


def cadastrar_instancia(ator: Ator, nome: str, url: str, client_id: str, segredo: str, realm_auth: str = "master",
                        concorrencia: int = 2, req_por_s: float = 5, versao: str | None = None,
                        realms_esperados: list[str] | None = None, homologacao: str | None = None,
                        sonda: str | None = None) -> dict:
    ator.exigir("admin_tecnico")
    ator.exigir_recente()
    with chaves.como_usuario(ator.token):
        cif = chaves.cifrar_segredo(nome, segredo)
    with conectar() as cx:
        cx.execute("INSERT INTO instancia (nome, url, realm_auth, client_id, segredo_cifrado, concorrencia, req_por_s, "
                   "versao_declarada, realms_esperados, realm_homologacao, usuario_sonda) VALUES "
                   "(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s) ON CONFLICT (nome) DO UPDATE SET url=EXCLUDED.url, "
                   "client_id=EXCLUDED.client_id, segredo_cifrado=EXCLUDED.segredo_cifrado, "
                   "realms_esperados=EXCLUDED.realms_esperados, realm_homologacao=EXCLUDED.realm_homologacao, "
                   "usuario_sonda=EXCLUDED.usuario_sonda",
                   (nome, url, realm_auth, client_id, cif, concorrencia, req_por_s, versao, realms_esperados or [],
                    homologacao, sonda))
        trilha(cx, ator.sub, "cadastrar_instancia", None, instancia=nome, url=url, porta=ator.porta)
    return {"instancia": nome}


def rodar_sondas(ator: Ator, nome: str) -> dict:
    """Teste de conexão, sondas no realm de homologação e descoberta (as requisições ficam registradas, §8.3)."""
    ator.exigir("admin_tecnico")
    from . import sondas
    from .descoberta import descobrir
    from .kc import ClienteKC
    with conectar() as cx:
        inst = cx.execute("SELECT * FROM instancia WHERE nome=%s", (nome,)).fetchone()
    if not inst:
        raise Negado("inexistente", "Instância inexistente", 404)
    with chaves.como_usuario(ator.token):
        cli = ClienteKC(inst, finalidade="sondas")
    try:
        cli.token()
        s = None
        if inst["realm_homologacao"]:
            s = sondas.executar(cli, inst["realm_homologacao"], inst["usuario_sonda"], inst["mapeamento"].get("cpf", "cpf"))
            with conectar() as cx:
                cx.execute("UPDATE instancia SET sondas=%s, sondas_em=now() WHERE id=%s", (Jsonb(s), inst["id"]))
            inst["sondas"] = s
        with conectar() as cx:
            realms = [{"realm": r["realm"], "status": r["status"]} for r in descobrir(cx, inst, cli)]
            trilha(cx, ator.sub, "rodar_sondas", None, instancia=nome, modo=(s or {}).get("modo"))
    finally:
        cli.fechar()
    return {"instancia": nome, "modo": (s or {}).get("modo"), "realms": realms}


def ajustar_orcamento(ator: Ator, nome: str, concorrencia: int, req_por_s: float) -> dict:
    ator.exigir("admin_tecnico")
    ator.exigir_recente()
    if not (1 <= concorrencia <= 8 and 0.5 <= req_por_s <= 20):
        raise Negado("faixa", "Concorrência 1–8 e taxa 0,5–20 req/s", 422)
    with conectar() as cx:
        if cx.execute("UPDATE instancia SET concorrencia=%s, req_por_s=%s WHERE nome=%s",
                      (concorrencia, req_por_s, nome)).rowcount != 1:
            raise Negado("inexistente", "Instância inexistente", 404)
        trilha(cx, ator.sub, "ajustar_orcamento", None, instancia=nome, concorrencia=concorrencia,
               req_por_s=req_por_s)
    return {"instancia": nome, "concorrencia": concorrencia, "req_por_s": req_por_s}


def saude(ator: Ator) -> dict:
    ator.exigir("admin_tecnico")
    with conectar() as cx:
        jobs = {f"{r['tipo']}:{r['status']}": r["n"] for r in cx.execute(
            "SELECT tipo, status, count(*) n FROM job GROUP BY 1,2")}
        tarefas = {r["status"]: r["n"] for r in cx.execute("SELECT status, count(*) n FROM tarefa GROUP BY 1")}
    return {"jobs": jobs, "tarefas": tarefas}


# ------------------------------------------------------------------ gestão de acesso
def usuarios(ator: Ator) -> list[dict]:
    """Para a recertificação: quem tem qual perfil (a concessão é feita no realm dedicado)."""
    ator.exigir("gestor_acesso")
    with conectar() as cx:
        return [{"usuario": r["username"], "unidade": r["unidade"], "papeis": r["papeis"],
                 "ultimo_login": r["ultimo_login"].isoformat()} for r in cx.execute("SELECT * FROM usuario ORDER BY 1")]


def alerta_papel(sub_alvo: str, mudanca: str):
    siem.enviar("mudanca_de_papel", "alerta", ator=sub_alvo, motivo_codigo=mudanca)
    with conectar() as cx:
        trilha(cx, "realm-auditor", "mudanca_de_papel", None, usuario=sub_alvo, mudanca=mudanca)


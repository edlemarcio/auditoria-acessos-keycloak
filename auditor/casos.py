"""Casos de uso com autorização (W1 e W2, PROPOSTA_WEB §4.2 e §8.1; docs/W2_CONTRATO.md): a única porta da API e,
por ela, da CLI de produção.

Cada função recebe o `Ator` (usuário autenticado no realm dedicado, com MFA) e confere, no servidor: perfil,
designação na investigação, segregação de funções (solicitante ≠ aprovador ≠ investigador; no pedido externo,
aprovador ≠ investigador), quatro olhos e autenticação recente (step-up) nas ações sensíveis. Tudo vai para a trilha.
As ações que a tela mostra (`acoes`) saem daqui também: a tela não reimplementa regra.
"""
from __future__ import annotations

import hashlib
import json
import re
import secrets
from datetime import date, datetime, timedelta, timezone
from pathlib import Path

from psycopg.types.json import Jsonb

from . import chaves, cripto, gestao, investigar, servicos
from .acesso import PAPEIS, Ator, Negado, conferir_papeis, funcoes, sem_acesso
from .db import conectar, trilha

PASTA_PACOTES = Path("saida/pacotes")
VALIDADE_SEM_MASCARA = timedelta(hours=24)
VALIDADE_LINK = timedelta(minutes=10)
FINAIS = ("concluida", "concluida_com_lacunas", "parcial")
TIPOS_PEDIDO_INV = ("investigacao", "preservacao_urgente")
DOC_MAX = 10 * 1024 * 1024
DOC_TIPOS = ((b"%PDF-", "application/pdf"), (b"\x89PNG\r\n\x1a\n", "image/png"), (b"\xff\xd8\xff", "image/jpeg"))
POR_PAGINA = 25
ACOES = ("enviar", "editar", "descartar", "aprovar", "devolver", "recusar", "cancelar", "reenviar",
         "autorizar_preservacao", "prorrogar_preservacao", "iniciar", "pausar", "retomar", "gerar_pacote",
         "pedir_sem_mascara", "enviar_documento", "baixar_documento")


def _inv(cx, inv_id: int) -> dict:
    i = cx.execute("SELECT * FROM investigacao WHERE id=%s", (inv_id,)).fetchone()
    if not i or i["status"] in ("abrindo", "descartada"):
        raise sem_acesso()
    return i


def _motivo(m: str | None):
    if not m or len(m.strip()) < 5:
        raise Negado("motivo", "Motivo obrigatório (mínimo de 5 caracteres)", 422)


def _lacrada(i: dict):
    if i.get("lacrada"):
        raise Negado("lacrada", "Coleta lacrada (preservação urgente): os dados só abrem depois da aprovação do "
                                "pedido completo", 409)


def _busca(processo: str | None) -> str | None:
    """HMAC do nº do processo normalizado (só letras e dígitos, minúsculas): a busca não precisa do texto em claro."""
    n = re.sub(r"[^0-9a-z]", "", processo.lower()) if processo else ""
    return chaves.hmac_processo(n) if n else None


def _gravar_extras(cx, inv_id: int, dek: bytes, tipo_processo, processo, contas, preservacao: bool):
    """tipo_processo (metadado), processo (texto livre: cifrado com a DEK, mais o HMAC para a busca) e as contas
    informadas (cifradas com a DEK, usadas no preparo)."""
    cx.execute("UPDATE investigacao SET tipo_processo=%s, processo_cifrado=%s, processo_hmac=%s, contas_cifradas=%s, "
               "preservacao_urgente=%s, atualizado_em=now() WHERE id=%s",
               (tipo_processo, cripto.cifrar_dek(dek, json.dumps(processo, ensure_ascii=False), cripto.aad(
                   inv_id, "investigacao", "processo", inv_id)) if processo else None, _busca(processo),
                cripto.cifrar_dek(dek, json.dumps(contas, ensure_ascii=False), cripto.aad(
                    inv_id, "investigacao", "contas", inv_id)) if contas else None, preservacao, inv_id))


def _abrir_extras(cofre, i: dict) -> dict:
    out = {}
    if i.get("processo_cifrado"):
        out["processo"] = json.loads(cripto.decifrar_dek(cofre.dek, bytes(i["processo_cifrado"]), cripto.aad(
            i["id"], "investigacao", "processo", i["id"])))
    if i.get("contas_cifradas"):
        out["contas_informadas"] = json.loads(cripto.decifrar_dek(cofre.dek, bytes(i["contas_cifradas"]), cripto.aad(
            i["id"], "investigacao", "contas", i["id"])))
    return out


def _contas(contas) -> list[dict] | None:
    if not contas:
        return None
    if len(contas) > 50:
        raise Negado("validacao", "contas_informadas: no máximo 50", 422)
    out = []
    for c in contas:
        c = {k: str((c or {}).get(k) or "").strip() for k in ("instancia", "realm", "username")}
        if not all(c.values()) or any(len(v) > 120 for v in c.values()):
            raise Negado("validacao", "contas_informadas: instancia, realm e username", 422)
        out.append(c)
    return out


def _enfileirar(inv_id: int, sub: str, token):
    """Põe a preparação na fila com as contas informadas no pedido (decifradas com a DEK, recifradas no job)."""
    from .sigilo import Cofre
    contas = None
    with conectar() as cx:
        i = cx.execute("SELECT id, contas_cifradas FROM investigacao WHERE id=%s", (inv_id,)).fetchone()
    if i["contas_cifradas"]:
        with chaves.como_usuario(token):
            contas = [(c["instancia"], c["realm"], "u:" + c["username"])
                      for c in _abrir_extras(Cofre(inv_id, "consulta"), i)["contas_informadas"]]
    servicos.enfileirar(inv_id, sub, contas)


class _Ctx:
    """O que o usuário atual tem em cada investigação, lido uma vez por requisição."""

    def __init__(self, cx, ator: Ator):
        self.cx, self.ator = cx, ator
        self.fs: dict[int, set] = {}
        for r in cx.execute("SELECT investigacao_id, funcao FROM designacao WHERE sub=%s", (ator.sub,)):
            self.fs.setdefault(r["investigacao_id"], set()).add(r["funcao"])
        self.pend = {r["investigacao_id"]: r for r in cx.execute(
            "SELECT * FROM pedido WHERE status='aguardando' AND tipo = ANY(%s)", (list(TIPOS_PEDIDO_INV),))}
        self._c: dict = {}

    def f(self, i) -> set:
        return self.fs.get(i["id"], set())

    def pode_decidir(self, i) -> bool:
        return (self.ator.tem("aprovador") and i["solicitante_sub"] != self.ator.sub and i["id"] in self.pend
                and "investigador" not in self.f(i) and (i["status"] == "aguardando_aprovacao" or i["lacrada"]))

    def dono(self, i) -> bool:
        return i["solicitante_sub"] == self.ator.sub and "solicitante" in self.f(i)

    def pode_ver(self, i) -> bool:
        if i["status"] in ("abrindo", "descartada"):
            return False
        f = self.f(i)
        if i["status"] == "rascunho":
            return "solicitante" in f
        return bool(f) or self.ator.tem("auditor_interno") or self.pode_decidir(i)

    def _q(self, k, sql, args=()):
        if k not in self._c:
            self._c[k] = self.cx.execute(sql, args).fetchall()
        return self._c[k]

    def nome(self, sub) -> str | None:
        if "nomes" not in self._c:
            self._c["nomes"] = {r["sub"]: r["username"] for r in self.cx.execute("SELECT sub, username FROM usuario")}
        return self._c["nomes"].get(sub, sub)

    def investigador(self, inv_id) -> str | None:
        if "invs" not in self._c:
            self._c["invs"] = {r["investigacao_id"]: r["sub"] for r in self.cx.execute(
                "SELECT investigacao_id, sub FROM designacao WHERE funcao='investigador' ORDER BY criado_em")}
        s = self._c["invs"].get(inv_id)
        return self.nome(s) if s else None

    def tem_doc(self, inv_id) -> bool:
        return inv_id in {r["investigacao_id"] for r in self._q("docs", "SELECT investigacao_id FROM documento")}

    def preservacao(self, inv_id) -> dict | None:
        return {r["investigacao_id"]: r for r in self._q("presv", "SELECT * FROM preservacao")}.get(inv_id)

    def progresso(self, inv_id) -> int | None:
        if "prog" not in self._c:
            self._c["prog"] = {r["investigacao_id"]: int(r["feitas"] * 100 / r["n"]) if r["n"] else 0
                               for r in self.cx.execute(
                "SELECT investigacao_id, count(*) n, count(*) FILTER (WHERE status NOT IN ('pendente','executando')) "
                "feitas FROM tarefa GROUP BY 1")}
        return self._c["prog"].get(inv_id)


def acoes(ctx: _Ctx, i: dict) -> list[str]:
    """Ações do §7.2 permitidas ao usuário atual nesta investigação (as mesmas regras das funções abaixo)."""
    a, ator, f, st = [], ctx.ator, ctx.f(i), i["status"]
    dono, inv = ctx.dono(i), "investigador" in f and ator.tem("investigador")
    decide = ctx.pode_decidir(i)
    if st == "rascunho" and dono:
        a += ["enviar", "editar", "descartar"] + (["enviar_documento"] if i["origem_externa"] else [])
    elif st == "devolvida" and dono:
        a += ["editar", "reenviar", "cancelar"] + (["enviar_documento"] if i["origem_externa"] else [])
    elif st == "aguardando_aprovacao" and not i["lacrada"]:
        if dono:
            a.append("cancelar")
        if decide:
            a += ["aprovar", "devolver", "recusar"] + (["autorizar_preservacao"] if i["preservacao_urgente"] else [])
    if i["lacrada"]:
        if decide:
            a += ["aprovar", "recusar"]
        p = ctx.preservacao(i["id"])
        if (ator.coordenador and ator.tem("aprovador") and p and not p["prorrogada_em"] and not p["encerrada_em"]
                and i["solicitante_sub"] != ator.sub and "investigador" not in f):
            a.append("prorrogar_preservacao")
    elif inv:
        a += {"aprovada": ["iniciar"], "na_fila": ["cancelar"], "coletando": ["pausar", "cancelar"],
              "pausada": ["retomar", "cancelar"], "parcial": ["retomar", "cancelar"],
              "concluida": ["gerar_pacote", "pedir_sem_mascara"],
              "concluida_com_lacunas": ["gerar_pacote", "pedir_sem_mascara"]}.get(st, [])
    if ctx.tem_doc(i["id"]) and (decide or inv or "aprovador" in f):
        a.append("baixar_documento")
    return [x for x in ACOES if x in a]


# ------------------------------------------------------------------ sessão
def registrar_login(ator: Ator) -> dict:
    conferir_papeis(ator.papeis)
    with conectar() as cx:
        cx.execute("INSERT INTO usuario (sub, username, nome, unidade, papeis, coordenador) VALUES (%s,%s,%s,%s,%s,%s) "
                   "ON CONFLICT (sub) DO UPDATE SET username=EXCLUDED.username, nome=EXCLUDED.nome, "
                   "unidade=EXCLUDED.unidade, papeis=EXCLUDED.papeis, coordenador=EXCLUDED.coordenador, "
                   "ultimo_login=now()",
                   (ator.sub, ator.username, ator.nome, ator.unidade, sorted(ator.papeis), ator.coordenador))
        trilha(cx, ator.sub, "login", None, porta=ator.porta, papeis=sorted(ator.papeis))
    return eu(ator)


def eu(ator: Ator) -> dict:
    return {"sub": ator.sub, "usuario": ator.username, "nome": ator.nome, "unidade": ator.unidade,
            "papeis": sorted(ator.papeis), "porta": ator.porta, "coordenador": ator.coordenador}


# ------------------------------------------------------------------ início (W2 §1)
ALERTAS = ("instancia_fora", "coleta_falhou", "papel_alterado", "escalonamento", "preservacao_expira")


def inicio(ator: Ator) -> dict:
    ator.exigir_perfil()
    with conectar() as cx:
        ctx = _Ctx(cx, ator)
        out = {"perfil": sorted(ator.papeis), "aguardando_minha_decisao": [], "minhas_por_estado": {}, "alertas": []}
        if ator.tem("aprovador"):
            out["aguardando_minha_decisao"] = aguardando_decisao(ator, cx)
        for i in cx.execute("SELECT * FROM investigacao WHERE id = ANY(%s)", (list(ctx.fs),)):
            if ctx.pode_ver(i):
                st = gestao.status_publico(i)
                out["minhas_por_estado"][st] = out["minhas_por_estado"].get(st, 0) + 1
        out["alertas"] = [{"tipo": r["tipo"], "texto": r["texto"], "investigacao": r["investigacao_id"],
                           "quando": gestao.iso(r["criado_em"])} for r in cx.execute(
            "SELECT * FROM notificacao WHERE sub=%s AND tipo = ANY(%s) AND lida_em IS NULL ORDER BY id DESC LIMIT 20",
            (ator.sub, list(ALERTAS)))]
        if ator.tem("admin_tecnico"):   # instância cuja última requisição (10 min) falhou
            for r in cx.execute("SELECT DISTINCT ON (q.instancia_id) i.nome, q.status, q.inicio FROM requisicao q "
                                "JOIN instancia i ON i.id=q.instancia_id WHERE q.inicio > now() - interval '10 minutes' "
                                "ORDER BY q.instancia_id, q.inicio DESC"):
                if r["status"] is None or r["status"] >= 500:
                    out["alertas"].append({"tipo": "instancia_fora", "texto": f"{r['nome']} não responde",
                                           "investigacao": None, "quando": gestao.iso(r["inicio"])})
        out["nao_lidas"] = cx.execute("SELECT count(*) n FROM notificacao WHERE sub=%s AND lida_em IS NULL",
                                      (ator.sub,)).fetchone()["n"]
    return out


# ------------------------------------------------------------------ pedido, rascunho e envio
def pedir(ator: Ator, tipo: str, valor: str, de: str, ate: str, justificativa: str, fuso: str = "America/Bahia",
          granularidade: str = "dia", instancias: list[str] | None = None, varredura: bool = False,
          base_dias: int = 0, origem: dict | None = None, rascunho: bool = False, preservacao_urgente: bool = False,
          tipo_processo: str | None = None, processo: str | None = None,
          contas_informadas: list[dict] | None = None) -> dict:
    """Solicitante pede; investigador registra pedido externo (ofício), com órgão, documento e fundamento. O pedido
    externo exige o documento de origem antes do envio: nasce como rascunho."""
    _permissao_pedido(ator, origem)
    _motivo(justificativa)
    if origem and not rascunho:
        raise Negado("documento", "Pedido externo exige o documento de origem: grave como rascunho "
                                  "(\"rascunho\": true), anexe o documento e envie", 422)
    processo = _extras(tipo_processo, processo, origem)
    contas = _contas(contas_informadas)
    try:
        with chaves.como_usuario(ator.token):
            inv = investigar.abrir(ator.sub, justificativa, tipo, valor, de, ate, fuso, granularidade, instancias,
                                   varredura, base_dias, status="rascunho" if rascunho else "aguardando_aprovacao",
                                   solicitante_sub=ator.sub, origem=origem)
    except ValueError as e:
        raise Negado("validacao", str(e), 422) from e
    status = "rascunho" if rascunho else "aguardando_aprovacao"
    from .sigilo import Cofre
    with chaves.como_usuario(ator.token):
        dek = Cofre(inv, "consulta").dek
    with conectar() as cx:
        _gravar_extras(cx, inv, dek, tipo_processo, processo, contas, preservacao_urgente)
        cx.execute("INSERT INTO designacao (investigacao_id, funcao, sub, designado_por) VALUES (%s,'solicitante',%s,%s)",
                   (inv, ator.sub, ator.sub))
        if not rascunho:
            _abrir_pedido(cx, inv, ator.sub, preservacao_urgente)
        trilha(cx, ator.sub, "pedir_investigacao", inv, externo=bool(origem), rascunho=rascunho,
               preservacao_urgente=preservacao_urgente, tipo_processo=tipo_processo, porta=ator.porta)
        if not rascunho:
            gestao.avisar_pedido(cx, inv, ator.sub, preservacao_urgente)
    return {"investigacao": inv, "status": status}


def _permissao_pedido(ator: Ator, origem: dict | None):
    if origem:
        ator.exigir("investigador", "solicitante")
        faltam = [k for k in ("orgao", "documento", "fundamento") if not (origem.get(k) or "").strip()]
        if faltam:
            raise Negado("origem", f"Pedido externo exige {', '.join(faltam)}", 422)
    else:
        ator.exigir("solicitante")


def _extras(tipo_processo: str | None, processo: str | None, origem: dict | None) -> str | None:
    processo = processo or (origem or {}).get("processo")
    for nome, v in (("tipo_processo", tipo_processo), ("processo", processo)):
        if v is not None and (len(v) > 80 or not v.strip()):
            raise Negado("validacao", f"{nome}: até 80 caracteres", 422)
    return processo.strip() if processo else None


def _abrir_pedido(cx, inv_id: int, sub: str, preservacao: bool):
    cx.execute("INSERT INTO pedido (investigacao_id, tipo, solicitante_sub) VALUES (%s,%s,%s)",
               (inv_id, "preservacao_urgente" if preservacao else "investigacao", sub))


def _do_dono(cx, ator: Ator, inv_id: int, estados: tuple[str, ...]) -> dict:
    i = _inv(cx, inv_id)
    if i["solicitante_sub"] != ator.sub or "solicitante" not in funcoes(cx, inv_id, ator.sub):
        raise sem_acesso()
    if i["status"] not in estados:
        raise Negado("estado", f"Investigação está '{gestao.status_publico(i)}'", 409)
    return i


def atualizar(ator: Ator, inv_id: int, tipo: str | None, valor: str | None, de: str, ate: str, justificativa: str,
              fuso: str = "America/Bahia", granularidade: str = "dia", instancias: list[str] | None = None,
              varredura: bool = False, base_dias: int = 0, origem: dict | None = None,
              preservacao_urgente: bool = False, tipo_processo: str | None = None,
              processo: str | None = None, contas_informadas: list[dict] | None = None) -> dict:
    """Edita o rascunho (ou o pedido devolvido), só o solicitante. O identificador é opcional: sem ele, fica o atual."""
    from .identificador import mascarar, normalizar
    from .sigilo import Cofre
    _permissao_pedido(ator, origem)
    _motivo(justificativa)
    processo = _extras(tipo_processo, processo, origem)
    contas = _contas(contas_informadas)
    try:
        ini, fim = investigar.periodo(de, ate, fuso)
        dig = normalizar(tipo, valor) if valor else None
    except ValueError as e:
        raise Negado("validacao", str(e), 422) from e
    with conectar() as cx:
        i = _do_dono(cx, ator, inv_id, ("rascunho", "devolvida"))
        if bool(origem) != i["origem_externa"]:
            raise Negado("origem", "Não se muda um pedido entre interno e externo: descarte e abra outro", 422)
        with chaves.como_usuario(ator.token):
            dek = Cofre(inv_id, "consulta").dek
            alvo = {}
            if dig:
                alvo = {"tipo": tipo, "alvo_hmac": chaves.hmac_alvo(tipo, dig),
                        "alvo_mascarado": mascarar(tipo, dig), "alvo_cifrado": chaves.cifrar_alvo(inv_id, dek, dig)}
        sets = {**alvo, "inicio_ms": ini, "fim_ms": fim, "fuso": fuso, "granularidade": granularidade,
                "parametros": Jsonb({"instancias": instancias, "varredura": varredura, "base_dias": base_dias}),
                "justificativa_cifrada": cripto.cifrar_dek(dek, json.dumps(justificativa, ensure_ascii=False),
                                                           cripto.aad(inv_id, "investigacao", "justificativa", inv_id)),
                "origem_cifrada": cripto.cifrar_dek(dek, json.dumps(origem, ensure_ascii=False),
                                                    cripto.aad(inv_id, "investigacao", "origem", inv_id))
                if origem else None}
        with cx.transaction():
            cx.execute("UPDATE investigacao SET " + ", ".join(f"{k}=%s" for k in sets) + ", atualizado_em=now() "
                       "WHERE id=%s", (*sets.values(), inv_id))
            _gravar_extras(cx, inv_id, dek, tipo_processo, processo, contas, preservacao_urgente)
            trilha(cx, ator.sub, "editar_pedido", inv_id, alvo_alterado=bool(dig), justificativa=justificativa,
                   alvo=alvo.get("alvo_mascarado"), porta=ator.porta)
    return {"investigacao": inv_id, "status": gestao.status_publico(i)}


def enviar(ator: Ator, inv_id: int) -> dict:
    ator.exigir("solicitante", "investigador")
    with conectar() as cx, cx.transaction():
        i = _do_dono(cx, ator, inv_id, ("rascunho",))
        if i["origem_externa"] and not cx.execute("SELECT 1 FROM documento WHERE investigacao_id=%s",
                                                  (inv_id,)).fetchone():
            raise Negado("documento", "Pedido externo exige o documento de origem antes do envio", 422)
        if cx.execute("UPDATE investigacao SET status='aguardando_aprovacao', atualizado_em=now() WHERE id=%s AND "
                      "status='rascunho'", (inv_id,)).rowcount != 1:
            raise Negado("estado", "Investigação mudou de estado", 409)
        _abrir_pedido(cx, inv_id, ator.sub, i["preservacao_urgente"])
        trilha(cx, ator.sub, "enviar_rascunho", inv_id, preservacao_urgente=i["preservacao_urgente"], porta=ator.porta)
        gestao.avisar_pedido(cx, inv_id, ator.sub, i["preservacao_urgente"])
    return {"investigacao": inv_id, "status": "aguardando_aprovacao"}


def descartar(ator: Ator, inv_id: int) -> dict:
    """Descarta o rascunho: as DEKs são destruídas (o alvo cifrado fica ilegível) e ele some das listas."""
    ator.exigir("solicitante", "investigador")
    with conectar() as cx, cx.transaction():
        _do_dono(cx, ator, inv_id, ("rascunho",))
        cx.execute("UPDATE investigacao SET status='descartada', atualizado_em=now() WHERE id=%s", (inv_id,))
        cx.execute("UPDATE chave_investigacao SET envelope=''::bytea, destruida_em=now() WHERE investigacao_id=%s",
                   (inv_id,))
        trilha(cx, ator.sub, "descartar_rascunho", inv_id, porta=ator.porta)
    chaves.esquecer(inv_id)
    return {"investigacao": inv_id, "status": "descartada"}


# ------------------------------------------------------------------ documento de origem (W2 §6)
def enviar_documento(ator: Ator, inv_id: int, nome: str, dados: bytes) -> dict:
    from .sigilo import Cofre
    ator.exigir("solicitante", "investigador")
    if len(dados) > DOC_MAX:
        raise Negado("documento", "Documento acima de 10 MB", 413)
    tipo = next((t for m, t in DOC_TIPOS if dados.startswith(m)), None)
    if not tipo:
        raise Negado("documento", "Documento deve ser PDF, PNG ou JPEG", 415)
    nome = (Path(nome or "documento").name or "documento")[:120]
    sha = hashlib.sha256(dados).hexdigest()
    with conectar() as cx:
        _do_dono(cx, ator, inv_id, ("rascunho", "devolvida"))
        with chaves.como_usuario(ator.token):
            cf = Cofre(inv_id, "consulta")
            cif = cf.cifrar_bytes("documento", "cifrado", inv_id, dados)
            meta = cf.cifrar("documento", "meta", inv_id, {"nome": nome, "tipo": tipo})
        with cx.transaction():
            cx.execute("INSERT INTO documento (investigacao_id, cifrado, meta_cifrado, sha256, tamanho, enviado_por) "
                       "VALUES (%s,%s,%s,%s,%s,%s) ON CONFLICT (investigacao_id) DO UPDATE SET cifrado=EXCLUDED.cifrado, "
                       "meta_cifrado=EXCLUDED.meta_cifrado, sha256=EXCLUDED.sha256, tamanho=EXCLUDED.tamanho, "
                       "enviado_por=EXCLUDED.enviado_por, enviado_em=now()",
                       (inv_id, cif, meta, sha, len(dados), ator.sub))
            trilha(cx, ator.sub, "anexar_documento", inv_id, sha256=sha, tamanho=len(dados), tipo=tipo,
                   porta=ator.porta)
    return {"nome": nome, "sha256": sha, "tamanho": len(dados)}


def baixar_documento(ator: Ator, inv_id: int) -> tuple[str, str, bytes]:
    """Aprovador que decide o pedido, aprovador e investigador designados. Nunca o auditor interno."""
    from .sigilo import Cofre
    ator.exigir("aprovador", "investigador")
    with conectar() as cx:
        i = _inv(cx, inv_id)
        ctx = _Ctx(cx, ator)
        f = ctx.f(i)
        decide = ctx.pode_decidir(i)
        if not (decide or ("investigador" in f and ator.tem("investigador")) or "aprovador" in f):
            raise sem_acesso()
        d = cx.execute("SELECT * FROM documento WHERE investigacao_id=%s", (inv_id,)).fetchone()
        if not d:
            raise Negado("inexistente", "Investigação sem documento de origem", 404)
        with chaves.como_usuario(ator.token):
            cf = Cofre(inv_id, "decisao" if decide and not f else "consulta")
            dados = cf.decifrar_bytes("documento", "cifrado", inv_id, d["cifrado"])
            meta = cf.decifrar("documento", "meta", inv_id, d["meta_cifrado"])
        trilha(cx, ator.sub, "baixar_documento", inv_id, sha256=d["sha256"], porta=ator.porta)
    return meta["nome"], meta["tipo"], dados


# ------------------------------------------------------------------ visão, lista e detalhe
def _visao(ctx: _Ctx, i: dict) -> dict:
    """O que cada perfil vê do cabeçalho. Auditor interno sem vínculo: só metadados, nunca o identificador mascarado."""
    f = ctx.f(i)
    st = gestao.status_publico(i)
    base = {"id": i["id"], "status": st, "status_interno": i["status"], "criado_em": gestao.iso(i["criado_em"]),
            "atualizado_em": gestao.iso(i["atualizado_em"]),
            "de": gestao.iso(datetime.fromtimestamp(i["inicio_ms"] / 1000, timezone.utc)),
            "ate": gestao.iso(datetime.fromtimestamp(i["fim_ms"] / 1000, timezone.utc)), "fuso": i["fuso"],
            "inicio_ms": i["inicio_ms"], "fim_ms": i["fim_ms"], "solicitante": ctx.nome(i["solicitante_sub"]),
            "investigador": ctx.investigador(i["id"]), "origem_externa": i["origem_externa"],
            "externo": i["origem_externa"], "sigilosa": i["sigilosa"], "preservacao_urgente": i["preservacao_urgente"],
            "tipo_processo": i["tipo_processo"], "minhas_funcoes": sorted(f), "acoes": acoes(ctx, i)}
    if i["status"] in ("coletando", "pausada", "parcial", "na_fila", "coletada") or i["lacrada"]:
        base["progresso_pct"] = ctx.progresso(i["id"]) or 0
    elif st in ("concluida", "concluida_com_lacunas"):
        base["progresso_pct"] = 100
    if ctx.ator.tem("auditor_interno") and not f:
        return {**base, "designados": [dict(r) for r in ctx.cx.execute(
            "SELECT funcao, sub FROM designacao WHERE investigacao_id=%s ORDER BY funcao", (i["id"],))]}
    v = {**base, "alvo_mascarado": i["alvo_mascarado"], "tipo": i["tipo"], "granularidade": i["granularidade"],
         "processo": None}
    if i.get("processo_cifrado") and (f or ctx.pode_decidir(i)):
        from .sigilo import Cofre
        try:
            with chaves.como_usuario(ctx.ator.token):
                v["processo"] = _abrir_extras(Cofre(i["id"], "consulta" if f else "decisao"),
                                              {**i, "contas_cifradas": None}).get("processo")
        except chaves.Recusado:
            pass
    return v


def listar(ator: Ator, visao: str | None = None, estados: list[str] | None = None, q: str | None = None,
           de: str | None = None, ate: str | None = None, pagina: int = 1, por_pagina: int = POR_PAGINA) -> dict:
    ator.exigir("solicitante", "investigador", "aprovador", "auditor_interno")
    if visao not in (None, "", "minhas", "aguardando", "lacunas", "retencao"):
        raise Negado("validacao", "visao: minhas, aguardando, lacunas ou retencao", 422)
    try:
        d0, d1 = (date.fromisoformat(de) if de else None), (date.fromisoformat(ate) if ate else None)
    except ValueError as e:
        raise Negado("validacao", "de/ate: AAAA-MM-DD", 422) from e
    pagina, por_pagina = max(1, pagina), min(max(1, por_pagina), 100)
    qid = q.strip() if q and q.strip() else None
    qn = _busca(qid) if qid else None
    with conectar() as cx:
        ctx = _Ctx(cx, ator)
        out = []
        for i in cx.execute("SELECT * FROM investigacao WHERE status NOT IN ('abrindo','descartada') ORDER BY id DESC"):
            if not ctx.pode_ver(i):
                continue
            st = gestao.status_publico(i)
            if visao == "minhas" and not ctx.f(i):
                continue
            if visao == "aguardando" and not (ctx.pode_decidir(i) or (ctx.dono(i) and st in (
                    "rascunho", "aguardando_aprovacao", "devolvida"))):
                continue
            if visao == "lacunas" and st != "concluida_com_lacunas":
                continue
            if visao == "retencao" and st != "retencao_legal":
                continue
            if estados and st not in estados:
                continue
            if qn:   # nº da investigação; processo (HMAC) só para quem lê o processo (não o auditor sem vínculo)
                por_processo = i["processo_hmac"] and i["processo_hmac"] == qn and (ctx.f(i) or ctx.pode_decidir(i))
                if not (qid == str(i["id"]) or por_processo):
                    continue
            c = i["criado_em"].astimezone(timezone.utc).date()
            if (d0 and c < d0) or (d1 and c > d1):
                continue
            out.append(i)
        pag = out[(pagina - 1) * por_pagina: pagina * por_pagina]
        return {"itens": [_visao(ctx, i) for i in pag], "total": len(out), "pagina": pagina, "por_pagina": por_pagina}


def ver(ator: Ator, inv_id: int) -> dict:
    from .sigilo import Cofre, justificativa
    ator.exigir("solicitante", "investigador", "aprovador", "auditor_interno")
    with conectar() as cx:
        i = _inv(cx, inv_id)
        ctx = _Ctx(cx, ator)
        if not ctx.pode_ver(i):
            raise sem_acesso()
        v = _visao(ctx, i)
        decide, f = ctx.pode_decidir(i), ctx.f(i)
        cofre = None
        if decide or f & {"solicitante", "investigador", "aprovador"}:
            # justificativa e origem: decifradas com a DEK, pedida em nome do usuário (no modo vault o chaveiro confere)
            try:
                with chaves.como_usuario(ator.token):
                    cofre = Cofre(inv_id, "decisao" if decide and not f else "consulta")
                    v["justificativa"] = justificativa(cofre, i)
                    if i["origem_cifrada"]:
                        v["origem"] = cofre.decifrar("investigacao", "origem", inv_id, i["origem_cifrada"])
                    x = _abrir_extras(cofre, i)   # as contas informadas não voltam (username é dado pessoal)
                    v["processo"] = x.get("processo")
                    v["contas_informadas"] = len(x.get("contas_informadas") or [])
            except chaves.Recusado:
                cofre = None   # DEK destruída (preservação recusada ou expirada): só metadados
        v["linha_do_tempo"] = gestao.linha_do_tempo(cx, i, cofre)
        nomes = (i["parametros"] or {}).get("instancias")
        v.update({"instancias": nomes, "varredura": bool((i["parametros"] or {}).get("varredura")),
                  "base_dias": (i["parametros"] or {}).get("base_dias") or 0})
        v["expiracao"] = gestao.expiracao(cx, i["inicio_ms"], nomes)
        n = cx.execute("SELECT count(*) n FROM tarefa WHERE investigacao_id=%s", (inv_id,)).fetchone()["n"]
        est = gestao.estimar(cx, i["inicio_ms"], i["fim_ms"], nomes, (i["parametros"] or {}).get("varredura", False),
                             (i["parametros"] or {}).get("base_dias") or 0)
        if n:
            est = {"tarefas": n, "segundos": est["segundos"] * n // max(est["tarefas"], 1)}
        v["estimativa"] = est
        d = cx.execute("SELECT * FROM documento WHERE investigacao_id=%s", (inv_id,)).fetchone()
        v["documento"] = None
        if d:
            nome = None
            if cofre is not None and "auditor_interno" not in ator.papeis:
                nome = cofre.decifrar("documento", "meta", inv_id, d["meta_cifrado"])["nome"]
            v["documento"] = {"nome": nome, "sha256": d["sha256"], "tamanho": d["tamanho"]}
        from . import analise
        dados = (ator.tem("investigador") and "investigador" in f and i["status"] in analise.ESTADOS_COM_DADOS
                 and not i["lacrada"])
        v["analise"] = {"dados": dados, "agregada": dados or (
            ator.tem("solicitante") and "solicitante" in f and i["status"] in analise.FINAIS and not i["lacrada"])}
        p = ctx.preservacao(inv_id)
        v["preservacao"] = {"autorizada_em": gestao.iso(p["autorizada_em"]), "escalona_em": gestao.iso(p["escalona_em"]),
                            "destroi_em": gestao.iso(p["destroi_em"]), "prorrogada": bool(p["prorrogada_em"]),
                            "encerrada_em": gestao.iso(p["encerrada_em"]), "desfecho": p["desfecho"]} if p else None
    return v


def progresso(ator: Ator, inv_id: int) -> dict:
    with conectar() as cx:
        i = _inv(cx, inv_id)
        f = funcoes(cx, inv_id, ator.sub)
        if not (f or ator.tem("auditor_interno")):
            ator.exigir("investigador", "solicitante", "auditor_interno")
            raise sem_acesso()
        t = {r["status"]: r["n"] for r in cx.execute(
            "SELECT status, count(*) n FROM tarefa WHERE investigacao_id=%s GROUP BY 1", (inv_id,))}
    return {"id": inv_id, "status": i["status"], "tarefas": t}


def acompanhamento(ator: Ator, inv_id: int) -> dict:
    """Acompanhamento ao vivo (§8.8): quem tem vínculo com a investigação. Sem dado pessoal."""
    abrir_acompanhamento(ator, inv_id)
    with conectar() as cx:
        return gestao.acompanhamento(cx, inv_id)


def abrir_acompanhamento(ator: Ator, inv_id: int):
    """Checagem de designação ao abrir o stream (e o JSON)."""
    ator.exigir("solicitante", "investigador", "aprovador")
    with conectar() as cx:
        i = _inv(cx, inv_id)
        if i["status"] == "rascunho" or not funcoes(cx, inv_id, ator.sub):
            raise sem_acesso()


def estimar(ator: Ator, de: str, ate: str, fuso: str = "America/Bahia", instancias: list[str] | None = None,
            varredura: bool = False, base_dias: int = 0) -> dict:
    """Assistente (passos 2 e 5): não grava nada e não vai para a trilha."""
    ator.exigir("solicitante", "investigador", "aprovador")
    try:
        ini, fim = investigar.periodo(de, ate, fuso)
    except ValueError as e:
        raise Negado("validacao", str(e), 422) from e
    with conectar() as cx:
        e = gestao.estimar(cx, ini, fim, instancias, varredura, base_dias)
        exp = gestao.expiracao(cx, ini - (base_dias or 0) * gestao.DIA_MS, instancias)
    return {**e, "expiracao": exp, "preservacao_recomendada": any(x["expira_antes_da_aprovacao"] for x in exp)}


# ------------------------------------------------------------------ decisão (aprovador)
def _decidir(ator: Ator, inv_id: int, motivo: str):
    ator.exigir("aprovador")
    ator.exigir_recente()
    _motivo(motivo)
    cx = conectar()
    try:
        i = _inv(cx, inv_id)
        if i["solicitante_sub"] == ator.sub:
            raise Negado("segregacao", "Quem pediu não decide o próprio pedido")
        if "investigador" in funcoes(cx, inv_id, ator.sub):
            raise Negado("segregacao", "O investigador designado não decide o pedido")
    except Negado:
        cx.close()
        raise
    return cx, i


def _investigador_valido(cx, ator: Ator, i: dict, investigador: str) -> dict:
    u = cx.execute("SELECT * FROM usuario WHERE sub=%s OR username=%s", (investigador, investigador)).fetchone()
    if not u or "investigador" not in u["papeis"]:
        raise Negado("designacao", "O designado precisa ter o perfil investigador e ter entrado no auditor ao "
                     "menos uma vez", 422)
    if u["sub"] == ator.sub:
        raise Negado("segregacao", "O aprovador não pode ser o investigador da mesma investigação")
    if u["sub"] == i["solicitante_sub"] and not i["origem_externa"]:
        raise Negado("segregacao", "O solicitante não pode ser o investigador (só no pedido externo)")
    return u


def aprovar(ator: Ator, inv_id: int, investigador: str, motivo: str, sigilosa: bool = False) -> dict:
    """Aprova o pedido (também o pedido completo de uma coleta lacrada, que então se abre)."""
    cx, i = _decidir(ator, inv_id, motivo)
    with cx:
        u = _investigador_valido(cx, ator, i, investigador)
        with cx.transaction():
            r = cx.execute("SELECT status, lacrada FROM investigacao WHERE id=%s FOR UPDATE", (inv_id,)).fetchone()
            lacrada = r["lacrada"]
            if not lacrada and r["status"] != "aguardando_aprovacao":
                raise Negado("estado", f"Investigação está '{gestao.status_publico({**i, **r})}'", 409)
            if lacrada:
                cx.execute("DELETE FROM designacao WHERE investigacao_id=%s AND funcao='investigador' AND sub<>%s",
                           (inv_id, u["sub"]))
                cx.execute("UPDATE investigacao SET lacrada=false, sigilosa=%s, atualizado_em=now() WHERE id=%s",
                           (sigilosa, inv_id))
                cx.execute("UPDATE preservacao SET encerrada_em=now(), desfecho='aprovada' WHERE investigacao_id=%s "
                           "AND encerrada_em IS NULL", (inv_id,))
            else:
                cx.execute("UPDATE investigacao SET status='aprovada', sigilosa=%s, atualizado_em=now() WHERE id=%s",
                           (sigilosa, inv_id))
            for funcao, sub in (("aprovador", ator.sub), ("investigador", u["sub"])):
                cx.execute("INSERT INTO designacao (investigacao_id, funcao, sub, designado_por) VALUES (%s,%s,%s,%s) "
                           "ON CONFLICT DO NOTHING", (inv_id, funcao, sub, ator.sub))
            cx.execute("UPDATE pedido SET status='aprovado', decidido_por=%s, decidido_em=now() WHERE "
                       "investigacao_id=%s AND tipo = ANY(%s) AND status='aguardando'",
                       (ator.sub, inv_id, list(TIPOS_PEDIDO_INV)))
            trilha(cx, ator.sub, "aprovar_investigacao", inv_id, investigador=u["sub"], sigilosa=sigilosa,
                   lacrada=lacrada, motivo=motivo, porta=ator.porta)
            gestao.notificar(cx, [i["solicitante_sub"]], "pedido_aprovado", f"Pedido nº {inv_id} aprovado", inv_id)
            gestao.notificar(cx, [u["sub"]], "designacao", f"Você foi designado investigador na investigação nº "
                             f"{inv_id}" + (" (coleta lacrada liberada)" if lacrada else ""), inv_id)
        st = cx.execute("SELECT * FROM investigacao WHERE id=%s", (inv_id,)).fetchone()
    return {"investigacao": inv_id, "status": gestao.status_publico(st), "investigador": u["username"]}


def devolver(ator: Ator, inv_id: int, motivo: str) -> dict:
    return _mudar_pedido(ator, inv_id, motivo, "devolvida", "devolvido", "devolver_investigacao")


def recusar(ator: Ator, inv_id: int, motivo: str) -> dict:
    return _mudar_pedido(ator, inv_id, motivo, "recusada", "recusado", "recusar_investigacao")


def _mudar_pedido(ator, inv_id, motivo, status, st_pedido, acao) -> dict:
    cx, i = _decidir(ator, inv_id, motivo)
    with cx:
        with cx.transaction():
            r = cx.execute("SELECT status, lacrada FROM investigacao WHERE id=%s FOR UPDATE", (inv_id,)).fetchone()
            if r["lacrada"]:
                if status != "recusada":
                    raise Negado("estado", "Coleta lacrada: só cabe aprovar o pedido completo ou recusar", 409)
                trilha(cx, ator.sub, acao, inv_id, lacrada=True, motivo=motivo, porta=ator.porta)
                gestao.destruir_dek(cx, inv_id, ator.sub, "recusa_do_pedido_de_preservacao", motivo)
            else:
                if r["status"] != "aguardando_aprovacao":
                    raise Negado("estado", f"Investigação está '{gestao.status_publico({**i, **r})}'", 409)
                cx.execute("UPDATE investigacao SET status=%s, atualizado_em=now() WHERE id=%s", (status, inv_id))
                cx.execute("UPDATE pedido SET status=%s, decidido_por=%s, decidido_em=now() WHERE investigacao_id=%s "
                           "AND tipo = ANY(%s) AND status='aguardando'",
                           (st_pedido, ator.sub, inv_id, list(TIPOS_PEDIDO_INV)))
                trilha(cx, ator.sub, acao, inv_id, motivo=motivo, porta=ator.porta)
            gestao.notificar(cx, [i["solicitante_sub"]], f"pedido_{st_pedido}",
                             f"Pedido nº {inv_id} {'devolvido para correção' if status == 'devolvida' else 'recusado'}",
                             inv_id)
    return {"investigacao": inv_id, "status": status}


def reenviar(ator: Ator, inv_id: int, motivo: str) -> dict:
    ator.exigir("solicitante", "investigador")
    _motivo(motivo)
    with conectar() as cx, cx.transaction():
        i = _inv(cx, inv_id)
        if i["solicitante_sub"] != ator.sub:
            raise sem_acesso()
        if i["status"] != "devolvida":
            raise Negado("estado", f"Investigação está '{gestao.status_publico(i)}'", 409)
        cx.execute("UPDATE investigacao SET status='aguardando_aprovacao', atualizado_em=now() WHERE id=%s", (inv_id,))
        _abrir_pedido(cx, inv_id, ator.sub, i["preservacao_urgente"])
        trilha(cx, ator.sub, "reenviar_investigacao", inv_id, motivo=motivo, porta=ator.porta)
        gestao.avisar_pedido(cx, inv_id, ator.sub, i["preservacao_urgente"])
    return {"investigacao": inv_id, "status": "aguardando_aprovacao"}


def aguardando_decisao(ator: Ator, cx=None) -> list[dict]:
    ator.exigir("aprovador")
    if cx is None:
        with conectar() as cx_:
            return aguardando_decisao(ator, cx_)
    presv = {r["investigacao_id"]: r for r in cx.execute("SELECT * FROM preservacao WHERE encerrada_em IS NULL")}
    out = []
    for r in cx.execute("SELECT * FROM pedido WHERE status='aguardando' AND solicitante_sub<>%s ORDER BY id",
                        (ator.sub,)):
        if _designado_como(cx, r["investigacao_id"], ator.sub, "investigador"):
            continue
        p = presv.get(r["investigacao_id"])
        prazo = p["destroi_em"] if p else gestao.somar_dias_uteis(r["criado_em"], gestao.PEDIDO_PARADO_DU)
        critico = None
        if r["tipo"] in TIPOS_PEDIDO_INV and not p:   # eventos do período que somem antes da decisão
            i = cx.execute("SELECT inicio_ms, parametros FROM investigacao WHERE id=%s",
                           (r["investigacao_id"],)).fetchone()
            exp = [x for x in gestao.expiracao(cx, i["inicio_ms"], (i["parametros"] or {}).get("instancias"))
                   if x["expira_antes_da_aprovacao"]]
            critico = min(exp, key=lambda x: x["eventos_desde"]) if exp else None
        out.append({"pedido": r["id"], "tipo": r["tipo"], "investigacao": r["investigacao_id"],
                    "risco_expiracao": critico is not None, "realm_critico": critico,
                    "desde": gestao.iso(r["criado_em"]), "criado_em": gestao.iso(r["criado_em"]),
                    "prazo": gestao.iso(prazo), "escalonado": bool(r["escalonamento"] or (p and p["escalonada_em"])),
                    "lacrada": bool(p), **({"parametros": r["parametros"]} if r["tipo"] == "pacote_sem_mascara"
                                           else {}),
                    **({"quantidade": len(r["parametros"].get("itens", []))} if r["tipo"] in (
                        "revelacao_cota", "revelacao_terceiro", "revelacao_total", "lista_oficio") else {})})
    return out


def investigadores_elegiveis(ator: Ator, inv_id: int) -> list[dict]:
    """Só para o aprovador que decide: quem pode ser designado sem ferir a segregação (o próprio aprovador nunca; o
    solicitante só no pedido externo, §4.2). Precisa ter entrado no auditor ao menos uma vez."""
    ator.exigir("aprovador")
    with conectar() as cx:
        i = _inv(cx, inv_id)
        ctx = _Ctx(cx, ator)
        if not ctx.pode_decidir(i):
            raise sem_acesso()
        return [{"username": r["username"], "nome": r["nome"], "unidade": r["unidade"]} for r in cx.execute(
            "SELECT * FROM usuario WHERE 'investigador' = ANY(papeis) ORDER BY username")
            if r["sub"] != ator.sub and (r["sub"] != i["solicitante_sub"] or i["origem_externa"])
            and not ({"gestor_acesso", "admin_tecnico"} & set(r["papeis"]))]


def instancias_disponiveis(ator: Ator) -> list[dict]:
    """Para o assistente: só nome e realms pesquisáveis (sem URL, segredo nem orçamento)."""
    ator.exigir("solicitante", "investigador", "aprovador")
    with conectar() as cx:
        realms: dict[str, list] = {r["nome"]: [] for r in cx.execute("SELECT nome FROM instancia ORDER BY nome")}
        for s in cx.execute("SELECT DISTINCT ON (s.instancia_id, s.realm) s.realm, s.visivel, s.status, i.nome FROM "
                            "realm_snapshot s JOIN instancia i ON i.id=s.instancia_id ORDER BY s.instancia_id, s.realm, "
                            "s.lido_em DESC"):
            if s["visivel"] and s["status"] not in ("sem_permissao", "esperado_invisivel"):
                realms[s["nome"]].append(s["realm"])
    return [{"nome": k, "realms": v} for k, v in realms.items()]


def _designado_como(cx, inv_id, sub, funcao) -> bool:
    return funcao in funcoes(cx, inv_id, sub)


# ------------------------------------------------------------------ preservação urgente (W2 §7, PROPOSTA §4.4)
def autorizar_preservacao(ator: Ator, inv_id: int, investigador: str, motivo: str) -> dict:
    """Aprovador autoriza só a coleta lacrada: coleta e cifra, mas nenhuma rota de dados abre até a aprovação do
    pedido completo. Prazos em dias úteis: escalona em 3, destrói a DEK em 5 sem decisão."""
    cx, i = _decidir(ator, inv_id, motivo)
    with cx:
        if not i["preservacao_urgente"]:
            raise Negado("estado", "O pedido não pediu preservação urgente", 409)
        u = _investigador_valido(cx, ator, i, investigador)
        agora = gestao.agora_utc()
        esc, dest = gestao.somar_dias_uteis(agora, gestao.ESCALONA_DU), gestao.somar_dias_uteis(agora, gestao.DESTROI_DU)
        with cx.transaction():
            r = cx.execute("SELECT status, lacrada FROM investigacao WHERE id=%s FOR UPDATE", (inv_id,)).fetchone()
            if r["status"] != "aguardando_aprovacao" or r["lacrada"]:
                raise Negado("estado", f"Investigação está '{gestao.status_publico({**i, **r})}'", 409)
            cx.execute("UPDATE investigacao SET status='na_fila', lacrada=true, atualizado_em=now() WHERE id=%s",
                       (inv_id,))
            for funcao, sub in (("aprovador", ator.sub), ("investigador", u["sub"])):
                cx.execute("INSERT INTO designacao (investigacao_id, funcao, sub, designado_por) VALUES (%s,%s,%s,%s) "
                           "ON CONFLICT DO NOTHING", (inv_id, funcao, sub, ator.sub))
            cx.execute("INSERT INTO preservacao (investigacao_id, autorizada_por, autorizada_em, escalona_em, destroi_em) "
                       "VALUES (%s,%s,%s,%s,%s)", (inv_id, ator.sub, agora, esc, dest))
            trilha(cx, ator.sub, "autorizar_preservacao", inv_id, investigador=u["sub"], escalona_em=gestao.iso(esc),
                   destroi_em=gestao.iso(dest), motivo=motivo, porta=ator.porta)
            gestao.notificar(cx, [i["solicitante_sub"], u["sub"]], "preservacao_autorizada",
                             f"Coleta lacrada autorizada na investigação nº {inv_id}: os dados abrem só com a "
                             f"aprovação do pedido completo", inv_id)
    _enfileirar(inv_id, ator.sub, ator.token)
    return {"investigacao": inv_id, "status": "preservacao_urgente", "escalona_em": gestao.iso(esc),
            "destroi_em": gestao.iso(dest)}


def prorrogar_preservacao(ator: Ator, inv_id: int, motivo: str) -> dict:
    """Coordenação, uma vez, +10 dias úteis, com motivo."""
    ator.exigir("aprovador")
    if not ator.coordenador:
        raise Negado("perfil", "Só a coordenação (atributo coordenador no realm) prorroga a preservação")
    ator.exigir_recente()
    _motivo(motivo)
    with conectar() as cx, cx.transaction():
        i = _inv(cx, inv_id)
        if i["solicitante_sub"] == ator.sub or "investigador" in funcoes(cx, inv_id, ator.sub):
            raise Negado("segregacao", "Quem pediu ou investiga não prorroga a preservação")
        p = cx.execute("SELECT * FROM preservacao WHERE investigacao_id=%s FOR UPDATE", (inv_id,)).fetchone()
        if not p or p["encerrada_em"] or not i["lacrada"]:
            raise Negado("estado", "Não há preservação urgente em andamento", 409)
        if p["prorrogada_em"]:
            raise Negado("estado", "A preservação já foi prorrogada uma vez", 409)
        novo = gestao.somar_dias_uteis(p["destroi_em"], gestao.PRORROGA_DU)
        cx.execute("UPDATE preservacao SET destroi_em=%s, prorrogada_por=%s, prorrogada_em=now() WHERE investigacao_id=%s",
                   (novo, ator.sub, inv_id))
        trilha(cx, ator.sub, "prorrogar_preservacao", inv_id, destroi_em=gestao.iso(novo), motivo=motivo,
               porta=ator.porta)
        gestao.notificar(cx, gestao.designados(cx, inv_id, "solicitante", "investigador", "aprovador"),
                         "preservacao_expira", f"Preservação da investigação nº {inv_id} prorrogada até "
                         f"{novo:%d/%m/%Y}", inv_id)
    return {"investigacao": inv_id, "destroi_em": gestao.iso(novo), "prorrogada": True}


# ------------------------------------------------------------------ coleta (investigador designado)
def _investigador(ator: Ator, inv_id: int) -> dict:
    ator.exigir("investigador")
    with conectar() as cx:
        i = _inv(cx, inv_id)
        if "investigador" not in funcoes(cx, inv_id, ator.sub):
            raise sem_acesso()
    return i


def iniciar_coleta(ator: Ator, inv_id: int) -> dict:
    i = _investigador(ator, inv_id)
    _lacrada(i)
    if i["status"] != "aprovada":
        raise Negado("estado", f"Investigação está '{gestao.status_publico(i)}'", 409)
    with conectar() as cx:
        if cx.execute("UPDATE investigacao SET status='na_fila', atualizado_em=now() WHERE id=%s AND status='aprovada'",
                      (inv_id,)).rowcount != 1:
            raise Negado("estado", "Investigação mudou de estado", 409)
        trilha(cx, ator.sub, "iniciar_coleta_pedida", inv_id, porta=ator.porta)
    _enfileirar(inv_id, ator.sub, ator.token)
    return {"investigacao": inv_id, "status": "preparando"}


def pausar(ator: Ator, inv_id: int) -> dict:
    _lacrada(_investigador(ator, inv_id))
    _transicao(lambda: servicos.pausar(inv_id, ator.sub))
    return {"investigacao": inv_id, "status": "pausada"}


def retomar(ator: Ator, inv_id: int) -> dict:
    _lacrada(_investigador(ator, inv_id))
    _transicao(lambda: servicos.retomar(inv_id, ator.sub))
    return {"investigacao": inv_id, "status": "coletando"}


def cancelar(ator: Ator, inv_id: int, motivo: str) -> dict:
    """Investigador designado cancela a coleta; o solicitante cancela o próprio pedido ainda não aprovado."""
    _motivo(motivo)
    with conectar() as cx:
        i = _inv(cx, inv_id)
        f = funcoes(cx, inv_id, ator.sub)
    if "solicitante" in f and i["status"] in ("aguardando_aprovacao", "devolvida") and not i["lacrada"]:
        with conectar() as cx, cx.transaction():
            cx.execute("UPDATE investigacao SET status='cancelada', atualizado_em=now() WHERE id=%s", (inv_id,))
            cx.execute("UPDATE pedido SET status='cancelado' WHERE investigacao_id=%s AND status='aguardando'",
                       (inv_id,))
            trilha(cx, ator.sub, "cancelar_pedido", inv_id, motivo=motivo, porta=ator.porta)
        return {"investigacao": inv_id, "status": "cancelada"}
    _lacrada(_investigador(ator, inv_id))
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
    _lacrada(i)
    if i["status"] not in FINAIS:
        raise Negado("estado", f"Investigação está '{gestao.status_publico(i)}': pacote só depois da coleta", 409)
    with conectar() as cx:
        if sem_mascara:
            ator.exigir_recente()
            _motivo(destino)
            p = cx.execute("INSERT INTO pedido (investigacao_id, tipo, solicitante_sub, parametros) "
                           "VALUES (%s,'pacote_sem_mascara',%s,%s) RETURNING id",
                           (inv_id, ator.sub, Jsonb({"destino_declarado": True}))).fetchone()["id"]
            trilha(cx, ator.sub, "pedir_pacote_sem_mascara", inv_id, pedido=p, motivo=destino, porta=ator.porta)
            gestao.notificar(cx, [s for s in gestao.com_papel(cx, "aprovador", exceto=(ator.sub,))
                                  if s not in gestao.designados(cx, inv_id, "solicitante", "investigador")],
                             "pacote_sem_mascara", f"Pedido nº {p} de pacote sem máscara (investigação nº {inv_id})",
                             inv_id)
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
        gestao.notificar(cx, [p["solicitante_sub"]], "decisao_pacote", f"Pedido nº {pedido_id} de pacote sem "
                         f"máscara {'aprovado' if aprovar_ else 'recusado'}", p["investigacao_id"])
        if aprovar_:
            return _gerar(cx, p["solicitante_sub"], p["investigacao_id"], True, pedido_id)
    return {"pedido": pedido_id, "status": "recusado"}


def pacotes(ator: Ator, inv_id: int) -> list[dict]:
    _lacrada(_investigador(ator, inv_id))
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
    _lacrada(_investigador(ator, p["investigacao_id"]))
    if p["pedido_por"] != ator.sub:
        raise Negado("designacao", "Só quem pediu o pacote baixa", 404)
    if p["sem_mascara"]:
        ator.exigir_recente()
    agora = datetime.now(timezone.utc)
    if p["status"] == "expirado" or (p["expira_em"] and p["expira_em"] < agora):
        raise Negado("expirado", "O pacote sem máscara ficou disponível por 24 h e foi apagado. Peça novamente.", 410)
    if p["status"] != "pronto":
        raise Negado("estado", f"Pacote {p['status']}", 409)
    tok = secrets.token_urlsafe(32)
    with conectar() as cx:
        cx.execute("INSERT INTO link_download (token_hash, pacote_id, sub, expira_em) VALUES (%s,%s,%s,%s)",
                   (hashlib.sha256(tok.encode()).hexdigest(), pacote_id, ator.sub, agora + VALIDADE_LINK))
    return {"link": f"/api/download/{tok}", "expira_em": (agora + VALIDADE_LINK).isoformat()}


def baixar(ator: Ator, tok: str) -> tuple[str, bytes]:
    h = hashlib.sha256(tok.encode()).hexdigest()
    with conectar() as cx, cx.transaction():
        l = cx.execute("SELECT * FROM link_download WHERE token_hash=%s FOR UPDATE", (h,)).fetchone()
        if not l or l["usado_em"] or l["sub"] != ator.sub:
            raise Negado("link", "Link inválido, já usado ou de outra pessoa", 404)
        if l["expira_em"] < datetime.now(timezone.utc):
            raise Negado("expirado", "Este link expirou (válido por 10 min). Gere um novo em Pacotes.", 410)
        p = cx.execute("SELECT * FROM pacote WHERE id=%s", (l["pacote_id"],)).fetchone()
        _lacrada(cx.execute("SELECT lacrada FROM investigacao WHERE id=%s", (p["investigacao_id"],)).fetchone())
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


# ------------------------------------------------------------------ notificações (W2 §9) e pedido de acesso (§10)
def notificacoes(ator: Ator, nao_lidas: bool = False) -> list[dict]:
    ator.exigir_perfil()
    with conectar() as cx:
        return [{"id": r["id"], "tipo": r["tipo"], "texto": r["texto"], "investigacao": r["investigacao_id"],
                 "quando": gestao.iso(r["criado_em"]), "lida": r["lida_em"] is not None}
                for r in cx.execute("SELECT * FROM notificacao WHERE sub=%s" + (" AND lida_em IS NULL" if nao_lidas
                                                                                 else "") + " ORDER BY id DESC LIMIT 200",
                                    (ator.sub,))]


def marcar_lida(ator: Ator, nid: int | None = None) -> dict:
    ator.exigir_perfil()
    with conectar() as cx:
        if nid is None:
            n = cx.execute("UPDATE notificacao SET lida_em=now() WHERE sub=%s AND lida_em IS NULL", (ator.sub,)).rowcount
            return {"lidas": n}
        if cx.execute("UPDATE notificacao SET lida_em=coalesce(lida_em, now()) WHERE id=%s AND sub=%s",
                      (nid, ator.sub)).rowcount != 1:
            raise Negado("inexistente", "Notificação inexistente", 404)
    return {"lidas": 1}


def pedir_acesso(ator: Ator, inv_id: int, motivo: str) -> dict:
    """Resposta igual exista ou não a investigação (não confirma existência); vai para a trilha global."""
    ator.exigir_perfil()
    _motivo(motivo)
    with conectar() as cx:
        trilha(cx, ator.sub, "pedir_acesso", None, investigacao_pedida=int(inv_id), motivo=motivo, porta=ator.porta)
    return {"recebido": True}


# ------------------------------------------------------------------ substitutos (W2 §11)
def substitutos(ator: Ator) -> list[dict]:
    ator.exigir("aprovador", "gestor_acesso", "auditor_interno")
    with conectar() as cx:
        nomes = {r["sub"]: r["username"] for r in cx.execute("SELECT sub, username FROM usuario")}
        subs = {r["aprovador_sub"]: r for r in cx.execute("SELECT * FROM substituto")}
        aprov = [r["sub"] for r in cx.execute("SELECT sub FROM usuario WHERE 'aprovador' = ANY(papeis) ORDER BY username")]
        return [{"aprovador": nomes.get(a, a),
                 "substituto": nomes.get(subs[a]["substituto_sub"], subs[a]["substituto_sub"]) if a in subs else None,
                 "atualizado_em": gestao.iso(subs[a]["atualizado_em"]) if a in subs else None}
                for a in aprov + [a for a in subs if a not in aprov]]


def definir_substituto(ator: Ator, substituto: str) -> dict:
    ator.exigir("aprovador")
    with conectar() as cx:
        u = cx.execute("SELECT * FROM usuario WHERE username=%s OR sub=%s", (substituto, substituto)).fetchone()
        if not u or "aprovador" not in u["papeis"]:
            raise Negado("designacao", "O substituto precisa ter o perfil aprovador e ter entrado no auditor", 422)
        if u["sub"] == ator.sub:
            raise Negado("segregacao", "O aprovador não é substituto de si mesmo", 422)
        cx.execute("INSERT INTO substituto (aprovador_sub, substituto_sub) VALUES (%s,%s) ON CONFLICT (aprovador_sub) "
                   "DO UPDATE SET substituto_sub=EXCLUDED.substituto_sub, atualizado_em=now()", (ator.sub, u["sub"]))
        trilha(cx, ator.sub, "definir_substituto", None, substituto=u["sub"], porta=ator.porta)
    return {"aprovador": ator.username, "substituto": u["username"]}


# ------------------------------------------------------------------ perfis e acessos (W2 §12, PROPOSTA §4.3)
def _admin():
    from . import kc_gestao
    try:
        return kc_gestao.Admin()
    except kc_gestao.IndisponivelKC as e:
        raise Negado("keycloak_indisponivel", str(e), 503) from e


def _kc(f):
    from . import kc_gestao
    try:
        return f()
    except kc_gestao.IndisponivelKC as e:
        raise Negado("keycloak_indisponivel", str(e), 503) from e


def perfis(ator: Ator) -> list[dict]:
    ator.exigir("gestor_acesso")
    adm = _admin()
    try:
        us = _kc(adm.usuarios)
    finally:
        adm.fechar()
    with conectar() as cx:
        login = {r["sub"]: r["ultimo_login"] for r in cx.execute("SELECT sub, ultimo_login FROM usuario")}
        recert = {r["sub"]: r["recertificado_em"] for r in cx.execute("SELECT sub, recertificado_em FROM papel_visto")}
    return [{"username": u["username"], "nome": u["nome"], "unidade": u["unidade"], "papeis": u["papeis"],
             "coordenador": u["coordenador"], "ultimo_login": gestao.iso(login.get(u["sub"])),
             "recertificado_em": gestao.iso(recert.get(u["sub"]))} for u in us]


def mudar_papeis(ator: Ator, username: str, conceder: list[str], revogar: list[str], motivo: str) -> dict:
    """Concessão/revogação pelo Keycloak Admin do realm dedicado. Combinação proibida recusada antes de chamar o
    Keycloak. Alerta ao auditor interno (notificação + SIEM)."""
    from . import kc_gestao
    ator.exigir("gestor_acesso")
    ator.exigir_recente()
    _motivo(motivo)
    conceder, revogar = sorted(set(conceder or [])), sorted(set(revogar or []))
    invalidos = (set(conceder) | set(revogar)) - set(PAPEIS)
    if invalidos or not (conceder or revogar):
        raise Negado("validacao", f"Perfis válidos: {', '.join(PAPEIS)}", 422)
    if set(conceder) & set(revogar):
        raise Negado("validacao", "O mesmo perfil não pode ser concedido e revogado", 422)
    adm = _admin()
    try:
        u = _kc(lambda: adm.usuario(username))
        if not u:
            raise Negado("inexistente", "Usuário inexistente no realm do auditor", 404)
        if u["sub"] == ator.sub:
            raise Negado("segregacao", "O gestor de acesso não altera os próprios perfis")
        novo = (set(u["papeis"]) | set(conceder)) - set(revogar)
        try:
            conferir_papeis(novo)
        except Negado as e:
            raise Negado("combinacao_proibida", f"{e} (§4.2): concessão recusada", 422) from e
        _kc(lambda: adm.mudar_papeis(u["sub"], [p for p in conceder if p not in u["papeis"]],
                                     [p for p in revogar if p in u["papeis"]]))
        depois = _kc(lambda: adm.usuario(username))
    finally:
        adm.fechar()
    with conectar() as cx:
        c, r = set(depois["papeis"]) - set(u["papeis"]), set(u["papeis"]) - set(depois["papeis"])
        if c or r:
            kc_gestao.alertar(cx, u["sub"], username, c, r, "api", ator.sub, motivo)
        kc_gestao.registrar_visto(cx, depois)
    return {"username": username, "papeis": depois["papeis"]}


def recertificacoes(ator: Ator) -> list[dict]:
    ator.exigir("gestor_acesso")
    with conectar() as cx:
        out = []
        for rc in cx.execute("SELECT * FROM recertificacao ORDER BY id DESC").fetchall():
            its = cx.execute("SELECT * FROM recertificacao_item WHERE recertificacao_id=%s ORDER BY username",
                             (rc["id"],)).fetchall()
            out.append(_recert(rc, its))
    return out


def _recert(rc: dict, its: list[dict]) -> dict:
    return {"id": rc["id"], "criada_em": gestao.iso(rc["aberta_em"]), "prazo": gestao.iso(rc["prazo"]),
            "concluida_em": gestao.iso(rc["encerrada_em"]),
            "pendentes": [{"username": x["username"], "papeis": x["papeis"]} for x in its if x["manter"] is None],
            "itens": [{"username": x["username"], "papeis": x["papeis"], "manter": x["manter"],
                       "decidido_em": gestao.iso(x["decidido_em"])} for x in its]}


def abrir_recertificacao(ator: Ator, usuarios: list[str] | None = None, prazo_dias: int = 30) -> dict:
    """Recertificação (semestral): lista quem tem perfil; o que não for confirmado até o prazo é revogado."""
    ator.exigir("gestor_acesso")
    if not 1 <= prazo_dias <= 90:
        raise Negado("validacao", "prazo_dias: 1 a 90", 422)
    adm = _admin()
    try:
        us = [u for u in _kc(adm.usuarios) if u["papeis"] and (not usuarios or u["username"] in usuarios)]
    finally:
        adm.fechar()
    with conectar() as cx, cx.transaction():
        rid = cx.execute("INSERT INTO recertificacao (aberta_por, prazo) VALUES (%s, now() + %s) RETURNING id",
                         (ator.sub, timedelta(days=prazo_dias))).fetchone()["id"]
        for u in us:
            cx.execute("INSERT INTO recertificacao_item (recertificacao_id, sub, username, papeis) VALUES (%s,%s,%s,%s)",
                       (rid, u["sub"], u["username"], u["papeis"]))
        trilha(cx, ator.sub, "abrir_recertificacao", None, recertificacao=rid, itens=len(us), prazo_dias=prazo_dias,
               porta=ator.porta)
        gestao.notificar(cx, gestao.coordenadores(cx), "recertificacao",
                         f"Recertificação nº {rid} aberta: confirme os perfis da equipe")
        rc = cx.execute("SELECT * FROM recertificacao WHERE id=%s", (rid,)).fetchone()
        its = cx.execute("SELECT * FROM recertificacao_item WHERE recertificacao_id=%s ORDER BY username",
                         (rid,)).fetchall()
    return _recert(rc, its)


def confirmar_recertificacao(ator: Ator, rid: int, username: str, manter: bool) -> dict:
    from . import kc_gestao
    ator.exigir("gestor_acesso")
    with conectar() as cx:
        it = cx.execute("SELECT i.*, r.encerrada_em FROM recertificacao_item i JOIN recertificacao r ON "
                        "r.id=i.recertificacao_id WHERE i.recertificacao_id=%s AND i.username=%s",
                        (rid, username)).fetchone()
        if not it:
            raise Negado("inexistente", "Item de recertificação inexistente", 404)
        if it["encerrada_em"] or it["manter"] is not None:
            raise Negado("estado", "Item já decidido ou recertificação encerrada", 409)
        if it["sub"] == ator.sub:
            raise Negado("segregacao", "Ninguém recertifica os próprios perfis")
        if not manter:
            ator.exigir_recente()
            adm = _admin()
            try:
                _kc(lambda: kc_gestao.revogar(cx, adm, it["sub"], username, ator.sub, "recertificacao"))
            finally:
                adm.fechar()
        else:
            cx.execute("UPDATE papel_visto SET recertificado_em=now() WHERE sub=%s", (it["sub"],))
        cx.execute("UPDATE recertificacao_item SET manter=%s, decidido_por=%s, decidido_em=now() WHERE "
                   "recertificacao_id=%s AND sub=%s", (manter, ator.sub, rid, it["sub"]))
        trilha(cx, ator.sub, "confirmar_recertificacao", None, recertificacao=rid, usuario=it["sub"], manter=manter,
               porta=ator.porta)
        if not cx.execute("SELECT 1 FROM recertificacao_item WHERE recertificacao_id=%s AND manter IS NULL",
                          (rid,)).fetchone():
            cx.execute("UPDATE recertificacao SET encerrada_em=now() WHERE id=%s", (rid,))
            trilha(cx, ator.sub, "encerrar_recertificacao", None, recertificacao=rid, vencida=False)
    return {"id": rid, "username": username, "manter": manter}


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


def _instancia(nome: str) -> dict:
    with conectar() as cx:
        inst = cx.execute("SELECT * FROM instancia WHERE nome=%s", (nome,)).fetchone()
    if not inst:
        raise Negado("inexistente", "Instância inexistente", 404)
    return inst


def rodar_sondas(ator: Ator, nome: str) -> dict:
    """Teste de conexão, sondas no realm de homologação e descoberta (as requisições ficam registradas, §8.3)."""
    ator.exigir("admin_tecnico")
    from . import sondas
    from .descoberta import descobrir
    from .kc import ClienteKC
    inst = _instancia(nome)
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


def testar_instancia(ator: Ator, nome: str) -> dict:
    """Teste de conexão (token do service account), sem sondas nem descoberta (W2 §13)."""
    import time
    ator.exigir("admin_tecnico")
    from .kc import ClienteKC
    from .redigir import erro
    inst = _instancia(nome)
    t0 = time.monotonic()
    ok, msg = True, None
    try:
        with chaves.como_usuario(ator.token):
            cli = ClienteKC(inst, finalidade="sondas", registrar=False)
        try:
            cli.token()
        finally:
            cli.fechar()
    except Exception as e:  # noqa: BLE001
        ok, msg = False, erro(f"{type(e).__name__}: {e}")[:300]
    ms = int((time.monotonic() - t0) * 1000)
    with conectar() as cx:
        trilha(cx, ator.sub, "testar_instancia", None, instancia=nome, ok=ok, ms=ms, porta=ator.porta)
    return {"instancia": nome, "ok": ok, "ms": ms, "erro": msg,
            "texto": f"Conexão com {nome} ok ({ms} ms)" if ok else f"Falha na conexão com {nome}: {msg}"}


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
        return {"jobs": jobs, "tarefas": tarefas, "filas": gestao.filas(cx), "workers": gestao.workers(cx)}


# ------------------------------------------------------------------ gestão de acesso (W1)
def usuarios(ator: Ator) -> list[dict]:
    """Para a recertificação: quem tem qual perfil e já entrou no auditor."""
    ator.exigir("gestor_acesso")
    with conectar() as cx:
        return [{"usuario": r["username"], "unidade": r["unidade"], "papeis": r["papeis"],
                 "ultimo_login": r["ultimo_login"].isoformat()} for r in cx.execute("SELECT * FROM usuario ORDER BY 1")]


def alerta_papel(sub_alvo: str, mudanca: str):
    from . import kc_gestao
    with conectar() as cx:
        kc_gestao.alertar(cx, sub_alvo, sub_alvo, [], [], mudanca)

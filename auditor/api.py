"""API do auditor e BFF (W1, PROPOSTA_WEB §8 e §8.9). Rotas finas sobre auditor/casos.py.

  python -m auditor api [--porta 8000]

Duas formas de autenticação, ambas com MFA (acr=mfa) no realm dedicado:
  * web: sessão do BFF (login por código + PKCE). Cookie HttpOnly, SameSite=Strict, Secure (AUDITOR_COOKIE_SEGURO=0
    só para teste em http); 30 min sem atividade, no máximo 8 h; id regenerado a cada login; os tokens ficam no
    banco cifrados com uma chave que só existe no cookie. Requisições que mudam estado exigem o cabeçalho
    `X-Requisicao: kc-auditor` (CSRF);
  * CLI de produção: `Authorization: Bearer <access token>` obtido por device flow.

W2: as telas (web/dist, SPA) são servidas em `/`; acompanhamento ao vivo por SSE (auditor/tempo_real.py); erro
inesperado responde 500 com um código de correlação, que vai para logs/api_erros.jsonl sem dado pessoal.

  AUDITOR_OIDC_EMISSOR, AUDITOR_API_URL (http://localhost:8000), AUDITOR_BFF_SEGREDO (ou chaves/realm_auditor.json),
  AUDITOR_WEB_DIST (web/dist)
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import secrets
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from fastapi import Depends, FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, JSONResponse, PlainTextResponse, RedirectResponse, Response
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field

from . import __version__, casos, oidc, tempo_real
from .acesso import Ator, Negado
from .db import conectar, trilha

COOKIE = "kc_auditor_sessao"
OCIOSA_S, MAXIMA_S = 30 * 60, 8 * 3600
CSRF = ("X-Requisicao", "kc-auditor")
BFF_ID = "kc-auditor-bff"


def _cfg() -> dict:
    p = Path(os.environ.get("AUDITOR_REALM_CFG", "chaves/realm_auditor.json"))
    c = json.loads(p.read_text()) if p.exists() else {}
    return {"segredo": os.environ.get("AUDITOR_BFF_SEGREDO") or c.get("bff_segredo"),
            "base": os.environ.get("AUDITOR_API_URL", "http://localhost:8000").rstrip("/")}


app = FastAPI(title="kc-auditor", version=__version__, docs_url="/api/docs", openapi_url="/api/openapi.json",
              redoc_url=None, swagger_ui_oauth2_redirect_url=None)


@app.middleware("http")
async def cabecalhos(request: Request, chamar):
    r = await chamar(request)
    longo = request.url.path.startswith("/assets/") and r.status_code == 200   # arquivos com hash no nome (Vite)
    r.headers.update({"Cache-Control": "public, max-age=31536000, immutable" if longo else "no-store",
                      "X-Content-Type-Options": "nosniff", "X-Frame-Options": "DENY",
                      "Referrer-Policy": "no-referrer",
                      "Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'; object-src 'none'"})
    return r


@app.exception_handler(Negado)
async def negado(_req, e: Negado):
    corpo = {"erro": e.codigo, "mensagem": str(e)}
    if e.codigo == "step_up":
        corpo["login"] = "/auth/entrar?step_up=1"
    return JSONResponse(corpo, status_code=e.status)


@app.exception_handler(RequestValidationError)
async def invalido(_req, e: RequestValidationError):
    """Sem eco do valor recebido (o corpo pode trazer o CPF): só onde e o quê."""
    campos = [{"campo": ".".join(str(x) for x in err.get("loc", ())[1:]), "erro": err.get("type")}
              for err in e.errors()]
    return JSONResponse({"erro": "validacao", "mensagem": "Requisição inválida: " +
                         ", ".join(c["campo"] or "corpo" for c in campos), "campos": campos}, status_code=422)


@app.exception_handler(Exception)
async def interno(req: Request, e: Exception):
    """Erro inesperado: código de correlação na resposta e no log, sem dado pessoal (mensagem redigida)."""
    from datetime import datetime, timezone

    from .redigir import erro
    cod = f"{secrets.token_hex(2).upper()}-{secrets.token_hex(2).upper()}"
    p = Path(os.environ.get("AUDITOR_LOG_ERROS", "logs/api_erros.jsonl"))
    p.parent.mkdir(parents=True, exist_ok=True)
    with p.open("a", encoding="utf-8") as f:
        f.write(json.dumps({"quando": datetime.now(timezone.utc).isoformat(), "correlacao": cod,
                            "metodo": req.method, "rota": getattr(req.scope.get("route"), "path", None),
                            "erro": erro(f"{type(e).__name__}: {e}")[:500]}, ensure_ascii=False) + "\n")
    return JSONResponse({"erro": "interno", "mensagem": f"Algo deu errado do nosso lado. Informe ao suporte o código "
                                                        f"{cod}.", "correlacao": cod}, status_code=500)


# ------------------------------------------------------------------ sessão
def _cifra(chave: bytes, dados: dict) -> bytes:
    n = os.urandom(12)
    return n + AESGCM(chave).encrypt(n, json.dumps(dados).encode(), b"kc-auditor/sessao")


def _decifra(chave: bytes, blob: bytes) -> dict:
    blob = bytes(blob)
    return json.loads(AESGCM(chave).decrypt(blob[:12], blob[12:], b"kc-auditor/sessao"))


def _ator_da_sessao(request: Request) -> Ator | None:
    v = request.cookies.get(COOKIE)
    if not v or "." not in v:
        return None
    sid, k64 = v.split(".", 1)
    try:
        chave = base64.urlsafe_b64decode(k64 + "=" * (-len(k64) % 4))
    except Exception:  # noqa: BLE001
        return None
    h = hashlib.sha256(sid.encode()).hexdigest()
    with conectar() as cx:
        s = cx.execute("SELECT *, extract(epoch FROM now()-ultimo_uso) ociosa, extract(epoch FROM now()-criado_em) "
                       "idade FROM sessao_web WHERE id_hash=%s AND encerrada_em IS NULL", (h,)).fetchone()
        if not s:
            return None
        if s["ociosa"] > OCIOSA_S or s["idade"] > MAXIMA_S:
            cx.execute("UPDATE sessao_web SET encerrada_em=now() WHERE id_hash=%s", (h,))
            return None
        try:
            t = _decifra(chave, s["tokens_cifrados"])
        except Exception:  # noqa: BLE001
            return None
        try:
            claims = oidc.validar(t["access_token"])
        except oidc.TokenInvalido:
            try:   # access token vence em 5 min; a sessão renova com o refresh token
                t = oidc.renovar(BFF_ID, _cfg()["segredo"], t["refresh_token"])
                claims = oidc.validar(t["access_token"])
            except oidc.TokenInvalido:
                cx.execute("UPDATE sessao_web SET encerrada_em=now() WHERE id_hash=%s", (h,))
                return None
            cx.execute("UPDATE sessao_web SET tokens_cifrados=%s WHERE id_hash=%s", (_cifra(chave, t), h))
        cx.execute("UPDATE sessao_web SET ultimo_uso=now() WHERE id_hash=%s", (h,))
    return Ator.de_claims(claims, "web", t["access_token"])


async def ator(request: Request) -> Ator:
    """Dependência async de propósito: o contextvar com o usuário (db.sub_atual) definido aqui, no contexto da
    requisição, chega às rotas síncronas que o FastAPI roda no threadpool (cópia do contexto em cada chamada)."""
    from starlette.concurrency import run_in_threadpool
    from . import db
    a = await run_in_threadpool(_ator, request)
    db.sub_atual.set(a.sub)
    return a


def _ator(request: Request) -> Ator:
    auth = request.headers.get("authorization", "")
    if auth.lower().startswith("bearer "):
        tok = auth[7:].strip()
        try:
            a = Ator.de_claims(oidc.validar(tok), "cli", tok)
        except oidc.TokenInvalido as e:
            raise Negado("token", f"Token recusado: {e}", 401) from e
    else:
        a = _ator_da_sessao(request)
        if not a:
            raise Negado("sem_sessao", "Autenticação exigida", 401)
        if request.method not in ("GET", "HEAD") and request.headers.get(CSRF[0]) != CSRF[1]:
            raise Negado("csrf", f"Cabeçalho {CSRF[0]} ausente", 403)
    from .acesso import conferir_papeis
    conferir_papeis(a.papeis)
    return a


# ------------------------------------------------------------------ login (BFF)
@app.get("/saude", include_in_schema=False)
def rota_saude():
    return {"ok": True, "versao": __version__}


@app.get("/auth/entrar")
def entrar(volta: str = "/", step_up: int = 0):
    if not volta.startswith("/") or volta.startswith("//"):
        volta = "/"
    estado, nonce = secrets.token_urlsafe(24), secrets.token_urlsafe(24)
    verificador, desafio = oidc.pkce()
    with conectar() as cx:
        cx.execute("DELETE FROM login_pendente WHERE criado_em < now() - interval '10 minutes'")
        cx.execute("INSERT INTO login_pendente (estado, verificador, nonce, volta) VALUES (%s,%s,%s,%s)",
                   (estado, verificador, nonce, volta))
    return RedirectResponse(oidc.url_autorizacao(BFF_ID, f"{_cfg()['base']}/auth/retorno", estado, nonce, desafio,
                                                 bool(step_up)), 302)


@app.get("/auth/retorno")
def retorno(request: Request, code: str = "", state: str = "", error: str = ""):
    with conectar() as cx:
        p = cx.execute("DELETE FROM login_pendente WHERE estado=%s AND criado_em > now() - interval '10 minutes' "
                       "RETURNING *", (state,)).fetchone()
    if not p or error or not code:
        raise Negado("login", "Login inválido ou expirado", 400)
    cfg = _cfg()
    try:
        t = oidc.trocar_codigo(BFF_ID, cfg["segredo"], code, f"{cfg['base']}/auth/retorno", p["verificador"])
        idt = oidc.validar(t["id_token"], audiencia=BFF_ID)
        claims = oidc.validar(t["access_token"])
    except oidc.TokenInvalido as e:
        raise Negado("login", f"Login recusado: {e}", 401) from e
    if idt.get("nonce") != p["nonce"] or idt.get("sub") != claims.get("sub"):
        raise Negado("login", "Login recusado: nonce", 401)
    a = Ator.de_claims(claims, "web", t["access_token"])
    casos.registrar_login(a)   # recusa papéis conflitantes
    sid, chave = secrets.token_urlsafe(32), os.urandom(32)
    with conectar() as cx:
        antigo = request.cookies.get(COOKIE, "").split(".")[0]
        if antigo:   # id da sessão regenerado a cada login
            cx.execute("UPDATE sessao_web SET encerrada_em=now() WHERE id_hash=%s",
                       (hashlib.sha256(antigo.encode()).hexdigest(),))
        cx.execute("INSERT INTO sessao_web (id_hash, sub, sid, auth_time, tokens_cifrados) VALUES (%s,%s,%s,%s,%s)",
                   (hashlib.sha256(sid.encode()).hexdigest(), a.sub, claims.get("sid"), a.auth_time,
                    _cifra(chave, {k: t[k] for k in ("access_token", "refresh_token", "id_token")})))
    r = RedirectResponse(p["volta"], 302)
    r.set_cookie(COOKIE, f"{sid}.{base64.urlsafe_b64encode(chave).rstrip(b'=').decode()}", httponly=True,
                 samesite="strict", secure=os.environ.get("AUDITOR_COOKIE_SEGURO", "1") != "0", max_age=MAXIMA_S,
                 path="/")
    return r


@app.post("/auth/sair")
def sair(request: Request, a: Ator = Depends(ator)):
    v = request.cookies.get(COOKIE, "").split(".")[0]
    with conectar() as cx:
        cx.execute("UPDATE sessao_web SET encerrada_em=now() WHERE id_hash=%s", (hashlib.sha256(v.encode()).hexdigest(),))
        trilha(cx, a.sub, "logout", None, porta=a.porta)
    r = JSONResponse({"saiu": True, "logout_idp": oidc.descoberta().get("end_session_endpoint")})
    r.delete_cookie(COOKIE, path="/")
    return r


@app.post("/auth/logout-canal", include_in_schema=False)
async def logout_canal(request: Request):
    """Logout pelo canal de retorno do OIDC: o Keycloak avisa o fim da sessão e o BFF encerra as suas."""
    tok = (await request.form()).get("logout_token", "")
    try:
        c = oidc.validar(str(tok), audiencia=BFF_ID, exigir_mfa=False)
    except oidc.TokenInvalido:
        return Response(status_code=400)
    if "http://schemas.openid.net/event/backchannel-logout" not in (c.get("events") or {}):
        return Response(status_code=400)
    with conectar() as cx:
        cx.execute("UPDATE sessao_web SET encerrada_em=now() WHERE encerrada_em IS NULL AND (sid=%s OR sub=%s)",
                   (c.get("sid"), c.get("sub") if not c.get("sid") else None))
    return Response(status_code=200)


# ------------------------------------------------------------------ corpo das requisições
class Pedido(BaseModel):
    cpf: str | None = None
    titulo: str | None = None
    de: str
    ate: str
    justificativa: str = Field(min_length=5)
    fuso: str = "America/Bahia"
    granularidade: str = "dia"
    instancias: list[str] | None = None
    varredura: bool = False
    base_dias: int = 0
    origem: dict | None = None     # pedido externo: orgao, documento, processo, fundamento, destinatario
    rascunho: bool = False         # W2: grava sem enviar
    preservacao_urgente: bool = False
    tipo_processo: str | None = None
    processo: str | None = None    # texto livre: cifrado com a DEK; a busca usa o HMAC normalizado
    contas_informadas: list[dict] | None = None   # [{"instancia", "realm", "username"}]


class Estimativa(BaseModel):
    de: str
    ate: str
    fuso: str = "America/Bahia"
    granularidade: str = "dia"
    instancias: list[str] | None = None
    varredura: bool = False
    base_dias: int = 0


class Preservacao(BaseModel):
    investigador: str
    motivo: str


class Substituto(BaseModel):
    substituto: str


class Papeis(BaseModel):
    conceder: list[str] = []
    revogar: list[str] = []
    motivo: str


class Recertificacao(BaseModel):
    usuarios: list[str] | None = None
    prazo_dias: int = 30


class Confirmacao(BaseModel):
    username: str
    manter: bool


class Aprovacao(BaseModel):
    investigador: str
    motivo: str
    sigilosa: bool = False


class Motivo(BaseModel):
    motivo: str


class PedidoPacote(BaseModel):
    sem_mascara: bool = False
    destino: str | None = None


class Decisao(BaseModel):
    aprovar: bool
    motivo: str


class Orcamento(BaseModel):
    concorrencia: int
    req_por_s: float


# ------------------------------------------------------------------ rotas
@app.get("/api/eu")
def r_eu(a: Ator = Depends(ator)):
    return casos.eu(a)


@app.get("/api/inicio")
def r_inicio(a: Ator = Depends(ator)):
    return casos.inicio(a)


@app.get("/api/investigacoes")
def r_listar(visao: str | None = None, estado: str | None = None, q: str | None = None, de: str | None = None,
             ate: str | None = None, pagina: int = 1, por_pagina: int = casos.POR_PAGINA, a: Ator = Depends(ator)):
    return casos.listar(a, visao, [x for x in (estado or "").split(",") if x], q, de, ate, pagina, por_pagina)


def _identificador(p: Pedido, obrigatorio: bool = True):
    tipo, valor = ("cpf", p.cpf) if p.cpf else ("titulo", p.titulo)
    if not valor and obrigatorio:
        raise Negado("identificador", "Informe cpf ou titulo", 422)
    return tipo, valor


@app.post("/api/investigacoes", status_code=201)
def r_pedir(p: Pedido, a: Ator = Depends(ator)):
    tipo, valor = _identificador(p)
    return casos.pedir(a, tipo, valor, p.de, p.ate, p.justificativa, p.fuso, p.granularidade, p.instancias,
                       p.varredura, p.base_dias, p.origem, p.rascunho, p.preservacao_urgente, p.tipo_processo,
                       p.processo, p.contas_informadas)


@app.put("/api/investigacoes/{inv}")
def r_editar(inv: int, p: Pedido, a: Ator = Depends(ator)):
    tipo, valor = _identificador(p, obrigatorio=False)
    return casos.atualizar(a, inv, tipo, valor, p.de, p.ate, p.justificativa, p.fuso, p.granularidade, p.instancias,
                           p.varredura, p.base_dias, p.origem, p.preservacao_urgente, p.tipo_processo, p.processo,
                           p.contas_informadas)


@app.post("/api/investigacoes/{inv}/enviar")
def r_enviar(inv: int, a: Ator = Depends(ator)):
    return casos.enviar(a, inv)


@app.delete("/api/investigacoes/{inv}")
def r_descartar(inv: int, a: Ator = Depends(ator)):
    return casos.descartar(a, inv)


@app.get("/api/investigacoes/{inv}")
def r_ver(inv: int, a: Ator = Depends(ator)):
    return casos.ver(a, inv)


def _multipart(corpo: bytes, tipo: str, campo: str) -> tuple[str, bytes]:
    """multipart/form-data sem dependência extra (email da biblioteca padrão)."""
    from email import policy
    from email.parser import BytesParser
    if not tipo.startswith("multipart/form-data"):
        raise Negado("documento", "Envie multipart/form-data com o campo 'arquivo'", 415)
    m = BytesParser(policy=policy.HTTP).parsebytes(f"Content-Type: {tipo}\r\n\r\n".encode() + corpo)
    for parte in m.iter_parts() if m.is_multipart() else []:
        if parte.get_param("name", header="content-disposition") == campo:
            return parte.get_filename() or "documento", parte.get_payload(decode=True) or b""
    raise Negado("documento", f"Campo '{campo}' ausente", 422)


@app.post("/api/investigacoes/{inv}/documento", status_code=201)
async def r_documento(inv: int, request: Request, a: Ator = Depends(ator)):
    import asyncio
    if int(request.headers.get("content-length") or 0) > casos.DOC_MAX + 64 * 1024:
        raise Negado("documento", "Documento acima de 10 MB", 413)
    corpo = await request.body()
    if len(corpo) > casos.DOC_MAX + 64 * 1024:
        raise Negado("documento", "Documento acima de 10 MB", 413)
    nome, dados = _multipart(corpo, request.headers.get("content-type", ""), "arquivo")
    return await asyncio.to_thread(casos.enviar_documento, a, inv, nome, dados)


@app.get("/api/investigacoes/{inv}/documento")
def r_baixar_documento(inv: int, a: Ator = Depends(ator)):
    from urllib.parse import quote
    nome, tipo, dados = casos.baixar_documento(a, inv)
    return Response(dados, media_type=tipo, headers={
        "Content-Disposition": f"attachment; filename=\"documento\"; filename*=UTF-8''{quote(nome)}",
        "X-Conteudo-Sha256": hashlib.sha256(dados).hexdigest()})


@app.post("/api/investigacoes/{inv}/autorizar-preservacao")
def r_autorizar_preservacao(inv: int, d: Preservacao, a: Ator = Depends(ator)):
    return casos.autorizar_preservacao(a, inv, d.investigador, d.motivo)


@app.post("/api/investigacoes/{inv}/prorrogar-preservacao")
def r_prorrogar_preservacao(inv: int, d: Motivo, a: Ator = Depends(ator)):
    return casos.prorrogar_preservacao(a, inv, d.motivo)


@app.post("/api/investigacoes/{inv}/pedir-acesso", status_code=202)
def r_pedir_acesso(inv: int, d: Motivo, a: Ator = Depends(ator)):
    return casos.pedir_acesso(a, inv, d.motivo)


@app.get("/api/investigacoes/{inv}/acompanhamento")
def r_acompanhamento(inv: int, a: Ator = Depends(ator)):
    return casos.acompanhamento(a, inv)


# ------------------------------------------------------------------ análise (W3)
def _q(request: Request) -> dict:
    """Filtros da análise: técnicos (instancia, realm, cliente, categorias, tecnicos, tipo, resultado, de, ate,
    destaque) e por rótulo de pseudônimo (conta, ip, sessao). Valores reais não são aceitos aqui."""
    return {k: v for k, v in request.query_params.items()
            if k in ("instancia", "realm", "cliente", "categorias", "tecnicos", "tipo", "resultado", "de", "ate",
                     "destaque", "conta", "ip", "sessao", "apos", "limite")}


@app.get("/api/investigacoes/{inv}/dashboard")
def r_dashboard(inv: int, request: Request, a: Ator = Depends(ator)):
    from . import casos_analise
    return casos_analise.dashboard(a, inv, _q(request))


@app.get("/api/investigacoes/{inv}/eventos")
def r_eventos(inv: int, request: Request, a: Ator = Depends(ator)):
    from . import casos_analise
    return casos_analise.eventos(a, inv, _q(request))


@app.get("/api/investigacoes/{inv}/eventos/{ref}")
def r_evento(inv: int, ref: str, a: Ator = Depends(ator)):
    from . import casos_analise
    return casos_analise.evento(a, inv, ref)


@app.get("/api/investigacoes/{inv}/contas")
def r_contas(inv: int, a: Ator = Depends(ator)):
    from . import casos_analise
    return casos_analise.contas(a, inv)


@app.get("/api/investigacoes/{inv}/contas/{conta}/extras")
def r_contas_extras(inv: int, conta: int, a: Ator = Depends(ator)):
    from . import casos_analise
    return casos_analise.extras_conta(a, inv, conta)


@app.post("/api/investigacoes/{inv}/contas/{conta}/excluir", status_code=202)
def r_excluir_conta(inv: int, conta: int, d: Motivo, a: Ator = Depends(ator)):
    from . import casos_analise
    return casos_analise.decidir_conta(a, inv, conta, False, d.motivo)


@app.post("/api/investigacoes/{inv}/contas/{conta}/incluir", status_code=202)
def r_incluir_conta(inv: int, conta: int, d: Motivo, a: Ator = Depends(ator)):
    from . import casos_analise
    return casos_analise.decidir_conta(a, inv, conta, True, d.motivo)


@app.get("/api/investigacoes/{inv}/cobertura")
def r_cobertura(inv: int, a: Ator = Depends(ator)):
    from . import casos_analise
    return casos_analise.cobertura(a, inv)


@app.get("/api/investigacoes/{inv}/visao-agregada")
def r_visao_agregada(inv: int, a: Ator = Depends(ator)):
    from . import casos_analise
    return casos_analise.visao_agregada(a, inv)


@app.get("/api/investigacoes/{inv}/acompanhamento/stream")
def r_acompanhamento_stream(inv: int, request: Request, a: Ator = Depends(ator)):
    casos.abrir_acompanhamento(a, inv)
    try:
        cid = tempo_real.reservar(a.sub)
    except tempo_real.Limite:
        raise Negado("limite_conexoes", f"No máximo {tempo_real.MAX_CONEXOES} conexões ao vivo por usuário", 429)
    try:
        ultimo = int(request.headers.get("last-event-id") or 0)
    except ValueError:
        ultimo = 0
    return StreamingResponse(tempo_real.transmitir(request, inv, a.sub, cid, ultimo), media_type="text/event-stream",
                             headers={"X-Accel-Buffering": "no", "Connection": "keep-alive"})


@app.post("/api/estimativas")
def r_estimativa(d: Estimativa, a: Ator = Depends(ator)):
    return casos.estimar(a, d.de, d.ate, d.fuso, d.instancias, d.varredura, d.base_dias)


@app.get("/api/notificacoes")
def r_notificacoes(nao_lidas: int = 0, a: Ator = Depends(ator)):
    return casos.notificacoes(a, bool(nao_lidas))


@app.post("/api/notificacoes/lidas")
def r_notificacoes_lidas(a: Ator = Depends(ator)):
    return casos.marcar_lida(a, None)


@app.post("/api/notificacoes/{nid}/lida")
def r_notificacao_lida(nid: int, a: Ator = Depends(ator)):
    return casos.marcar_lida(a, nid)


@app.get("/api/substitutos")
def r_substitutos(a: Ator = Depends(ator)):
    return casos.substitutos(a)


@app.put("/api/substitutos/eu")
def r_substituto(d: Substituto, a: Ator = Depends(ator)):
    return casos.definir_substituto(a, d.substituto)


@app.get("/api/perfis")
def r_perfis(a: Ator = Depends(ator)):
    return casos.perfis(a)


@app.post("/api/perfis/{username}/papeis")
def r_papeis(username: str, d: Papeis, a: Ator = Depends(ator)):
    return casos.mudar_papeis(a, username, d.conceder, d.revogar, d.motivo)


@app.get("/api/recertificacoes")
def r_recertificacoes(a: Ator = Depends(ator)):
    return casos.recertificacoes(a)


@app.post("/api/recertificacoes", status_code=201)
def r_abrir_recertificacao(d: Recertificacao | None = None, a: Ator = Depends(ator)):
    d = d or Recertificacao()
    return casos.abrir_recertificacao(a, d.usuarios, d.prazo_dias)


@app.get("/api/investigacoes/{inv}/investigadores-elegiveis")
def r_elegiveis(inv: int, a: Ator = Depends(ator)):
    return casos.investigadores_elegiveis(a, inv)


@app.get("/api/instancias/disponiveis")
def r_disponiveis(a: Ator = Depends(ator)):
    return casos.instancias_disponiveis(a)


@app.post("/api/recertificacoes/{rid}/confirmar")
def r_confirmar_recertificacao(rid: int, d: Confirmacao, a: Ator = Depends(ator)):
    return casos.confirmar_recertificacao(a, rid, d.username, d.manter)


@app.get("/api/investigacoes/{inv}/progresso")
def r_progresso(inv: int, a: Ator = Depends(ator)):
    return casos.progresso(a, inv)


@app.post("/api/investigacoes/{inv}/aprovar")
def r_aprovar(inv: int, d: Aprovacao, a: Ator = Depends(ator)):
    return casos.aprovar(a, inv, d.investigador, d.motivo, d.sigilosa)


@app.post("/api/investigacoes/{inv}/devolver")
def r_devolver(inv: int, d: Motivo, a: Ator = Depends(ator)):
    return casos.devolver(a, inv, d.motivo)


@app.post("/api/investigacoes/{inv}/recusar")
def r_recusar(inv: int, d: Motivo, a: Ator = Depends(ator)):
    return casos.recusar(a, inv, d.motivo)


@app.post("/api/investigacoes/{inv}/reenviar")
def r_reenviar(inv: int, d: Motivo, a: Ator = Depends(ator)):
    return casos.reenviar(a, inv, d.motivo)


@app.post("/api/investigacoes/{inv}/iniciar")
def r_iniciar(inv: int, a: Ator = Depends(ator)):
    return casos.iniciar_coleta(a, inv)


@app.post("/api/investigacoes/{inv}/pausar")
def r_pausar(inv: int, a: Ator = Depends(ator)):
    return casos.pausar(a, inv)


@app.post("/api/investigacoes/{inv}/retomar")
def r_retomar(inv: int, a: Ator = Depends(ator)):
    return casos.retomar(a, inv)


@app.post("/api/investigacoes/{inv}/cancelar")
def r_cancelar(inv: int, d: Motivo, a: Ator = Depends(ator)):
    return casos.cancelar(a, inv, d.motivo)


@app.get("/api/investigacoes/{inv}/pacotes")
def r_pacotes(inv: int, a: Ator = Depends(ator)):
    return casos.pacotes(a, inv)


@app.post("/api/investigacoes/{inv}/pacotes", status_code=202)
def r_pedir_pacote(inv: int, d: PedidoPacote, a: Ator = Depends(ator)):
    return casos.pedir_pacote(a, inv, d.sem_mascara, d.destino)


@app.get("/api/aprovacoes")
def r_aprovacoes(a: Ator = Depends(ator)):
    return casos.aguardando_decisao(a)


@app.post("/api/aprovacoes/{pedido}/decidir")
def r_decidir(pedido: int, d: Decisao, a: Ator = Depends(ator)):
    return casos.decidir_pacote(a, pedido, d.aprovar, d.motivo)


@app.post("/api/pacotes/{pacote}/link")
def r_link(pacote: int, a: Ator = Depends(ator)):
    return casos.link_download(a, pacote)


@app.get("/api/download/{tok}")
def r_download(tok: str, a: Ator = Depends(ator)):
    nome, dados = casos.baixar(a, tok)
    return Response(dados, media_type="application/zip",
                    headers={"Content-Disposition": f'attachment; filename="{nome}"',
                             "X-Conteudo-Sha256": hashlib.sha256(dados).hexdigest()})


@app.get("/api/trilha")
def r_trilha(investigacao: int | None = None, a: Ator = Depends(ator)):
    return casos.trilha_investigacao(a, investigacao)


@app.get("/api/trilha/verificar")
def r_verificar(investigacao: int | None = None, a: Ator = Depends(ator)):
    return casos.verificar_cadeia(a, investigacao)


@app.get("/api/instancias")
def r_instancias(a: Ator = Depends(ator)):
    return casos.instancias(a)


class Instancia(BaseModel):
    nome: str
    url: str
    client_id: str
    segredo: str
    realm_auth: str = "master"
    concorrencia: int = 2
    req_por_s: float = 5
    versao: str | None = None
    realms_esperados: list[str] = []
    homologacao: str | None = None
    sonda: str | None = None


@app.post("/api/instancias", status_code=201)
def r_cadastrar(d: Instancia, a: Ator = Depends(ator)):
    return casos.cadastrar_instancia(a, **d.model_dump())


@app.post("/api/instancias/{nome}/sondas")
def r_sondas(nome: str, a: Ator = Depends(ator)):
    return casos.rodar_sondas(a, nome)


@app.post("/api/instancias/{nome}/testar")
def r_testar(nome: str, a: Ator = Depends(ator)):
    return casos.testar_instancia(a, nome)


@app.post("/api/instancias/{nome}/orcamento")
def r_orcamento(nome: str, d: Orcamento, a: Ator = Depends(ator)):
    return casos.ajustar_orcamento(a, nome, d.concorrencia, d.req_por_s)


@app.get("/api/servicos/saude")
def r_saude_servicos(a: Ator = Depends(ator)):
    return casos.saude(a)


@app.get("/api/usuarios")
def r_usuarios(a: Ator = Depends(ator)):
    return casos.usuarios(a)


# ------------------------------------------------------------------ telas (W2 §14): web/dist como SPA
def _dist() -> Path:
    return Path(os.environ.get("AUDITOR_WEB_DIST", Path(__file__).resolve().parents[1] / "web" / "dist"))


@app.get("/", include_in_schema=False)
@app.get("/{caminho:path}", include_in_schema=False)
def r_spa(caminho: str = ""):
    """Arquivo de web/dist se existir; senão index.html (rotas da SPA). /api e /auth nunca caem aqui."""
    if caminho.split("/", 1)[0] in ("api", "auth"):
        return JSONResponse({"erro": "inexistente", "mensagem": "Rota inexistente"}, status_code=404)
    d = _dist().resolve()
    if not (d / "index.html").is_file():
        return PlainTextResponse("Interface não compilada (npm run build em web/)", status_code=503)
    if caminho:
        f = (d / caminho).resolve()
        if f.is_file() and f.is_relative_to(d):
            return FileResponse(f)
        if caminho.startswith("assets/"):
            return PlainTextResponse("Arquivo inexistente", status_code=404)
    return FileResponse(d / "index.html", media_type="text/html")


ROTAS_PUBLICAS = {"/saude", "/auth/entrar", "/auth/retorno", "/auth/logout-canal", "/api/docs", "/api/openapi.json",
                  "/", "/{caminho:path}"}


def servir(porta: int = 8000):
    """Com AUDITOR_DSN_API, a API conecta com o papel kc_api (sujeito à RLS por designação, migração 0011)."""
    import uvicorn
    from . import db
    if os.environ.get("AUDITOR_DSN_API"):
        db.DSN = os.environ["AUDITOR_DSN_API"]
    uvicorn.run(app, host="127.0.0.1", port=porta, log_level="warning")

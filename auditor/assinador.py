"""`assinador`: serviço de assinatura isolado (W5, PROPOSTA_WEB §6.2).

O Vault Transit assina o que receber de um token autorizado e não sabe o que é um selo. O controle fica aqui: um
serviço pequeno, em host próprio, único com a política `transit/sign/kc-auditor-assinatura`. Ele recebe o manifesto
do worker de pacotes, lê os selos da cadeia da investigação, recalcula a raiz e as contagens, confere com o
manifesto, confere a cabeça da trilha, registra o pedido na trilha e só então assina. Pedido que não confere é
recusado, vai para a trilha e gera alerta no SIEM.

  ASSINADOR_DSN=postgresql://...  ASSINADOR_SEGREDO=<segredo compartilhado com o worker de pacotes> \\
  ASSINADOR_VAULT_TOKEN_FILE=chaves/vault/assinador.token  python -m auditor assinador [--porta 8319]

Sem Vault (modo local), assina com a chave Ed25519 de AUDITOR_CHAVE_ED25519, com as mesmas conferências, no próprio
processo (`assinar()` sem AUDITOR_ASSINADOR_URL). O worker de pacotes, no modo vault, chama o serviço por HTTP
(AUDITOR_ASSINADOR_URL + AUDITOR_ASSINADOR_SEGREDO); em produção, mTLS como o chaveiro.

Chave pública: `identidade()` devolve key_id, algoritmo e impressão digital (SHA-256 da chave pública bruta), que
vão no manifesto antes da assinatura. As chaves publicadas (atuais e antigas) ficam em chaves_publicas/chaves.json,
versionado no repositório e embutido no verificador.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
from datetime import datetime, timezone
from pathlib import Path

import httpx
from cryptography.hazmat.primitives import serialization
from starlette.requests import Request

from . import merkle, siem

CHAVE_TRANSIT = "kc-auditor-assinatura"
PUBLICADAS = Path(__file__).resolve().parent.parent / "chaves_publicas" / "chaves.json"


class Recusado(RuntimeError):
    pass


# ------------------------------------------------------------------ chave
def _vault() -> httpx.Client | None:
    tf = os.environ.get("ASSINADOR_VAULT_TOKEN_FILE")
    if not tf:
        return None
    return httpx.Client(base_url=os.environ.get("VAULT_ADDR", "http://127.0.0.1:8200"),
                        headers={"X-Vault-Token": Path(tf).read_text().strip()}, timeout=10, trust_env=False)


def _bruta_local() -> bytes:
    priv = serialization.load_pem_private_key(Path(os.environ["AUDITOR_CHAVE_ED25519"]).read_bytes(), None)
    return priv.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def identidade() -> dict:
    """key_id, algoritmo e impressão digital da chave que vai assinar."""
    v = _vault()
    if v:
        with v:
            r = v.get(f"/v1/transit/keys/{CHAVE_TRANSIT}")
            r.raise_for_status()
            d = r.json()["data"]
        ver = d["latest_version"]
        bruta = base64.b64decode(d["keys"][str(ver)]["public_key"])
        kid = f"vault:{CHAVE_TRANSIT}:v{ver}"
    else:
        bruta = _bruta_local()
        kid = "local:" + hashlib.sha256(bruta).hexdigest()[:16]
    return {"key_id": kid, "algoritmo": "Ed25519", "impressao_digital": hashlib.sha256(bruta).hexdigest(),
            "chave_publica": base64.b64encode(bruta).decode()}


def _assinar_bruto(corpo: bytes) -> bytes:
    v = _vault()
    if v:
        with v:
            r = v.post(f"/v1/transit/sign/{CHAVE_TRANSIT}", json={"input": base64.b64encode(corpo).decode()})
            r.raise_for_status()
            return base64.b64decode(r.json()["data"]["signature"].split(":", 2)[2])
    from .cripto import assinar
    return assinar(corpo)


# ------------------------------------------------------------------ conferência
def conferir(cx, corpo: bytes) -> dict:
    """Confere o manifesto contra a cadeia da investigação. Devolve o manifesto lido, ou levanta Recusado."""
    try:
        m = json.loads(corpo)
    except ValueError as e:
        raise Recusado("manifesto ilegível") from e
    if m.get("formato") != 2:
        raise Recusado("só manifestos de formato 2")
    inv = (m.get("investigacao") or {}).get("id")
    if not isinstance(inv, int):
        raise Recusado("manifesto sem investigação")
    selos = cx.execute("SELECT DISTINCT ON (tarefa_id) tarefa_id, conta_id, inicio_ms, raiz, n_eventos FROM selo "
                       "WHERE investigacao_id=%s ORDER BY tarefa_id, versao DESC", (inv,)).fetchall()
    selos.sort(key=lambda s: (s["conta_id"], s["inicio_ms"], s["tarefa_id"]))
    raiz = merkle.raiz([s["raiz"] for s in selos])
    cus = m.get("custodia") or {}
    erros = []
    if cus.get("raiz_merkle") != raiz:
        erros.append("raiz Merkle diferente da cadeia de selos")
    if cus.get("fatias_seladas") != len(selos):
        erros.append(f"número de fatias diferente ({cus.get('fatias_seladas')} × {len(selos)} seladas)")
    if cus.get("eventos_selados") != sum(s["n_eventos"] for s in selos):
        erros.append("contagem de eventos diferente dos selos")
    ch = ((m.get("trilha") or {}).get("cabeca")) or {}
    if ch:
        r = cx.execute("SELECT hash FROM trilha_auditoria WHERE cadeia=%s AND seq=%s", (inv, ch.get("seq"))).fetchone()
        if not r or r["hash"] != ch.get("hash"):
            erros.append("cabeça da trilha não confere")
    ident = identidade()
    ass = m.get("assinatura") or {}
    if ass.get("key_id") != ident["key_id"] or ass.get("impressao_digital") != ident["impressao_digital"]:
        erros.append("manifesto declara outra chave de assinatura")
    if erros:
        raise Recusado("; ".join(erros))
    return m


def assinar_conferido(cx, corpo: bytes, pedido_por: str = "pacotes") -> dict:
    from .db import trilha
    sha = hashlib.sha256(corpo).hexdigest()
    try:
        m = conferir(cx, corpo)
    except Recusado as e:
        inv = None
        try:
            inv = json.loads(corpo)["investigacao"]["id"]
        except Exception:  # noqa: BLE001
            pass
        trilha(cx, "assinador", "assinatura_recusada", inv if isinstance(inv, int) else None, sha256_manifesto=sha,
               pedido_por=pedido_por, razao=str(e)[:200])
        siem.enviar("assinatura_recusada", "alerta", investigacao=inv, sha256=sha)
        raise
    sig = _assinar_bruto(corpo)
    trilha(cx, "assinador", "assinar_manifesto", m["investigacao"]["id"], sha256_manifesto=sha,
           key_id=m["assinatura"]["key_id"], pedido_por=pedido_por)
    return {"assinatura": base64.b64encode(sig).decode(), "key_id": m["assinatura"]["key_id"], "sha256": sha}


# ------------------------------------------------------------------ cliente (worker de pacotes)
def _remoto() -> httpx.Client | None:
    url = os.environ.get("AUDITOR_ASSINADOR_URL")
    if not url:
        return None
    return httpx.Client(base_url=url, timeout=60, trust_env=False,
                        headers={"Authorization": f"Bearer {os.environ['AUDITOR_ASSINADOR_SEGREDO']}"})


def identidade_remota() -> dict:
    c = _remoto()
    if not c:
        return identidade()
    with c:
        r = c.get("/chave")
        r.raise_for_status()
        return r.json()


def assinar(corpo: bytes) -> bytes:
    """Assinatura Ed25519 do manifesto (bytes brutos), pelo serviço ou, no modo local, no próprio processo."""
    c = _remoto()
    if c:
        with c:
            r = c.post("/assinar", content=corpo, headers={"Content-Type": "application/json"})
            if r.status_code == 409:
                raise Recusado(r.json().get("mensagem", "recusado"))
            r.raise_for_status()
            return base64.b64decode(r.json()["assinatura"])
    from .db import conectar
    with conectar() as cx:
        return base64.b64decode(assinar_conferido(cx, corpo, "local")["assinatura"])


# ------------------------------------------------------------------ publicação das chaves
def publicar(destinos: list[Path]) -> dict:
    """Acrescenta a chave atual à lista publicada (idempotente). Revogação: `revogada_em` editado à mão, com data."""
    ident = identidade()
    for p in destinos:
        lista = json.loads(p.read_text()) if p.exists() else {"formato": 1, "chaves": []}
        if not any(k["key_id"] == ident["key_id"] and k["impressao_digital"] == ident["impressao_digital"]
                   for k in lista["chaves"]):
            uso = os.environ.get("ASSINADOR_USO") or ("desenvolvimento (modo local; não vale para produção)"
                                                      if ident["key_id"].startswith("local:") else "homologação")
            lista["chaves"].append({k: ident[k] for k in ("key_id", "algoritmo", "impressao_digital", "chave_publica")}
                                   | {"uso": uso, "publicada_em": datetime.now(timezone.utc).date().isoformat(),
                                      "revogada_em": None})
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(lista, ensure_ascii=False, indent=1) + "\n")
    return ident


# ------------------------------------------------------------------ serviço HTTP
def app():
    from fastapi import FastAPI
    from fastapi.responses import JSONResponse
    from starlette.concurrency import run_in_threadpool
    from psycopg.rows import dict_row
    from psycopg_pool import ConnectionPool

    segredo = os.environ["ASSINADOR_SEGREDO"].encode()
    pool = ConnectionPool(os.environ["ASSINADOR_DSN"], min_size=1, max_size=4,
                          kwargs={"autocommit": True, "row_factory": dict_row}, open=True)
    a = FastAPI(title="kc-auditor assinador", docs_url=None, redoc_url=None, openapi_url=None)

    def autorizado(req: Request) -> bool:
        tok = req.headers.get("authorization", "").removeprefix("Bearer ").encode()
        return hmac.compare_digest(tok, segredo)

    @a.get("/chave")
    def chave(req: Request):
        if not autorizado(req):
            return JSONResponse({"erro": "nao_autorizado"}, 401)
        return identidade()

    @a.post("/assinar")
    async def r_assinar(req: Request):
        if not autorizado(req):
            siem.enviar("assinador_nao_autorizado", "alerta")
            return JSONResponse({"erro": "nao_autorizado"}, 401)
        corpo = await req.body()
        if len(corpo) > 8 * 1024 * 1024:
            return JSONResponse({"erro": "grande", "mensagem": "manifesto acima de 8 MB"}, 413)
        def _assinar():
            with pool.connection() as cx:
                return assinar_conferido(cx, corpo)
        try:
            return await run_in_threadpool(_assinar)
        except Recusado as e:
            return JSONResponse({"erro": "recusado", "mensagem": str(e)}, 409)

    return a


def servir(porta: int = 8319):
    import uvicorn
    uvicorn.run(app(), host="127.0.0.1", port=porta, log_level="warning")

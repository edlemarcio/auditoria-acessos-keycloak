"""Chaves de uso do lado dos serviços (W0b, PROPOSTA_WEB §5.3).

Dois modos, escolhidos por AUDITOR_MODO:

  local  (padrão) chaves derivadas de AUDITOR_CHAVE; a DEK de cada investigação é gerada aqui e envolvida por uma
         KEK local. Para desenvolvimento e teste. Falha fechado: recusa rodar com AUDITOR_AMBIENTE=producao.
  vault  nada de chave no processo: DEKs, HMAC do alvo e segredos dos service accounts vêm do `chaveiro` por mTLS,
         que confere identidade, finalidade e estado da investigação (auditor/chaveiro.py). Sem chaveiro, falha;
         nunca recorre ao modo local.

  AUDITOR_CHAVEIRO     https://127.0.0.1:8443
  AUDITOR_IDENTIDADE   worker | pacotes | operador (certificado chaves/servicos/<identidade>.crt)
  AUDITOR_CERTS        diretório dos certificados (padrão chaves/servicos)

DEK desembrulhada fica em memória no máximo 5 min (TTL), nunca em disco nem em log.
"""
from __future__ import annotations

import base64
import os
import threading
import time
from pathlib import Path

from . import cripto, siem

TTL_DEK_S = 300
CLASSES = ("principal", "terceiros")


class Recusado(PermissionError):
    """O chaveiro recusou a entrega (finalidade ou estado da investigação não permitem)."""


class ChaveiroIndisponivel(RuntimeError):
    pass


def modo() -> str:
    m = os.environ.get("AUDITOR_MODO", "local")
    if m not in ("local", "vault"):
        raise RuntimeError(f"AUDITOR_MODO inválido: {m}")
    if m == "local" and os.environ.get("AUDITOR_AMBIENTE") == "producao":
        siem.enviar("modo_local_em_producao", "alerta")
        raise RuntimeError("Modo local recusado em produção (AUDITOR_AMBIENTE=producao): use AUDITOR_MODO=vault")
    return m


# ------------------------------------------------------------------ cliente do chaveiro (mTLS)
_cli = None
_cli_lock = threading.Lock()


def identidade() -> str:
    return os.environ.get("AUDITOR_IDENTIDADE", "operador")


def _chaveiro():
    global _cli
    with _cli_lock:
        if _cli is None:
            import ssl

            import httpx
            d = Path(os.environ.get("AUDITOR_CERTS", "chaves/servicos"))
            ident = identidade()
            ctx = ssl.create_default_context(cafile=str(d / "ca.crt"))   # só a AC dos serviços
            ctx.minimum_version = ssl.TLSVersion.TLSv1_3
            ctx.load_cert_chain(str(d / f"{ident}.crt"), str(d / f"{ident}.key"))
            _cli = httpx.Client(base_url=os.environ.get("AUDITOR_CHAVEIRO", "https://127.0.0.1:8443"), verify=ctx,
                                timeout=15, trust_env=False)
        return _cli


def pedir(caminho: str, **corpo) -> dict:
    import httpx
    try:
        r = _chaveiro().post(caminho, json=corpo)
    except httpx.TransportError as e:
        raise ChaveiroIndisponivel(f"chaveiro indisponível: {type(e).__name__}") from e
    if r.status_code == 403:
        raise Recusado(r.json().get("motivo", "recusado"))
    if r.status_code != 200:
        raise ChaveiroIndisponivel(f"chaveiro: HTTP {r.status_code} {r.text[:200]}")
    return r.json()


# ------------------------------------------------------------------ DEKs
_cache: dict[tuple, tuple[bytes, float]] = {}
_cache_lock = threading.Lock()


def criar_deks(cx, inv_id: int) -> bytes:
    """Gera e guarda (envolvidas) a DEK principal e a de terceiros de uma investigação em 'abrindo'.
    Devolve a principal."""
    if modo() == "vault":
        r = pedir("/v1/dek/criar", investigacao=inv_id)
        dek = base64.b64decode(r["dek"])
    else:
        deks = {c: os.urandom(32) for c in CLASSES}
        for c, k in deks.items():
            cx.execute("INSERT INTO chave_investigacao (investigacao_id, classe, envelope, key_id) "
                       "VALUES (%s,%s,%s,'local')", (inv_id, c, cripto.envolver_local(k, inv_id, c)))
        dek = deks["principal"]
    with _cache_lock:
        _cache[(inv_id, "principal", "abrir")] = (dek, time.monotonic() + TTL_DEK_S)
    return dek


def dek(inv_id: int, finalidade: str, classe: str = "principal") -> bytes:
    k = (inv_id, classe, finalidade)
    agora = time.monotonic()
    with _cache_lock:
        v = _cache.get(k)
        if v and v[1] > agora:
            return v[0]
    if modo() == "vault":
        d = base64.b64decode(pedir("/v1/dek", investigacao=inv_id, finalidade=finalidade, classe=classe)["dek"])
    else:
        from .db import conectar
        with conectar() as cx:
            r = cx.execute("SELECT envelope FROM chave_investigacao WHERE investigacao_id=%s AND classe=%s "
                           "AND destruida_em IS NULL", (inv_id, classe)).fetchone()
        if not r:
            raise Recusado(f"investigação {inv_id} sem DEK '{classe}' (expurgada ou anterior à W0b)")
        d = cripto.desenvolver_local(r["envelope"], inv_id, classe)
    with _cache_lock:
        _cache[k] = (d, agora + TTL_DEK_S)
    return d


def esquecer(inv_id: int | None = None):
    with _cache_lock:
        for k in [k for k in _cache if inv_id is None or k[0] == inv_id]:
            del _cache[k]


# ------------------------------------------------------------------ alvo
def hmac_alvo(tipo: str, digitos: str) -> str:
    if modo() == "vault":
        return pedir("/v1/hmac/alvo", tipo=tipo, digitos=digitos)["hmac"]
    return cripto.hmac_alvo(tipo, digitos)


def cifrar_alvo(inv_id: int, dek_: bytes, digitos: str) -> bytes:
    return cripto.cifrar_dek(dek_, digitos, cripto.aad(inv_id, "investigacao", "alvo_cifrado", inv_id))


def alvo(inv: dict, finalidade: str) -> str:
    """Identificador do alvo em claro. v3 (DEK); v1/v2 (chave mestra) só nas investigações ainda não migradas."""
    blob = bytes(inv["alvo_cifrado"])
    if blob[:1] == cripto.V3:
        return cripto.decifrar_dek(dek(inv["id"], finalidade), blob,
                                   cripto.aad(inv["id"], "investigacao", "alvo_cifrado", inv["id"])).decode()
    if modo() == "vault":
        raise Recusado(f"investigação {inv['id']} anterior à W0b: migre no modo local (python -m auditor init)")
    return cripto.decifrar(blob, cripto.ctx_alvo(inv["alvo_hmac"]))


# ------------------------------------------------------------------ segredos dos service accounts
def cifrar_segredo(nome_instancia: str, segredo: str) -> bytes:
    if modo() == "vault":
        return pedir("/v1/segredo/cifrar", instancia=nome_instancia, segredo=segredo)["cifrado"].encode()
    return cripto.cifrar(segredo, cripto.ctx_segredo(nome_instancia))


def segredo(inst: dict, finalidade: str) -> str:
    blob = bytes(inst["segredo_cifrado"])
    if blob.startswith(b"vault:"):
        if modo() != "vault":
            raise RuntimeError(f"segredo da instância {inst['nome']} cifrado pelo Vault: use AUDITOR_MODO=vault")
        # o chaveiro lê o cifrado no banco: não decifra o que o cliente mandar
        return pedir("/v1/segredo", instancia_id=inst["id"], finalidade=finalidade)["segredo"]
    if modo() == "vault":
        raise Recusado(f"segredo da instância {inst['nome']} no formato local: recadastre-a no modo vault")
    return cripto.decifrar(blob, cripto.ctx_segredo(inst["nome"]))


# ------------------------------------------------------------------ migração das investigações anteriores à W0b
def migrar_deks(cx) -> int:
    """Modo local: cria as DEKs das investigações antigas e recifra o alvo com a DEK (v2 → v3). Idempotente."""
    if modo() != "local":
        return 0
    n = 0
    for inv in cx.execute("SELECT i.* FROM investigacao i WHERE NOT EXISTS (SELECT 1 FROM chave_investigacao k "
                          "WHERE k.investigacao_id=i.id) AND i.status <> 'abrindo' ORDER BY id").fetchall():
        with cx.transaction():
            dig = cripto.decifrar(bytes(inv["alvo_cifrado"]), cripto.ctx_alvo(inv["alvo_hmac"]))
            d = criar_deks(cx, inv["id"])
            cx.execute("UPDATE investigacao SET alvo_cifrado=%s WHERE id=%s",
                       (cifrar_alvo(inv["id"], d, dig), inv["id"]))
        n += 1
    return n

"""OIDC do realm dedicado ao auditor (W1): descoberta, JWKS, validação de token, código + PKCE e device flow.

Validação feita aqui, só com `cryptography` (RS256/PS256/ES256): assinatura pela chave do JWKS, emissor, audiência,
validade, `azp` entre os clientes do auditor e `acr` = "mfa" (MFA obrigatório).

  AUDITOR_OIDC_EMISSOR   http://localhost:8090/realms/auditor
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import secrets
import threading
import time

import httpx
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

CLIENTES = ("kc-auditor-bff", "kc-auditor-cli")
ACR_MFA = "mfa"
STEP_UP_S = 300


class TokenInvalido(Exception):
    pass


def emissor() -> str:
    e = os.environ.get("AUDITOR_OIDC_EMISSOR")
    if not e:
        raise RuntimeError("Defina AUDITOR_OIDC_EMISSOR (realm dedicado do auditor)")
    return e.rstrip("/")


def _b64d(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


_cache: dict = {}
_lock = threading.Lock()


def descoberta() -> dict:
    with _lock:
        d = _cache.get("disc")
        if not d:
            d = _cache["disc"] = httpx.get(f"{emissor()}/.well-known/openid-configuration", timeout=10,
                                           trust_env=False).json()
        return d


def _chaves(forcar=False) -> dict:
    with _lock:
        if forcar or "jwks" not in _cache or time.monotonic() - _cache["jwks_t"] > 3600:
            u = _cache.get("disc", {}).get("jwks_uri") or f"{emissor()}/protocol/openid-connect/certs"
            _cache["jwks"] = {k["kid"]: k for k in httpx.get(u, timeout=10, trust_env=False).json()["keys"]}
            _cache["jwks_t"] = time.monotonic()
        return _cache["jwks"]


def _verificar_assinatura(alg: str, jwk: dict, dados: bytes, sig: bytes):
    if jwk["kty"] == "RSA":
        n, e = (int.from_bytes(_b64d(jwk[x]), "big") for x in ("n", "e"))
        pub = rsa.RSAPublicNumbers(e, n).public_key()
        pad = padding.PKCS1v15() if alg == "RS256" else padding.PSS(padding.MGF1(hashes.SHA256()), 32)
        if alg not in ("RS256", "PS256"):
            raise TokenInvalido(f"algoritmo {alg} não aceito")
        pub.verify(sig, dados, pad, hashes.SHA256())
    elif jwk["kty"] == "EC" and alg == "ES256":
        x, y = (int.from_bytes(_b64d(jwk[c]), "big") for c in ("x", "y"))
        pub = ec.EllipticCurvePublicNumbers(x, y, ec.SECP256R1()).public_key()
        pub.verify(encode_dss_signature(int.from_bytes(sig[:32], "big"), int.from_bytes(sig[32:], "big")), dados,
                   ec.ECDSA(hashes.SHA256()))
    else:
        raise TokenInvalido(f"algoritmo {alg} não aceito")


def validar(token: str, audiencia: str = "kc-auditor-api", exigir_mfa: bool = True) -> dict:
    """Devolve as claims de um access token válido; senão, TokenInvalido."""
    try:
        h64, p64, s64 = token.split(".")
        cab, claims = json.loads(_b64d(h64)), json.loads(_b64d(p64))
    except Exception as e:  # noqa: BLE001
        raise TokenInvalido("token malformado") from e
    if cab.get("alg") in (None, "none") or "kid" not in cab:
        raise TokenInvalido("token sem assinatura")
    jwk = _chaves().get(cab["kid"]) or _chaves(forcar=True).get(cab["kid"])
    if not jwk:
        raise TokenInvalido("chave do token desconhecida")
    try:
        _verificar_assinatura(cab["alg"], jwk, f"{h64}.{p64}".encode(), _b64d(s64))
    except TokenInvalido:
        raise
    except Exception as e:  # noqa: BLE001
        raise TokenInvalido("assinatura inválida") from e
    agora = time.time()
    if claims.get("iss") != emissor():
        raise TokenInvalido("emissor inválido")
    aud = claims.get("aud") or []
    if audiencia not in (aud if isinstance(aud, list) else [aud]):
        raise TokenInvalido("audiência inválida")
    if claims.get("exp", 0) < agora - 30 or claims.get("nbf", 0) > agora + 30:
        raise TokenInvalido("token expirado")
    if claims.get("azp") not in CLIENTES:
        raise TokenInvalido("cliente não autorizado")
    if claims.get("typ", "Bearer") not in ("Bearer", "ID"):
        raise TokenInvalido("tipo de token inválido")
    if exigir_mfa and claims.get("acr") != ACR_MFA:
        raise TokenInvalido("autenticação sem MFA")
    return claims


def papeis(claims: dict) -> set[str]:
    return set((claims.get("realm_access") or {}).get("roles") or [])


# ------------------------------------------------------------------ código + PKCE (BFF)
def pkce() -> tuple[str, str]:
    v = secrets.token_urlsafe(48)
    return v, base64.urlsafe_b64encode(hashlib.sha256(v.encode()).digest()).rstrip(b"=").decode()


def url_autorizacao(cliente: str, retorno: str, estado: str, nonce: str, desafio: str, step_up: bool = False) -> str:
    from urllib.parse import urlencode
    p = {"client_id": cliente, "response_type": "code", "scope": "openid", "redirect_uri": retorno, "state": estado,
         "nonce": nonce, "code_challenge": desafio, "code_challenge_method": "S256", "acr_values": ACR_MFA}
    if step_up:
        p["max_age"] = str(STEP_UP_S)   # autenticação recente: o OTP é pedido de novo se passou do prazo
    return f"{descoberta()['authorization_endpoint']}?{urlencode(p)}"


def trocar_codigo(cliente: str, segredo: str, codigo: str, retorno: str, verificador: str) -> dict:
    r = httpx.post(descoberta()["token_endpoint"], timeout=15, trust_env=False,
                   data={"grant_type": "authorization_code", "code": codigo, "redirect_uri": retorno,
                         "client_id": cliente, "client_secret": segredo, "code_verifier": verificador})
    if r.status_code != 200:
        raise TokenInvalido(f"troca do código recusada: HTTP {r.status_code}")
    return r.json()


def renovar(cliente: str, segredo: str | None, refresh: str) -> dict:
    d = {"grant_type": "refresh_token", "refresh_token": refresh, "client_id": cliente}
    if segredo:
        d["client_secret"] = segredo
    r = httpx.post(descoberta()["token_endpoint"], data=d, timeout=15, trust_env=False)
    if r.status_code != 200:
        raise TokenInvalido(f"renovação recusada: HTTP {r.status_code}")
    return r.json()


# ------------------------------------------------------------------ device flow (CLI de produção)
def iniciar_dispositivo(cliente: str = "kc-auditor-cli") -> dict:
    """Pede o código do dispositivo (com PKCE). O verificador fica no dicionário devolvido, só em memória."""
    v, desafio = pkce()
    r = httpx.post(descoberta()["device_authorization_endpoint"], timeout=15, trust_env=False,
                   data={"client_id": cliente, "scope": "openid", "acr_values": ACR_MFA, "code_challenge": desafio,
                         "code_challenge_method": "S256"})
    if r.status_code != 200:
        raise TokenInvalido(f"device flow recusado: {r.text[:200]}")
    return {**r.json(), "_verificador": v}


def aguardar_dispositivo(d: dict, cliente: str = "kc-auditor-cli", limite_s: float = 300) -> dict:
    fim, intervalo = time.monotonic() + min(limite_s, d.get("expires_in", 300)), d.get("interval", 5)
    while time.monotonic() < fim:
        r = httpx.post(descoberta()["token_endpoint"], timeout=15, trust_env=False,
                       data={"grant_type": "urn:ietf:params:oauth:grant-type:device_code",
                             "device_code": d["device_code"], "client_id": cliente,
                             "code_verifier": d["_verificador"]})
        if r.status_code == 200:
            return r.json()
        erro = r.json().get("error")
        if erro == "slow_down":
            intervalo += 5
        elif erro != "authorization_pending":
            raise TokenInvalido(f"login do dispositivo recusado: {erro}")
        time.sleep(intervalo)
    raise TokenInvalido("código do dispositivo expirou")

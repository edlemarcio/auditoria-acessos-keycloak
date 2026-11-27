"""Segredos (AES-GCM), HMAC do identificador e assinatura Ed25519 do manifesto.

Chaves fora do banco:
  AUDITOR_CHAVE        32 bytes em base64 (AES-GCM e HMAC)
  AUDITOR_CHAVE_ED25519 caminho do arquivo PEM da chave privada de assinatura
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import os
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def _chave() -> bytes:
    k = os.environ.get("AUDITOR_CHAVE")
    if not k:
        raise RuntimeError("Defina AUDITOR_CHAVE (32 bytes em base64). Gere com: python -m auditor chave")
    b = base64.b64decode(k)
    if len(b) != 32:
        raise RuntimeError("AUDITOR_CHAVE deve ter 32 bytes")
    return b


def cifrar(texto: str) -> bytes:
    nonce = os.urandom(12)
    return nonce + AESGCM(_chave()).encrypt(nonce, texto.encode(), b"kc-auditor")


def decifrar(blob: bytes) -> str:
    blob = bytes(blob)
    return AESGCM(_chave()).decrypt(blob[:12], blob[12:], b"kc-auditor").decode()


def hmac_alvo(tipo: str, digitos: str) -> str:
    return hmac.new(_chave(), f"{tipo}:{digitos}".encode(), hashlib.sha256).hexdigest()


def gerar_chaves(destino: Path) -> tuple[str, Path]:
    destino.mkdir(parents=True, exist_ok=True)
    priv = Ed25519PrivateKey.generate()
    (destino / "assinatura.pem").write_bytes(priv.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    (destino / "assinatura.pub.pem").write_bytes(priv.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
    os.chmod(destino / "assinatura.pem", 0o600)
    return base64.b64encode(os.urandom(32)).decode(), destino


def assinar(dados: bytes) -> bytes:
    caminho = os.environ.get("AUDITOR_CHAVE_ED25519")
    if not caminho:
        raise RuntimeError("Defina AUDITOR_CHAVE_ED25519 com o caminho da chave privada")
    priv = serialization.load_pem_private_key(Path(caminho).read_bytes(), password=None)
    return priv.sign(dados)


def verificar(dados: bytes, assinatura: bytes, chave_publica_pem: bytes) -> bool:
    pub = serialization.load_pem_public_key(chave_publica_pem)
    assert isinstance(pub, Ed25519PublicKey)
    try:
        pub.verify(assinatura, dados)
        return True
    except Exception:  # noqa: BLE001
        return False

"""Segredos (AES-GCM), HMAC do identificador e assinatura Ed25519 do manifesto.

Chaves fora do banco:
  AUDITOR_CHAVE        32 bytes em base64: chave mestra, da qual se derivam (HKDF-SHA-256) uma chave por finalidade
  AUDITOR_CHAVE_ED25519 caminho do arquivo PEM da chave privada de assinatura

Formato v2 (atual): b"\\x02" + nonce(12) + cifrado, com chave AES derivada e AAD que amarra o cifrado à tabela,
à coluna e à linha (contexto). Formato v1 (até a 0.1.x): nonce(12) + cifrado, com a chave mestra direta e AAD fixo;
continua legível e é convertido por `migrar_chaves()`.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import os
from functools import lru_cache
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

V2 = b"\x02"
AAD_V1 = b"kc-auditor"
FINALIDADE_AES = b"kc-auditor/aes-gcm/v2"
FINALIDADE_HMAC_ALVO = b"kc-auditor/hmac-alvo/v2"


def _mestra() -> bytes:
    k = os.environ.get("AUDITOR_CHAVE")
    if not k:
        raise RuntimeError("Defina AUDITOR_CHAVE (32 bytes em base64). Gere com: python -m auditor chave")
    b = base64.b64decode(k)
    if len(b) != 32:
        raise RuntimeError("AUDITOR_CHAVE deve ter 32 bytes")
    return b


@lru_cache(maxsize=8)
def _derivada(mestra: bytes, finalidade: bytes) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=finalidade).derive(mestra)


def _chave(finalidade: bytes) -> bytes:
    return _derivada(_mestra(), finalidade)


# --- contextos (AAD): amarram o cifrado à linha; trocar células entre linhas faz a decifração falhar
def ctx_alvo(alvo_hmac: str) -> str:
    return f"investigacao.alvo_cifrado|{alvo_hmac}"


def ctx_segredo(nome_instancia: str) -> str:
    return f"instancia.segredo_cifrado|{nome_instancia}"


def cifrar(texto: str, contexto: str) -> bytes:
    nonce = os.urandom(12)
    return V2 + nonce + AESGCM(_chave(FINALIDADE_AES)).encrypt(nonce, texto.encode(), b"kc-auditor/v2|" +
                                                                 contexto.encode())


def _decifrar_v2(blob: bytes, contexto: str) -> str:
    return AESGCM(_chave(FINALIDADE_AES)).decrypt(blob[1:13], blob[13:], b"kc-auditor/v2|" +
                                                   contexto.encode()).decode()


def _decifrar_v1(blob: bytes) -> str:
    return AESGCM(_mestra()).decrypt(blob[:12], blob[12:], AAD_V1).decode()


def versao(blob: bytes, contexto: str) -> int:
    """2 se o blob está no formato atual com este contexto, 1 se está no formato antigo."""
    blob = bytes(blob)
    if blob[:1] == V2:
        try:
            _decifrar_v2(blob, contexto)
            return 2
        except InvalidTag:
            pass   # um blob v1 pode começar com 0x02 por acaso (nonce aleatório)
    _decifrar_v1(blob)
    return 1


def decifrar(blob: bytes, contexto: str) -> str:
    blob = bytes(blob)
    if blob[:1] == V2:
        try:
            return _decifrar_v2(blob, contexto)
        except InvalidTag:
            pass
    return _decifrar_v1(blob)


def hmac_alvo(tipo: str, digitos: str) -> str:
    return hmac.new(_chave(FINALIDADE_HMAC_ALVO), f"{tipo}:{digitos}".encode(), hashlib.sha256).hexdigest()


def hmac_alvo_v1(tipo: str, digitos: str) -> str:
    """HMAC da 0.1.x (chave mestra direta), usado só na migração."""
    return hmac.new(_mestra(), f"{tipo}:{digitos}".encode(), hashlib.sha256).hexdigest()


def migrar_chaves(cx) -> dict:
    """Converte segredos e alvos do formato v1 para o v2 e recalcula o HMAC do alvo (idempotente)."""
    feitos = {"instancias": 0, "investigacoes": 0, "historico": 0}
    with cx.transaction():
        for i in cx.execute("SELECT id, nome, segredo_cifrado FROM instancia FOR UPDATE").fetchall():
            ctx = ctx_segredo(i["nome"])
            if versao(i["segredo_cifrado"], ctx) == 1:
                cx.execute("UPDATE instancia SET segredo_cifrado=%s WHERE id=%s",
                           (cifrar(_decifrar_v1(bytes(i["segredo_cifrado"])), ctx), i["id"]))
                feitos["instancias"] += 1
        for inv in cx.execute("SELECT id, tipo, alvo_cifrado, alvo_hmac FROM investigacao FOR UPDATE").fetchall():
            if versao(inv["alvo_cifrado"], ctx_alvo(inv["alvo_hmac"])) == 2:
                continue
            dig = _decifrar_v1(bytes(inv["alvo_cifrado"]))
            antigo, novo = inv["alvo_hmac"], hmac_alvo(inv["tipo"], dig)
            if antigo != novo:
                n = cx.execute(
                    "INSERT INTO historico_identidade (alvo_hmac, instancia_id, realm, user_id, username, visto_em) "
                    "SELECT %s, instancia_id, realm, user_id, username, visto_em FROM historico_identidade "
                    "WHERE alvo_hmac=%s ON CONFLICT DO NOTHING", (novo, antigo)).rowcount
                cx.execute("DELETE FROM historico_identidade WHERE alvo_hmac=%s", (antigo,))
                feitos["historico"] += n
            cx.execute("UPDATE investigacao SET alvo_hmac=%s, alvo_cifrado=%s WHERE id=%s",
                       (novo, cifrar(dig, ctx_alvo(novo)), inv["id"]))
            feitos["investigacoes"] += 1
    return feitos


# ------------------------------------------------------------------ formato v3: DEK por investigação (W0b)
# b"\x03" + nonce(12) + cifrado, AES-256-GCM com a DEK da investigação. AAD = investigação | tabela | coluna |
# chave da linha | classe da DEK (§5.3): trocar uma célula de linha, de coluna ou de investigação faz a decifração
# falhar.
V3 = b"\x03"
FINALIDADE_KEK_LOCAL = b"kc-auditor/kek-local/v1"
LOCAL_V1 = b"local:v1:"


def aad(inv_id: int, tabela: str, coluna: str, linha, classe: str = "principal") -> bytes:
    return f"kc-auditor/v3|{inv_id}|{tabela}|{coluna}|{linha}|{classe}".encode()


def cifrar_dek(dek: bytes, dados: bytes | str, aad_: bytes) -> bytes:
    if isinstance(dados, str):
        dados = dados.encode()
    nonce = os.urandom(12)
    return V3 + nonce + AESGCM(dek).encrypt(nonce, dados, aad_)


def decifrar_dek(dek: bytes, blob: bytes, aad_: bytes) -> bytes:
    blob = bytes(blob)
    if blob[:1] != V3:
        raise ValueError("cifrado fora do formato v3")
    return AESGCM(dek).decrypt(blob[1:13], blob[13:], aad_)


def chave_pseudo(dek: bytes, inv_id: int, classe: str) -> bytes:
    """K_pseudo da investigação por classe de pseudônimo (§5.3): morre com a DEK."""
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=str(inv_id).encode(),
                info=f"kc-auditor/pseudo/v1/{classe}".encode()).derive(dek)


def envolver_local(dek: bytes, inv_id: int, classe: str) -> bytes:
    """Modo local: a DEK é envolvida por uma KEK derivada de AUDITOR_CHAVE (no modo vault, pelo Transit)."""
    nonce = os.urandom(12)
    return LOCAL_V1 + nonce + AESGCM(_chave(FINALIDADE_KEK_LOCAL)).encrypt(
        nonce, dek, f"kc-auditor/kek|{inv_id}|{classe}".encode())


def desenvolver_local(envelope: bytes, inv_id: int, classe: str) -> bytes:
    e = bytes(envelope)
    if not e.startswith(LOCAL_V1):
        raise RuntimeError("DEK envolvida pelo Vault: use AUDITOR_MODO=vault (o modo local não abre envelopes do "
                           "Vault)")
    e = e[len(LOCAL_V1):]
    return AESGCM(_chave(FINALIDADE_KEK_LOCAL)).decrypt(e[:12], e[12:], f"kc-auditor/kek|{inv_id}|{classe}".encode())


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

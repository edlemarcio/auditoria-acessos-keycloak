"""Compromissos com sal e árvore Merkle (W0b, PROPOSTA_WEB §6.1 e §6.4).

  folha    = SHA-256(0x00 ‖ sal ‖ RFC 8785(evento como recebido)), sal aleatório de 256 bits por evento
  nó       = SHA-256(0x01 ‖ esquerda ‖ direita)
  ímpar    = o último nó de um nível sobe sem ser duplicado (sem o ataque de duplicação do Bitcoin)
  vazia    = SHA-256("") (RFC 6962)

"Como recebido": no Keycloak <= 21, sem o id sintético que o auditor acrescenta (kc.py). Sem o sal, a folha não
serve de oráculo: testar os 2³² IPv4 ou os CPFs válidos contra ela não confirma nada.
"""
from __future__ import annotations

import hashlib
import json

import rfc8785


def como_recebido(e: dict) -> dict:
    return {k: v for k, v in e.items() if k != "id_g" and not (k == "id" and str(v).startswith("sha256:"))}


def _simples(o) -> bool:
    """Sem float e sem chave fora do BMP: aí json.dumps ordenado é byte a byte o RFC 8785."""
    if isinstance(o, dict):
        return all(isinstance(k, str) and max(map(ord, k), default=0) < 0x10000 and _simples(v) for k, v in o.items())
    if isinstance(o, list):
        return all(_simples(v) for v in o)
    return not isinstance(o, float)


def jcs(o) -> bytes:
    """RFC 8785 (JCS). Caminho rápido pelo json da biblioteca padrão quando o resultado é idêntico."""
    if _simples(o):
        return json.dumps(o, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
                          allow_nan=False).encode("utf-8")
    return rfc8785.dumps(o)


def canonico(e: dict) -> bytes:
    return jcs(como_recebido(e))


def folha(sal: bytes, canon: bytes) -> str:
    return hashlib.sha256(b"\x00" + sal + canon).hexdigest()


def raiz(folhas: list[str]) -> str:
    """Raiz sobre as folhas na ordem dada (o chamador ordena)."""
    if not folhas:
        return hashlib.sha256(b"").hexdigest()
    nivel = [bytes.fromhex(f) for f in folhas]
    while len(nivel) > 1:
        prox = [hashlib.sha256(b"\x01" + nivel[i] + nivel[i + 1]).digest() for i in range(0, len(nivel) - 1, 2)]
        if len(nivel) % 2:
            prox.append(nivel[-1])
        nivel = prox
    return nivel[0].hex()

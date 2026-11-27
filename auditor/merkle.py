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

import rfc8785


def como_recebido(e: dict) -> dict:
    return {k: v for k, v in e.items() if k != "id_g" and not (k == "id" and str(v).startswith("sha256:"))}


def canonico(e: dict) -> bytes:
    return rfc8785.dumps(como_recebido(e))


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

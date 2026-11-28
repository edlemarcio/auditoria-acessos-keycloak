"""Hashes e árvore Merkle do pacote v2 (FORMATO_PACOTE.md §4), reimplementados sem depender do auditor.

  folha     = SHA-256(0x00 ‖ sal ‖ JCS(evento como recebido))
  nó        = SHA-256(0x01 ‖ esquerda ‖ direita)
  ímpar     = o último nó de um nível sobe sem ser duplicado
  vazia     = SHA-256("")
  prova     = [["e"|"d", irmão], ...] da folha até a raiz ("e": o irmão fica à esquerda)
"""
from __future__ import annotations

import hashlib

import rfc8785


def jcs(o) -> bytes:
    return rfc8785.dumps(o)


def como_recebido(e: dict) -> dict:
    """Sem os campos que o auditor acrescenta: `id_g` e, no Keycloak ≤ 21, o id sintético `sha256:…`."""
    return {k: v for k, v in e.items() if k != "id_g" and not (k == "id" and str(v).startswith("sha256:"))}


def folha(sal: bytes, evento: dict) -> str:
    return hashlib.sha256(b"\x00" + sal + jcs(como_recebido(evento))).hexdigest()


def compromisso(sal: bytes, valor) -> str:
    return hashlib.sha256(b"\x00" + sal + jcs(valor)).hexdigest()


def _no(e: bytes, d: bytes) -> bytes:
    return hashlib.sha256(b"\x01" + e + d).digest()


def raiz(folhas: list[str]) -> str:
    if not folhas:
        return hashlib.sha256(b"").hexdigest()
    nivel = [bytes.fromhex(f) for f in folhas]
    while len(nivel) > 1:
        prox = [_no(nivel[i], nivel[i + 1]) for i in range(0, len(nivel) - 1, 2)]
        if len(nivel) % 2:
            prox.append(nivel[-1])
        nivel = prox
    return nivel[0].hex()


def prova(folhas: list[str], i: int) -> list[list[str]]:
    nivel, caminho = [bytes.fromhex(f) for f in folhas], []
    while len(nivel) > 1:
        if i % 2:
            caminho.append(["e", nivel[i - 1].hex()])
        elif i + 1 < len(nivel):
            caminho.append(["d", nivel[i + 1].hex()])
        prox = [_no(nivel[j], nivel[j + 1]) for j in range(0, len(nivel) - 1, 2)]
        if len(nivel) % 2:
            prox.append(nivel[-1])
        nivel, i = prox, i // 2
    return caminho


def subir(folha_hex: str, caminho: list[list[str]]) -> str:
    h = bytes.fromhex(folha_hex)
    for lado, irmao in caminho:
        h = _no(bytes.fromhex(irmao), h) if lado == "e" else _no(h, bytes.fromhex(irmao))
    return h.hex()


def folha_cabeca(c: dict) -> str:
    """Folha da âncora diária: a cabeça de uma cadeia da trilha."""
    return hashlib.sha256(b"\x00" + jcs({"cadeia": c["cadeia"], "seq": c["seq"], "hash": c["hash"]})).hexdigest()


def genese(cadeia: int) -> str:
    return hashlib.sha256(f"kc-auditor/trilha/v1|{cadeia}".encode()).hexdigest()

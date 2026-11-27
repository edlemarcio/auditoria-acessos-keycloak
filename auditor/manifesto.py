"""Manifesto de evidência: JSON canônico (RFC 8785), hashes SHA-256 e assinatura Ed25519."""
from __future__ import annotations

import hashlib
import json
import zipfile
from pathlib import Path

import rfc8785

from .cripto import assinar, verificar


def canonico(obj) -> bytes:
    return rfc8785.dumps(obj)


def linhas_eventos(eventos_brutos: list[dict]) -> bytes:
    """Um evento por linha em JSON canônico, ordenado por (instância, realm, id)."""
    ordenados = sorted(eventos_brutos, key=lambda e: (e["_instancia"], e["_realm"], e["id"]))
    return b"".join(canonico(e) + b"\n" for e in ordenados)


def sha256(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def assinar_manifesto(manifesto: dict) -> tuple[bytes, bytes]:
    corpo = canonico(manifesto)
    return corpo, assinar(corpo)


def verificar_pacote(zip_path: Path, chave_publica_pem: bytes) -> tuple[bool, list[str]]:
    msgs, ok = [], True
    with zipfile.ZipFile(zip_path) as z:
        corpo = z.read("manifesto.json")
        sig = z.read("manifesto.sig")
        if verificar(corpo, sig, chave_publica_pem):
            msgs.append("[ok] assinatura do manifesto confere")
        else:
            return False, ["[FALHA] assinatura do manifesto não confere"]
        m = json.loads(corpo)
        for nome, h in m["arquivos"].items():
            if nome not in z.namelist():
                msgs.append(f"[--] {nome}: não incluído neste pacote (hash registrado: {h[:16]}…)")
                continue
            hh = sha256(z.read(nome))
            if hh == h:
                msgs.append(f"[ok] {nome}")
            else:
                ok = False
                msgs.append(f"[FALHA] {nome}: hash diferente")
        if "eventos.jsonl" in z.namelist():
            dados = z.read("eventos.jsonl")
            refeito = linhas_eventos([json.loads(x) for x in dados.splitlines() if x])
            if sha256(refeito) == m["eventos"]["sha256"] and refeito == dados:
                msgs.append(f"[ok] conjunto de {m['eventos']['total']} eventos reproduz o hash")
            else:
                ok = False
                msgs.append("[FALHA] conjunto de eventos não reproduz o hash")
    return ok, msgs

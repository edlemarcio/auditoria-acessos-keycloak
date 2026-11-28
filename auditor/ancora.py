"""Âncora diária verificável por terceiro (W0b, PROPOSTA_WEB §6.3).

Uma vez por dia, as cabeças de todas as cadeias da trilha (a última entrada de cada cadeia até o fim do dia, UTC)
entram numa árvore Merkle, e a raiz recebe carimbo do tempo. O pacote leva, para cada dia, a prova de inclusão da
cabeça da cadeia da investigação. Assim um terceiro prova que a cadeia (e os selos de fatia que ela contém) existia
naquela data, sem ver as cadeias de outras investigações.

  folha da cabeça = SHA-256(0x00 ‖ RFC 8785({"cadeia", "seq", "hash"})); nós como em merkle.py

Carimbo: RFC 3161 pela ACT de AUDITOR_TSA_URL (carimbo.py). Sem ela, um carimbo **simulado**, assinado com Ed25519 por uma chave
local (AUDITOR_ACT_SIMULADA, padrão chaves/act_simulada.pem, gerada no primeiro uso) e marcado como tal.
"""
from __future__ import annotations

import base64
import hashlib
import os
from datetime import date, datetime, time, timedelta, timezone
from pathlib import Path

import rfc8785
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from psycopg.types.json import Jsonb

from . import merkle
from .db import trilha


def folha_cabeca(c: dict) -> str:
    return hashlib.sha256(b"\x00" + rfc8785.dumps({"cadeia": c["cadeia"], "seq": c["seq"], "hash": c["hash"]})).hexdigest()


def prova(folhas: list[str], i: int) -> list[list[str]]:
    """Caminho de auditoria da folha i: [["e"|"d", hash irmão], ...] (nível promovido não entra)."""
    nivel, caminho = [bytes.fromhex(f) for f in folhas], []
    while len(nivel) > 1:
        if i % 2:
            caminho.append(["e", nivel[i - 1].hex()])
        elif i + 1 < len(nivel):
            caminho.append(["d", nivel[i + 1].hex()])
        prox = [hashlib.sha256(b"\x01" + nivel[j] + nivel[j + 1]).digest() for j in range(0, len(nivel) - 1, 2)]
        if len(nivel) % 2:
            prox.append(nivel[-1])
        nivel, i = prox, i // 2
    return caminho


def verificar_prova(folha: str, caminho: list[list[str]], raiz: str) -> bool:
    h = bytes.fromhex(folha)
    for lado, irmao in caminho:
        h = hashlib.sha256(b"\x01" + (bytes.fromhex(irmao) + h if lado == "e" else h + bytes.fromhex(irmao))).digest()
    return h.hex() == raiz


# ------------------------------------------------------------------ carimbo (simulado até a ACT)
def _chave_act() -> Ed25519PrivateKey:
    p = Path(os.environ.get("AUDITOR_ACT_SIMULADA", "chaves/act_simulada.pem"))
    if not p.exists():
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(Ed25519PrivateKey.generate().private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        os.chmod(p, 0o600)
    return serialization.load_pem_private_key(p.read_bytes(), password=None)


def carimbar(raiz: str) -> dict:
    """RFC 3161 pela ACT configurada (AUDITOR_TSA_URL); sem ela, o carimbo simulado."""
    from . import carimbo
    if carimbo.configurado():
        return carimbo.carimbo_ancora(raiz)
    k = _chave_act()
    corpo = {"raiz": raiz, "carimbado_em": datetime.now(timezone.utc).isoformat(), "politica": "simulada"}
    return {"tipo": "simulado", "aviso": "carimbo simulado (sem ACT ICP-Brasil); não atesta data perante terceiros",
            **corpo, "assinatura": base64.b64encode(k.sign(rfc8785.dumps(corpo))).decode(),
            "chave_publica": base64.b64encode(k.public_key().public_bytes(
                serialization.Encoding.Raw, serialization.PublicFormat.Raw)).decode()}


def verificar_carimbo(c: dict, raiz: str) -> bool:
    if c.get("tipo") == "rfc3161":
        from . import carimbo
        return carimbo.verificar_ancora(c, raiz)
    corpo = {"raiz": c["raiz"], "carimbado_em": c["carimbado_em"], "politica": c["politica"]}
    try:
        Ed25519PublicKey.from_public_bytes(base64.b64decode(c["chave_publica"])).verify(
            base64.b64decode(c["assinatura"]), rfc8785.dumps(corpo))
    except Exception:  # noqa: BLE001
        return False
    return c["raiz"] == raiz


# ------------------------------------------------------------------ âncoras
def ancorar(cx, dia: date) -> dict | None:
    """Ancora o dia (idempotente). Devolve a âncora, ou None se não havia trilha até o fim do dia."""
    ja = cx.execute("SELECT * FROM ancora WHERE dia=%s AND tipo='diaria'", (dia,)).fetchone()
    if ja:
        return ja
    return _ancorar(cx, dia, datetime.combine(dia + timedelta(days=1), time(), timezone.utc), "diaria")


def ancorar_agora(cx) -> dict | None:
    """Âncora sob demanda (antes de gerar um pacote): as cabeças de agora, com carimbo. Não substitui a diária."""
    agora = datetime.now(timezone.utc)
    return _ancorar(cx, agora.date(), agora, "sob_demanda")


def _ancorar(cx, dia: date, fim: datetime, tipo: str) -> dict | None:
    cabecas = cx.execute("SELECT DISTINCT ON (cadeia) cadeia, seq, hash FROM trilha_auditoria WHERE cadeia IS NOT NULL "
                         "AND hash IS NOT NULL AND quando < %s ORDER BY cadeia, seq DESC", (fim,)).fetchall()
    if not cabecas:
        return None
    raiz = merkle.raiz([folha_cabeca(c) for c in cabecas])
    car = carimbar(raiz)
    r = cx.execute("INSERT INTO ancora (dia, raiz, cabecas, carimbo, tipo, ate) VALUES (%s,%s,%s,%s,%s,%s) "
                   "ON CONFLICT DO NOTHING RETURNING *", (dia, raiz, Jsonb([dict(c) for c in cabecas]), Jsonb(car),
                                                         tipo, fim)).fetchone()
    trilha(cx, "ancora", "ancorar_dia" if tipo == "diaria" else "ancorar_sob_demanda", None, dia=dia.isoformat(),
           raiz=raiz, cadeias=len(cabecas))
    return r or cx.execute("SELECT * FROM ancora WHERE dia=%s AND tipo=%s", (dia, tipo)).fetchone()


def ancorar_pendentes(cx, ate: date | None = None) -> list[date]:
    """Ancora todos os dias ainda sem âncora, do primeiro registro da trilha até `ate` (padrão: ontem, UTC)."""
    ate = ate or (datetime.now(timezone.utc).date() - timedelta(days=1))
    p = cx.execute("SELECT min(quando) AS q FROM trilha_auditoria WHERE hash IS NOT NULL").fetchone()["q"]
    if not p:
        return []
    feitos, d = [], p.astimezone(timezone.utc).date()
    ja = {r["dia"] for r in cx.execute("SELECT dia FROM ancora WHERE tipo='diaria'")}
    while d <= ate:
        if d not in ja and ancorar(cx, d):
            feitos.append(d)
        d += timedelta(days=1)
    return feitos


def provas_da_cadeia(cx, cadeia: int) -> list[dict]:
    """Para cada dia ancorado em que a cadeia tem cabeça: a cabeça, a prova de inclusão e o carimbo."""
    out = []
    for a in cx.execute("SELECT * FROM ancora ORDER BY ate, id"):
        cabs = a["cabecas"]
        idx = next((i for i, c in enumerate(cabs) if c["cadeia"] == cadeia), None)
        if idx is None:
            continue
        folhas = [folha_cabeca(c) for c in cabs]
        out.append({"dia": a["dia"].isoformat(), "tipo": a["tipo"], "ate": a["ate"].isoformat(), "raiz": a["raiz"], "cabeca": cabs[idx], "folha": folhas[idx],
                    "prova": prova(folhas, idx), "carimbo": a["carimbo"]})
    # dias consecutivos com a mesma cabeça provam a mesma coisa; fica o primeiro (data mais antiga)
    vistos, unicos = set(), []
    for p in out:
        k = (p["cabeca"]["seq"], p["cabeca"]["hash"])
        if k not in vistos:
            vistos.add(k)
            unicos.append(p)
    return unicos

"""Acompanhamento ao vivo por Server-Sent Events (W2, PROPOSTA_WEB §8.8).

Um único leitor por investigação em cada processo da API lê a tabela `tarefa` a cada 1 s e é compartilhado por todas
as conexões abertas para ela; o leitor para quando a última conexão fecha. Evento `progresso` a cada mudança,
`heartbeat` a cada 15 s, `id:` crescente (o cliente reconecta com `Last-Event-ID` e recebe o estado atual com id
maior). No máximo 3 conexões por usuário (a quarta recebe 429). Se a API reiniciar, nada se perde: a fonte é o banco.

  AUDITOR_SSE_HEARTBEAT_S  (15)
"""
from __future__ import annotations

import asyncio
import json
import os
import threading
import time

from .db import conectar

HEARTBEAT_S = float(os.environ.get("AUDITOR_SSE_HEARTBEAT_S", "15"))
LEITURA_S = 1.0
MAX_CONEXOES = 3
_conexoes: dict[str, dict[int, float]] = {}   # sub -> {id da conexão: reservada em}
_lock = threading.Lock()
_seq = [0]
_leitores: dict[int, "Leitor"] = {}


class Limite(Exception):
    pass


def reservar(sub: str) -> int:
    """Reserva uma das 3 conexões do usuário (antes de responder 200). Reservas que nunca começaram a transmitir
    caem em 30 s."""
    with _lock:
        cs = _conexoes.setdefault(sub, {})
        agora = time.monotonic()
        for k in [k for k, t in cs.items() if t and agora - t > 30]:
            del cs[k]
        if len(cs) >= MAX_CONEXOES:
            raise Limite()
        _seq[0] += 1
        cs[_seq[0]] = agora
        return _seq[0]


def _iniciada(sub: str, cid: int):
    with _lock:
        if cid in _conexoes.get(sub, {}):
            _conexoes[sub][cid] = 0.0   # transmitindo: só sai no fim da conexão


def liberar(sub: str, cid: int):
    with _lock:
        _conexoes.get(sub, {}).pop(cid, None)


def _ler(inv_id: int) -> dict:
    from .gestao import acompanhamento
    with conectar() as cx:
        return acompanhamento(cx, inv_id)


def _chave(estado: dict) -> str:
    return json.dumps({k: v for k, v in estado.items() if k != "termino_estimado"}, sort_keys=True, default=str)


class Leitor:
    def __init__(self, inv_id: int):
        self.inv, self.seq, self.atual, self._k = inv_id, 0, None, None
        self.assinantes = 0
        self.mudou = asyncio.Event()
        self.tarefa: asyncio.Task | None = None

    async def laco(self):
        try:
            while self.assinantes > 0:
                try:
                    e = await asyncio.to_thread(_ler, self.inv)
                except Exception:  # noqa: BLE001  (banco indisponível: tenta no próximo ciclo)
                    e = None
                if e is not None and _chave(e) != self._k:
                    self.atual, self._k, self.seq = e, _chave(e), self.seq + 1
                    self.mudou.set()
                    self.mudou = asyncio.Event()
                await asyncio.sleep(LEITURA_S)
        finally:
            if _leitores.get(self.inv) is self:
                del _leitores[self.inv]


def _assinar(inv_id: int) -> Leitor:
    lt = _leitores.get(inv_id)
    if lt is None:
        lt = _leitores[inv_id] = Leitor(inv_id)
    lt.assinantes += 1
    if lt.tarefa is None or lt.tarefa.done():
        lt.tarefa = asyncio.create_task(lt.laco())
    return lt


def leitores_ativos() -> dict[int, int]:
    return {k: v.assinantes for k, v in _leitores.items()}


def evento(nome: str, dados: dict, id_: int | None = None) -> str:
    return (f"id: {id_}\n" if id_ is not None else "") + f"event: {nome}\ndata: " + \
        json.dumps(dados, ensure_ascii=False, default=str) + "\n\n"


async def transmitir(request, inv_id: int, sub: str, cid: int, ultimo_id: int = 0):
    _iniciada(sub, cid)
    lt = _assinar(inv_id)
    enviado, prox, ult = None, max(0, ultimo_id), time.monotonic()
    try:
        yield "retry: 3000\n\n"
        while True:
            if await request.is_disconnected():
                break
            if lt.atual is not None and lt.seq != enviado:
                enviado, prox = lt.seq, max(prox + 1, lt.seq)
                ult = time.monotonic()
                yield evento("progresso", lt.atual, prox)
            elif time.monotonic() - ult >= HEARTBEAT_S:
                ult = time.monotonic()
                yield evento("heartbeat", {"quando": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())})
            try:
                await asyncio.wait_for(lt.mudou.wait(), timeout=1.0)
            except asyncio.TimeoutError:
                pass
    finally:
        lt.assinantes -= 1
        liberar(sub, cid)

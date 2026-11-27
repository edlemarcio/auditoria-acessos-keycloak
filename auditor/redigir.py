"""Versões redigidas, em claro, do que pode levar dado pessoal: requisições à Admin API e mensagens de erro."""
from __future__ import annotations

import re

# parâmetros técnicos da Admin API; qualquer outro (user, username, q, search, email, resourcePath...) é redigido
PARAMS_TECNICOS = {"type", "dateFrom", "dateTo", "first", "max", "direction", "exact", "briefRepresentation",
                   "client", "operationTypes", "resourceTypes", "enabled"}
REDIGIDO = "[redigido]"
_USERS = re.compile(r"/users/[^/?\s]+")
_PESSOAL = [re.compile(p) for p in (
    r"[\w.+-]+@[\w-]+(\.[\w-]+)+",                         # e-mail
    r"\b\d{1,3}(\.\d{1,3}){3}\b",                          # IPv4
    r"\b[0-9a-fA-F]{0,4}(:[0-9a-fA-F]{0,4}){2,7}\b",       # IPv6
    r"\b\d{3}\.?\d{3}\.?\d{3}-?\d{2}\b",                   # CPF
    r"\d{6,}",                                             # sequências longas de dígitos (título, CPF sem máscara)
    r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b",   # userId
)]


def caminho(c: str | None) -> str | None:
    return _USERS.sub(f"/users/{REDIGIDO}", c) if c else c


def params(p):
    if isinstance(p, dict):
        return {k: (v if k in PARAMS_TECNICOS else REDIGIDO) for k, v in p.items()}
    return p


def erro(msg: str | None) -> str | None:
    """Mensagem de erro para guardar e mostrar em claro: sem caminho de usuário, sem identificador, IP nem e-mail."""
    if not msg:
        return msg
    m = caminho(msg)
    for r in _PESSOAL:
        m = r.sub(REDIGIDO, m)
    return m

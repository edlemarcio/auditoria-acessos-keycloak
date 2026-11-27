"""Normalização, validação, variantes e máscara de CPF e Título de Eleitor."""
from __future__ import annotations

import re

TIPOS = ("cpf", "titulo")


def so_digitos(valor: str) -> str:
    return re.sub(r"\D", "", valor or "")


# ---------------- CPF ----------------
def _dv_cpf(base: str) -> str:
    s1 = sum(int(d) * w for d, w in zip(base[:9], range(10, 1, -1)))
    d1 = (s1 * 10) % 11 % 10
    s2 = sum(int(d) * w for d, w in zip(base[:9] + str(d1), range(11, 1, -1)))
    d2 = (s2 * 10) % 11 % 10
    return f"{d1}{d2}"


def cpf_valido(valor: str) -> bool:
    d = so_digitos(valor)
    if len(d) != 11 or d == d[0] * 11:
        return False
    return _dv_cpf(d[:9]) == d[9:]


def completar_cpf(base9: str) -> str:
    return base9 + _dv_cpf(base9)


def formatar_cpf(d: str) -> str:
    return f"{d[:3]}.{d[3:6]}.{d[6:9]}-{d[9:]}"


# ---------------- Título de Eleitor ----------------
# 12 dígitos: 8 sequenciais + 2 da UF (01..28) + 2 DV.
# UF 01 (SP) e 02 (MG): DV igual a 0 vira 1.
def _dv_titulo(seq8: str, uf: str) -> str:
    s1 = sum(int(d) * w for d, w in zip(seq8, range(2, 10)))
    r1 = s1 % 11
    d1 = 0 if r1 == 10 else r1
    if d1 == 0 and uf in ("01", "02"):
        d1 = 1
    s2 = int(uf[0]) * 7 + int(uf[1]) * 8 + d1 * 9
    r2 = s2 % 11
    d2 = 0 if r2 == 10 else r2
    if d2 == 0 and uf in ("01", "02"):
        d2 = 1
    return f"{d1}{d2}"


def titulo_valido(valor: str) -> bool:
    d = so_digitos(valor)
    if len(d) != 12:
        return False
    uf = d[8:10]
    if not ("01" <= uf <= "28"):
        return False
    return _dv_titulo(d[:8], uf) == d[10:]


def completar_titulo(seq8: str, uf: str) -> str:
    return seq8 + uf + _dv_titulo(seq8, uf)


def formatar_titulo(d: str) -> str:
    return f"{d[:4]} {d[4:8]} {d[8:]}"


# ---------------- comum ----------------
def normalizar(tipo: str, valor: str) -> str:
    """Retorna só dígitos; levanta ValueError se inválido."""
    d = so_digitos(valor)
    if tipo == "cpf" and cpf_valido(d):
        return d
    if tipo == "titulo" and titulo_valido(d):
        return d
    raise ValueError(f"{'CPF' if tipo == 'cpf' else 'Título de Eleitor'} inválido")


def variantes(tipo: str, digitos: str) -> list[str]:
    if tipo == "cpf":
        return [digitos, formatar_cpf(digitos)]
    return [digitos, formatar_titulo(digitos)]


def mascarar(tipo: str, digitos: str) -> str:
    if tipo == "cpf":
        return f"***.{digitos[3:6]}.{digitos[6:9]}-**"
    return f"**** {digitos[4:8]} ****"


def mascarar_texto(texto: str | None, tipo: str, digitos: str) -> str | None:
    """Mascara qualquer ocorrência do identificador (com ou sem máscara) num texto."""
    if not texto:
        return texto
    out = texto
    for v in variantes(tipo, digitos):
        out = out.replace(v, mascarar(tipo, digitos))
    return out

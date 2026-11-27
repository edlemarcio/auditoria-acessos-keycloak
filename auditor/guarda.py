"""Modo local que falha fechado (W1, PROPOSTA_WEB §8.7).

  * sem AUDITOR_MODO explícito, a CLI não inicia;
  * no modo local, recusa iniciar se o banco ou alguma instância cadastrada estiver na lista de destinos de produção
    (AUDITOR_DESTINOS_PRODUCAO, "host[:porta],..." ou um por linha no arquivo /etc/kc-auditor/destinos-producao), ou
    num host marcado como produção (AUDITOR_AMBIENTE=producao); a recusa vai para o SIEM;
  * no modo producao (CLI cliente da API), recusa iniciar com credencial de banco, chave ou certificado no ambiente.
"""
from __future__ import annotations

import os
from pathlib import Path
from urllib.parse import urlparse

from . import siem

MODOS = ("local", "vault", "producao")
ARQ_DESTINOS = Path("/etc/kc-auditor/destinos-producao")
CREDENCIAIS = ("AUDITOR_DSN", "AUDITOR_CHAVE", "AUDITOR_CHAVE_ED25519", "CHAVEIRO_DSN", "AUDITOR_CERTS",
               "AUDITOR_IDENTIDADE", "VAULT_TOKEN")


class Recusado(SystemExit):
    pass


def modo() -> str:
    m = os.environ.get("AUDITOR_MODO")
    if m not in MODOS:
        raise Recusado("Defina AUDITOR_MODO: local (desenvolvimento e teste), vault (serviços) ou producao "
                       "(CLI cliente da API). Sem modo explícito a CLI não inicia.")
    return m


def destinos_producao() -> set[str]:
    txt = os.environ.get("AUDITOR_DESTINOS_PRODUCAO", "")
    if ARQ_DESTINOS.exists():
        txt += "\n" + ARQ_DESTINOS.read_text()
    return {d.strip().lower() for d in txt.replace(",", "\n").splitlines() if d.strip() and not d.startswith("#")}


def _alvos(url: str) -> set[str]:
    u = urlparse(url if "://" in url else f"x://{url}")
    h = (u.hostname or "").lower()
    return {h, f"{h}:{u.port}"} if u.port else {h}


def exigir_local_seguro(dsn: str | None = None, instancias: list[str] | None = None):
    if os.environ.get("AUDITOR_AMBIENTE") == "producao":
        siem.enviar("modo_local_em_producao", "alerta")
        raise Recusado("Modo local recusado: este host está marcado como produção (AUDITOR_AMBIENTE=producao)")
    prod = destinos_producao()
    if not prod:
        return
    candidatos = [("banco", dsn or os.environ.get("AUDITOR_DSN", ""))] + [("instância", u) for u in instancias or []]
    for o_que, url in candidatos:
        if url and _alvos(url) & prod:
            siem.enviar("modo_local_contra_producao", "alerta", motivo_codigo=o_que)
            raise Recusado(f"Modo local recusado: o {o_que} configurado é um destino de produção")


def instancias_cadastradas() -> list[str]:
    try:
        from .db import conectar
        with conectar() as cx:
            return [r["url"] for r in cx.execute("SELECT url FROM instancia")]
    except Exception:  # noqa: BLE001  (banco ainda sem esquema: o DSN já foi conferido)
        return []


def exigir_cliente_limpo():
    presentes = [v for v in CREDENCIAIS if os.environ.get(v)]
    if presentes:
        raise Recusado(f"Modo producao: a CLI é só cliente da API e não aceita credenciais no ambiente "
                       f"({', '.join(presentes)}). Remova-as.")

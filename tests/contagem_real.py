"""Critério de aceite 1 contra a stack real: compara, id a id (ou pelo conteúdo, no Keycloak <= 21), o que o auditor coletou com a EVENT_ENTITY.

  KC_DSN_kc26=... KC_DSN_kc18=... AUDITOR_DSN=... python tests/contagem_real.py <investigacao>

Desde a W0b os eventos ficam cifrados: o teste decifra com a DEK da investigação (modo local: AUDITOR_CHAVE; modo
vault: identidade `pacotes`, com a investigação concluída).
"""
from __future__ import annotations

import os
import sys
from collections import Counter
from pathlib import Path

import psycopg

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
os.environ.setdefault("AUDITOR_IDENTIDADE", "pacotes")
from auditor import sigilo  # noqa: E402
from auditor.db import conectar  # noqa: E402

MAPA = {"kc26": "kc26", "rhsso": "kc18"}


def main(inv: int):
    falhas = 0
    with conectar() as cx:
        i = cx.execute("SELECT * FROM investigacao WHERE id=%s", (inv,)).fetchone()
        cf = sigilo.Cofre(inv, "exportar")
        for c in sigilo.contas(cx, cf, "AND c.incluida"):
            if not c.get("user_id"):
                continue
            # mesma janela da consulta à EVENT_ENTITY (o período de base, --base-dias, fica de fora)
            linhas = [sigilo.abrir_evento(cf, r) for r in cx.execute(
                "SELECT * FROM evento WHERE conta_id=%s AND time_ms>=%s AND time_ms<%s",
                (c["id"], i["inicio_ms"], i["fim_ms"])).fetchall()]
            linhas = [(e["id"], e["time_ms"], e["type"], e["session_id"], e["ip"]) for e in linhas]
            with psycopg.connect(os.environ[f"KC_DSN_{MAPA[c['instancia']]}"]) as kc:
                ref_l = kc.execute(
                    "SELECT e.id, e.event_time, e.type, e.session_id, e.ip_address FROM event_entity e "
                    "JOIN realm r ON r.id=e.realm_id WHERE r.name=%s AND e.user_id=%s "
                    "AND e.event_time>=%s AND e.event_time<%s",
                    (c["realm"], c["user_id"], i["inicio_ms"], i["fim_ms"])).fetchall()
            # Keycloak <= 21 não expõe o id do evento (o auditor gera um id sintético): compara pelo conteúdo
            sintetico = any(str(r[0]).startswith(("sha256:", "h:")) for r in linhas)
            chave = (lambda r: tuple(r[1:])) if sintetico else (lambda r: r[0])
            col, ref = Counter(map(chave, linhas)), Counter(map(chave, ref_l))
            ok = col == ref
            falhas += not ok
            print(f"{'OK   ' if ok else 'FALHA'} {c['instancia']:6s} {c['realm']:15s} coletados={len(linhas):6d} "
                  f"sql={len(ref_l):6d} faltando={(ref - col).total()} extras={(col - ref).total()} "
                  f"comparação={'conteúdo' if sintetico else 'id'}")
    sys.exit(1 if falhas else 0)


if __name__ == "__main__":
    main(int(sys.argv[1]))

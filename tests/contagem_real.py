"""Critério de aceite 1 contra a stack real: compara, id a id, o que o auditor coletou com a EVENT_ENTITY.

  KC_DSN_kc26=... KC_DSN_kc18=... AUDITOR_DSN=... python tests/contagem_real.py <investigacao>
"""
from __future__ import annotations

import os
import sys

import psycopg

MAPA = {"kc26": "kc26", "rhsso": "kc18"}


def main(inv: int):
    aud = psycopg.connect(os.environ.get("AUDITOR_DSN", "postgresql://postgres@127.0.0.1/auditor"))
    i0, i1 = aud.execute("SELECT inicio_ms, fim_ms FROM investigacao WHERE id=%s", (inv,)).fetchone()
    falhas = 0
    for cid, inst, realm, uid in aud.execute(
            "SELECT c.id, i.nome, c.realm, c.user_id FROM conta c JOIN instancia i ON i.id=c.instancia_id "
            "WHERE c.investigacao_id=%s AND c.incluida AND c.user_id IS NOT NULL", (inv,)).fetchall():
        col = {r[0] for r in aud.execute("SELECT id FROM evento WHERE conta_id=%s", (cid,))}
        with psycopg.connect(os.environ[f"KC_DSN_{MAPA[inst]}"]) as kc:
            ref = {r[0] for r in kc.execute(
                "SELECT e.id FROM event_entity e JOIN realm r ON r.id=e.realm_id WHERE r.name=%s AND e.user_id=%s "
                "AND e.event_time>=%s AND e.event_time<%s", (realm, uid, i0, i1))}
        ok = col == ref
        falhas += not ok
        print(f"{'OK   ' if ok else 'FALHA'} {inst:6s} {realm:15s} coletados={len(col):6d} sql={len(ref):6d} "
              f"faltando={len(ref - col)} extras={len(col - ref)}")
    sys.exit(1 if falhas else 0)


if __name__ == "__main__":
    main(int(sys.argv[1]))

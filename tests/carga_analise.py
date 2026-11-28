"""Carga da análise (W3, PROPOSTA_WEB §7.11 e §8.4): primeira tela do dashboard < 2 s (p95) com 500 mil eventos.

  AUDITOR_DSN=<kc_auditor_app> AUDITOR_DSN_DONO=<dono> AUDITOR_CHAVE=... python tests/carga_analise.py [--eventos N]

Cria uma investigação sintética (cópia dos metadados de uma concluída de investigador1, com contas próprias) e grava N
eventos pseudonimizados com distribuição parecida com a real (logins, falhas, técnicos; 5 mil IPs; 20 aplicações;
180 dias), calcula os agregados e mede, pela API (papel kc_api, com RLS), o dashboard sem filtro e com filtros, a
primeira página de eventos e a página filtrada por IP. No fim apaga a investigação sintética.
"""
from __future__ import annotations

import argparse
import statistics
import sys
import time
from pathlib import Path

RAIZ = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(RAIZ / "tests"))
import analise as base  # noqa: E402  (mesma infraestrutura: banco, API com kc_api, login)

META_S = 2.0


def criar(n: int) -> int:
    with base.banco(base.DSN_DONO) as cx:
        sub = {r["username"]: r["sub"] for r in cx.execute("SELECT username, sub FROM usuario")}
        orig = cx.execute("""SELECT i.id FROM investigacao i JOIN designacao d ON d.investigacao_id=i.id
            AND d.funcao='investigador' AND d.sub=%s WHERE i.status LIKE 'concluida%%' ORDER BY i.id DESC LIMIT 1""",
                          (sub["investigador1"],)).fetchone()["id"]
        with cx.transaction():
            cx.execute("CREATE TEMP TABLE t_inv AS SELECT * FROM investigacao WHERE id=%s", (orig,))
            novo = cx.execute("SELECT nextval(pg_get_serial_sequence('investigacao','id')) AS n").fetchone()["n"]
            cx.execute("UPDATE t_inv SET id=%s, status='concluida', lacrada=false", (novo,))
            cx.execute("INSERT INTO investigacao SELECT * FROM t_inv")
            cx.execute("DROP TABLE t_inv")
            cx.execute("INSERT INTO designacao (investigacao_id, funcao, sub, designado_por) VALUES (%s,'investigador',%s,"
                       "'carga')", (novo, sub["investigador1"]))
            insts = [r["id"] for r in cx.execute("SELECT id FROM instancia ORDER BY id LIMIT 2")]
            contas = []
            for k in range(8):
                contas.append(cx.execute("""INSERT INTO conta (investigacao_id, instancia_id, realm, via, incluida,
                    ps_conta) VALUES (%s,%s,%s,'atributo',true,%s) RETURNING id""",
                                         (novo, insts[k % len(insts)], f"realm{k % 4}", f"carga-conta-{k}")).fetchone()["id"])
            inv = cx.execute("SELECT inicio_ms, fim_ms FROM investigacao WHERE id=%s", (novo,)).fetchone()
            t0 = time.time()
            cx.execute("""INSERT INTO evento (investigacao_id, instancia_id, realm, id, conta_id, time_ms, type, client_id,
                    error, ps_conta, ps_ip, ps_sessao)
                SELECT %(inv)s, c.instancia_id, c.realm, 'carga-' || g, c.id,
                       %(ini)s + (random() * (%(fim)s - %(ini)s - 1))::bigint,
                       (ARRAY['LOGIN','LOGIN','LOGIN','LOGIN_ERROR','CODE_TO_TOKEN','REFRESH_TOKEN','LOGOUT',
                              'UPDATE_PASSWORD'])[1 + (g %% 8)],
                       'app-' || (g %% 20), CASE WHEN g %% 8 = 3 THEN 'invalid_user_credentials' END,
                       c.ps_conta, 'carga-ip-' || ((g * 7919) %% 5000), 'carga-s-' || (g %% 40000)
                FROM generate_series(1::bigint, %(n)s::bigint) g
                JOIN LATERAL (SELECT * FROM conta WHERE id = (%(c)s::int[])[1 + (g %% 8)]) c ON true""",
                       {"inv": novo, "ini": inv["inicio_ms"], "fim": inv["fim_ms"], "n": n, "c": contas})
            print(f"{n} eventos gravados em {time.time() - t0:.1f}s (investigação sintética {novo})")
        cx.execute("ANALYZE evento")
        from auditor import analise
        t0 = time.time()
        r = analise.calcular(cx, novo)
        print(f"agregados e destaques: {time.time() - t0:.1f}s {r}")
    return novo


def apagar(inv_id: int):
    with base.banco(base.DSN_DONO) as cx:
        for t in ("agregado_hora", "agregado_ip", "destaque", "analise", "conta_decisao", "evento", "designacao", "job",
                  "trilha_auditoria"):
            if t == "trilha_auditoria":
                continue   # só inserção; o teste não grava trilha nesta investigação
            cx.execute(f"DELETE FROM {t} WHERE investigacao_id=%s", (inv_id,))
        cx.execute("DELETE FROM conta WHERE investigacao_id=%s", (inv_id,))
        cx.execute("DELETE FROM investigacao WHERE id=%s", (inv_id,))


def medir(nome: str, caminho: str, params=None, vezes: int = 10) -> float:
    ts = []
    for _ in range(vezes):
        t0 = time.perf_counter()
        c, _ = base.j("investigador1", "GET", caminho, params=params or {})
        ts.append(time.perf_counter() - t0)
        assert c == 200, (nome, c)
    p95 = sorted(ts)[max(0, int(len(ts) * 0.95) - 1)]
    base.checar(p95 < META_S, f"{nome}: p95 {p95:.2f}s (mediana {statistics.median(ts):.2f}s)", f"meta < {META_S}s")
    return p95


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--eventos", type=int, default=500_000)
    ap.add_argument("--inv", type=int, help="reusar uma investigação sintética já criada (com --manter)")
    ap.add_argument("--manter", action="store_true", help="não apagar a investigação sintética no fim")
    a = ap.parse_args()
    inv = a.inv or criar(a.eventos)
    api, wk = base.processos()
    try:
        base.entrar("investigador1")
        P = f"/api/investigacoes/{inv}"
        c, d = base.j("investigador1", "GET", f"{P}/dashboard")
        base.checar(d["kpis"]["eventos"] > 0, "dashboard responde com a massa sintética", d["kpis"])
        medir("dashboard sem filtro", f"{P}/dashboard")
        medir("dashboard com técnicos", f"{P}/dashboard", {"tecnicos": "1"})
        medir("dashboard filtrado por aplicação", f"{P}/dashboard", {"cliente": "app-3"})
        medir("dashboard filtrado por realm", f"{P}/dashboard", {"realm": "realm1"})
        medir("eventos: primeira página", f"{P}/eventos", {"limite": 50})
        medir("eventos: falhas", f"{P}/eventos", {"tipo": "falhas", "limite": 50})
        c, p = base.j("investigador1", "GET", f"{P}/eventos", params={"limite": 50})
        medir("eventos: página seguinte", f"{P}/eventos", {"limite": 50, "apos": p["proximo"]})
    finally:
        api.terminate()
        wk.terminate()
        if not a.manter:
            apagar(inv)
    print(f"\n{base.oks[0]} OK; {'APROVADO' if not base.falhas else 'REPROVADO'}: {len(base.falhas)} falha(s)")
    sys.exit(1 if base.falhas else 0)


if __name__ == "__main__":
    main()

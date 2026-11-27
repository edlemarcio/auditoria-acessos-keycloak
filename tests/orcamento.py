"""Critério de aceite do orçamento de carga entre processos (docs/PROPOSTA_WEB.md, §8.3, etapa W0a).

Três processos, cada um com várias threads, fazem requisições à mesma instância ao mesmo tempo. Nenhuma janela de
1 s pode passar de `req_por_s` e o número de requisições simultâneas não pode passar de `concorrencia`.

  AUDITOR_DSN=... python tests/orcamento.py [instancia] [processos] [threads] [requisicoes_por_thread]
"""
from __future__ import annotations

import subprocess
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

RAIZ = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(RAIZ))
from auditor.db import conectar  # noqa: E402
from auditor.kc import ClienteKC  # noqa: E402


def filho(nome: str, threads: int, n: int):
    with conectar() as cx:
        inst = cx.execute("SELECT * FROM instancia WHERE nome=%s", (nome,)).fetchone()
    cli = ClienteKC(inst)
    realm = inst["realms_esperados"][0] if inst["realms_esperados"] else "master"

    def rodar():
        for _ in range(n):
            cli.get(f"/admin/realms/{realm}/events", {"max": "1"})

    ths = [threading.Thread(target=rodar) for _ in range(threads)]
    for t in ths:
        t.start()
    for t in ths:
        t.join()
    cli.fechar()


def main(nome="kc26", processos=3, threads=3, n=12):
    with conectar() as cx:
        inst = cx.execute("SELECT * FROM instancia WHERE nome=%s", (nome,)).fetchone()
    t0 = datetime.now(timezone.utc)
    inicio = time.monotonic()
    procs = [subprocess.Popen([sys.executable, __file__, "filho", nome, str(threads), str(n)], cwd=RAIZ)
             for _ in range(processos)]
    codigos = [p.wait() for p in procs]
    duracao = time.monotonic() - inicio
    with conectar() as cx:
        taxa = cx.execute("""
            SELECT coalesce(max(n), 0) AS n FROM (SELECT count(*) OVER (ORDER BY inicio
                RANGE BETWEEN CURRENT ROW AND interval '999 milliseconds' FOLLOWING) n
              FROM requisicao WHERE instancia_id=%s AND inicio >= %s AND investigacao_id IS NULL) x""",
                          (inst["id"], t0)).fetchone()["n"]
        # simultâneas: varre inícios (+1) e fins (-1) das requisições
        sim = cx.execute("""
            SELECT coalesce(max(s), 0) AS s FROM (SELECT sum(d) OVER (ORDER BY t, d) s FROM (
              SELECT inicio t, 1 d FROM requisicao WHERE instancia_id=%(i)s AND inicio >= %(t0)s
                AND investigacao_id IS NULL
              UNION ALL
              SELECT inicio + make_interval(secs => ms / 1000.0), -1 FROM requisicao WHERE instancia_id=%(i)s
                AND inicio >= %(t0)s AND investigacao_id IS NULL) e) x""", {"i": inst["id"], "t0": t0}).fetchone()["s"]
        total = cx.execute("SELECT count(*) n FROM requisicao WHERE instancia_id=%s AND inicio >= %s "
                           "AND investigacao_id IS NULL", (inst["id"], t0)).fetchone()["n"]
    esperado = processos * threads * n
    ok = all(c == 0 for c in codigos) and total == esperado and taxa <= inst["req_por_s"] \
        and sim <= inst["concorrencia"]
    print(f"{'OK   ' if ok else 'FALHA'} {processos} processos × {threads} threads × {n} requisições = {total}/"
          f"{esperado} em {duracao:.1f}s · máximo em 1 s: {taxa} (limite {inst['req_por_s']:g}) · "
          f"simultâneas: {sim} (limite {inst['concorrencia']})")
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "filho":
        filho(sys.argv[2], int(sys.argv[3]), int(sys.argv[4]))
    else:
        a = sys.argv[1:]
        main(*(a[:1] + [int(x) for x in a[1:]]))

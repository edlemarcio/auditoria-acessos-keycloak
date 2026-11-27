"""Critérios de aceite da fila e do worker (docs/PROPOSTA_WEB.md §8.2, etapa W0a), contra a stack real.

  AUDITOR_DSN=<kc_auditor_app> KC_DSN_kc26=... KC_DSN_kc18=... python tests/fila.py [dias]

1. Rodízio: duas investigações enfileiradas avançam juntas no mesmo worker.
2. Pausa: a investigação pausada fica sem fatias em execução, a outra continua; nada se perde.
3. Retomada: ela volta à fila e as duas fecham sozinhas (job 'fechar'); contagem id a id confere.
4. Cancelamento: a investigação cancelada para, as pendentes viram 'cancelada' e não há fechamento.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import threading
import time
from datetime import date, timedelta
from pathlib import Path

RAIZ = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(RAIZ))
from auditor import investigar, servicos  # noqa: E402
from auditor.db import conectar  # noqa: E402

falhas: list[str] = []


def checar(ok: bool, nome: str, detalhe: str = ""):
    print(f"{'OK   ' if ok else 'FALHA'} {nome}{(' — ' + detalhe) if detalhe else ''}", flush=True)
    if not ok:
        falhas.append(nome)


def estado(inv: int) -> dict:
    with conectar() as cx:
        st = cx.execute("SELECT status FROM investigacao WHERE id=%s", (inv,)).fetchone()["status"]
        t = {r["status"]: r["n"] for r in cx.execute(
            "SELECT status, count(*) n FROM tarefa WHERE investigacao_id=%s GROUP BY 1", (inv,))}
    return {"status": st, **t}


def esperar(cond, limite=600, passo=1.0):
    fim = time.monotonic() + limite
    while time.monotonic() < fim:
        if cond():
            return True
        time.sleep(passo)
    return False


def abrir(dias: int, rotulo: str) -> int:
    alvo = json.loads((RAIZ / "dados/pessoas.json").read_text())["casos"]["ALVO"]["cpf"]
    ate = date.today() - timedelta(days=1)
    inv = investigar.abrir("teste-fila", f"Teste da fila: {rotulo}", "cpf", alvo,
                           (ate - timedelta(days=dias)).isoformat(), ate.isoformat(), varredura=True)
    servicos.enfileirar(inv, "teste-fila")
    return inv


def main(dias: int = 20):
    a, b = abrir(dias, "A"), abrir(dias, "B")
    print(f"investigações A={a} B={b}", flush=True)
    feito: list[tuple[float, int]] = []

    def anotar(s: str):
        if s.startswith("tarefa"):
            feito.append((time.monotonic(), int(s.rsplit("#", 1)[1])))

    parar = threading.Event()
    w = threading.Thread(target=servicos.worker, kwargs={"threads": 2, "parar": parar, "ao_fazer": anotar},
                         daemon=True)
    w.start()

    # 1. rodízio
    esperar(lambda: estado(a)["status"] == "coletando" and estado(b)["status"] == "coletando", 300)
    esperar(lambda: len(feito) >= 30, 300)
    janela = [i for _, i in feito[:30]]
    checar(janela.count(a) >= 8 and janela.count(b) >= 8, "1 rodízio entre investigações",
           f"nas 30 primeiras fatias: A={janela.count(a)} B={janela.count(b)}")

    # 2. pausa
    servicos.pausar(a, "teste-fila")
    parou = esperar(lambda: estado(a).get("executando", 0) == 0, 60, 0.5)
    antes = estado(a)
    n_b = sum(1 for _, i in feito if i == b)
    time.sleep(8)
    depois = estado(a)
    checar(parou and antes == depois and antes["status"] == "pausada", "2 pausada: sem fatias em execução e sem "
           "avanço", f"{depois}")
    checar(sum(1 for _, i in feito if i == b) > n_b, "2 a outra investigação continua durante a pausa")

    # 3. retomada e fechamento automático
    servicos.retomar(a, "teste-fila")
    fechou = esperar(lambda: all(estado(x)["status"] in ("concluida", "concluida_com_lacunas") for x in (a, b)), 900)
    checar(fechou, "3 retomada e fechamento automático pelo worker", f"A={estado(a)} B={estado(b)}")
    for x in (a, b):
        r = subprocess.run([sys.executable, "tests/contagem_real.py", str(x)], cwd=RAIZ, capture_output=True,
                           text=True, env=os.environ)
        checar(r.returncode == 0, f"3 contagem id a id da investigação {x}", r.stdout.strip().replace("\n", " | "))

    # 4. cancelamento
    c = abrir(dias, "C")
    esperar(lambda: estado(c).get("concluida", 0) >= 5, 300)
    servicos.cancelar(c, "teste-fila", "Teste de cancelamento")
    esperar(lambda: estado(c).get("executando", 0) == 0, 60, 0.5)
    time.sleep(5)
    ec = estado(c)
    with conectar() as cx:
        jobs = cx.execute("SELECT tipo, status FROM job WHERE investigacao_id=%s ORDER BY id", (c,)).fetchall()
    checar(ec["status"] == "cancelada" and ec.get("pendente", 0) == 0 and ec.get("cancelada", 0) > 0
           and not any(j["tipo"] == "fechar" for j in jobs), "4 cancelamento sem pendentes e sem fechamento",
           f"{ec}, jobs={[(j['tipo'], j['status']) for j in jobs]}")

    parar.set()
    w.join(30)
    print(f"\n{'APROVADO' if not falhas else 'REPROVADO'}: {len(falhas)} falha(s)")
    sys.exit(1 if falhas else 0)


if __name__ == "__main__":
    main(*(int(x) for x in sys.argv[1:2]))

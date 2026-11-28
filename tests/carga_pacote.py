"""Carga do pacote v2 (W5, PROPOSTA_WEB §6.4): até 500 mil eventos com menos de 1 GB de memória no worker.

  source env; AUDITOR_TSA_URL=... AUDITOR_TSA_HOMOLOGACAO=1 python tests/carga_pacote.py [--eventos 500000]

Cria um banco descartável (auditor_w5carga, no mesmo servidor), aplica as migrações e grava uma investigação
sintética como a coleta grava: eventos cifrados com a DEK, folha com sal de 256 bits, pseudônimos, uma tarefa por conta
e dia, selo de cada fatia na cadeia. Gera os pacotes mascarado e sem máscara em processos separados, medindo a memória
máxima (RSS) e o tempo, roda o verificador offline com --recalcular sobre os dois e apaga o banco no fim.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path

RAIZ = Path(__file__).resolve().parents[1]
BANCO = "auditor_w5carga"
META_KB = 1024 * 1024
FALHAS: list[str] = []


def checar(ok: bool, nome: str, det: str = ""):
    print(f"[{'ok' if ok else 'FALHA'}] {nome}" + (f" — {det}" if det else ""))
    if not ok:
        FALHAS.append(nome)


def dsn_de(base: str, banco: str) -> str:
    return re.sub(r"/[^/]+$", f"/{banco}", base)


POPULAR = r'''
import json, os, random, sys, uuid
from datetime import datetime
from zoneinfo import ZoneInfo
from auditor import investigar, merkle, sigilo, cripto
from auditor.coleta import selar
from auditor.db import conectar
N = int(sys.argv[1])
random.seed(7)
with conectar() as cx:
    cx.execute("INSERT INTO instancia (nome, url, client_id, segredo_cifrado, versao_declarada, sondas) VALUES "
               "('kc26', 'http://localhost:8090', 'auditor', '\\x00', '26', '{\"modo\": \"admin_events\"}') "
               "ON CONFLICT DO NOTHING")
inv = investigar.abrir("carga-w5", "Carga do pacote v2 (W5)", "cpf", "52998224725", "2026-05-01", "2026-10-27",
                       fuso="America/Sao_Paulo", granularidade="dia", instancias=["kc26"], base_dias=30,
                       status="coletando")
cf = sigilo.Cofre(inv, "coleta")
tz = ZoneInfo("America/Sao_Paulo")
ini = int(datetime(2026, 5, 1, tzinfo=tz).timestamp() * 1000)
DIA = 86_400_000
ips = [f"10.{random.randrange(256)}.{random.randrange(256)}.{random.randrange(1, 255)}" for _ in range(5000)]
clientes = [f"app-{i:02d}" for i in range(20)]
tipos = ["LOGIN"] * 60 + ["LOGIN_ERROR"] * 15 + ["CODE_TO_TOKEN"] * 15 + ["REFRESH_TOKEN"] * 8 + ["UPDATE_PASSWORD"] * 2
with conectar() as cx:
    inst = cx.execute("SELECT id FROM instancia WHERE nome='kc26'").fetchone()["id"]
    contas = []
    for k in range(2):
        uid = str(uuid.UUID(int=random.getrandbits(128)))
        cid = sigilo.inserir_conta(cx, cf, inst, "intranet", uid, f"usuario.carga{k}", f"carga{k}@exemplo.gov.br")
        contas.append((cid, uid, f"usuario.carga{k}"))
    por_tarefa = max(1, N // (len(contas) * 180))
    total = 0
    for cid, uid, uname in contas:
        for d in range(180):
            t0 = ini + d * DIA
            tid = cx.execute("INSERT INTO tarefa (investigacao_id, conta_id, inicio_ms, fim_ms, modo, status, eventos) "
                             "VALUES (%s,%s,%s,%s,'admin','concluida',%s) RETURNING id",
                             (inv, cid, t0, t0 + DIA, por_tarefa)).fetchone()["id"]
            linhas = []
            sessao = str(uuid.uuid4())
            for j in range(por_tarefa):
                if j % 10 == 0:
                    sessao = str(uuid.UUID(int=random.getrandbits(128)))
                tp = random.choice(tipos)
                b = {"id": str(uuid.UUID(int=random.getrandbits(128))), "time": t0 + random.randrange(DIA),
                     "type": tp, "realmId": "intranet", "clientId": random.choice(clientes), "userId": uid,
                     "sessionId": sessao, "ipAddress": random.choice(ips),
                     "details": {"auth_method": "openid-connect", "username": uname,
                                 "redirect_uri": "https://app.exemplo.gov.br/callback"}}
                if tp.endswith("_ERROR"):
                    b["error"] = "invalid_user_credentials"
                sal = os.urandom(32)
                canon = merkle.canonico(b)
                linhas.append((inv, inst, "intranet", b["id"], cid, b["time"], tp, b["clientId"], b.get("error"),
                               sigilo.cifrar_evento(cf, inst, "intranet", b["id"], b, sal=sal.hex()),
                               cf.ps("conta", uid), cf.ps("ip", b["ipAddress"]), cf.ps("sessao", sessao),
                               merkle.folha(sal, canon), cf.ps("conteudo", canon.decode())))
            with cx.cursor() as cur, cur.copy("COPY evento (investigacao_id, instancia_id, realm, id, conta_id, time_ms, "
                                              "type, client_id, error, cifrado, ps_conta, ps_ip, ps_sessao, folha, "
                                              "hash_conteudo) FROM STDIN") as cp:
                for l in linhas:
                    cp.write_row(l)
            selar(cx, inv, {"id": tid, "conta_id": cid, "inicio_ms": t0, "fim_ms": t0 + DIA})
            total += len(linhas)
        cx.execute("INSERT INTO cobertura (investigacao_id, instancia_id, realm, conta_id, classe, status, detalhe, "
                   "desde_ms) VALUES (%s,%s,'intranet',%s,'coberto','ok',NULL,%s)", (inv, inst, cid, ini - 30 * DIA))
    cx.execute("UPDATE investigacao SET status='concluida', concluido_em=now() WHERE id=%s", (inv,))
print(json.dumps({"inv": inv, "eventos": total}))
'''

GERAR = r'''
import json, sys
from pathlib import Path
from auditor.exportar import exportar
r = exportar(int(sys.argv[1]), Path(sys.argv[2]), "carga-w5", sem_mascara=sys.argv[3] == "1", soltos=False)
print(json.dumps(r))
'''


def medir(cmd: list[str], env: dict) -> tuple[dict, int, float]:
    t = time.time()
    p = subprocess.run(["/usr/bin/time", "-f", "RSS_KB=%M"] + cmd, cwd=RAIZ, env=env, capture_output=True, text=True)
    rss = int(re.search(r"RSS_KB=(\d+)", p.stderr).group(1))
    if p.returncode not in (0, 1):
        raise SystemExit(p.stderr[-2000:])
    texto = p.stdout.strip()
    for cand in (texto, texto.splitlines()[-1] if texto else ""):
        try:
            return json.loads(cand), rss, time.time() - t
        except json.JSONDecodeError:
            continue
    return {"bruto": p.stdout[-3000:], "rc": p.returncode}, rss, time.time() - t


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--eventos", type=int, default=500_000)
    ap.add_argument("--manter", action="store_true", help="não apaga o banco no fim")
    a = ap.parse_args()
    base = os.environ["AUDITOR_DSN"]
    dono = os.environ.get("AUDITOR_DSN_DONO", base.replace("kc_auditor_app:senha-app-teste", "keycloak:keycloak"))
    adm = dsn_de(dono, "postgres")
    dsn = dsn_de(dono, BANCO)
    subprocess.run(["psql", adm, "-qc", f"DROP DATABASE IF EXISTS {BANCO}"], check=True)
    subprocess.run(["psql", adm, "-qc", f"CREATE DATABASE {BANCO}"], check=True)
    env = {**os.environ, "AUDITOR_DSN": dsn, "AUDITOR_MODO": "local", "PYTHONWARNINGS": "ignore"}
    py = str(RAIZ / ".venv" / "bin" / "python")
    try:
        subprocess.run([py, "-c", "from auditor.db import migrar_esquema; migrar_esquema()"], cwd=RAIZ, env=env,
                       check=True)
        t = time.time()
        r, _, _ = medir([py, "-c", POPULAR, str(a.eventos)], env)
        print(f"  investigação sintética {r['inv']}: {r['eventos']:,} eventos cifrados e selados em {time.time() - t:.0f} s")
        for sem, rot in ((False, "mascarado"), (True, "sem máscara")):
            g, rss, dt = medir([py, "-c", GERAR, str(r["inv"]), str(RAIZ / "saida" / "carga_w5"), "1" if sem else "0"],
                               env)
            checar(rss < META_KB and g.get("eventos") == r["eventos"],
                   f"pacote {rot} com {r['eventos']:,} eventos abaixo de 1 GB de memória",
                   f"RSS máximo {rss / 1024:.0f} MB, {dt:.0f} s, {Path(g['pacote']).stat().st_size / 1e6:.0f} MB")
            v, rss_v, dt_v = medir([py, "-m", "kc_verificar", g["pacote"], "--homologacao", "--recalcular", "--json"],
                                   {**env, "PYTHONPATH": str(RAIZ / "verificador")})
            checar(v.get("integro") is True and rss_v < META_KB,
                   f"verificador offline aprova o pacote {rot} de {r['eventos']:,} eventos (--recalcular), abaixo de 1 GB",
                   f"RSS {rss_v / 1024:.0f} MB, {dt_v:.0f} s; " + "; ".join(
                       i["texto"] for i in v.get("itens", []) if i["nivel"] == "falha")[:300])
    finally:
        if not a.manter:
            subprocess.run(["psql", adm, "-qc", f"DROP DATABASE IF EXISTS {BANCO} WITH (FORCE)"])
            for f in (RAIZ / "saida" / "carga_w5").glob("*.zip"):
                f.unlink()
    print(f"\n{'APROVADO' if not FALHAS else 'REPROVADO'}: {len(FALHAS)} falha(s)")
    sys.exit(1 if FALHAS else 0)


if __name__ == "__main__":
    main()

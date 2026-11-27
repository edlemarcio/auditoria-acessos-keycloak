"""Testes de aceite (seção 6 da proposta) contra 1 milhão de eventos por instância.

Executa as investigações, mata o coletor no meio (kill -9), retoma, roda com expurgo ativo e compara
o que foi coletado com o banco do Keycloak (contagem independente por SQL, id a id).

Uso: python tests/aceite.py   (simuladores no ar: tools/sims.sh)
"""
from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
import time
import zipfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from zoneinfo import ZoneInfo

import psycopg

RAIZ = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(RAIZ))
AUD = "postgresql://postgres@127.0.0.1/auditor"
KCDB = {"kc26": "kc26", "rhsso": "kc18", "kc26-carga": "kc26", "rhsso-carga": "kc18", "kc26-bugdateto": "kc26",
        "kc26-semdir": "kc26", "kc26-curinga": "kc26", "kc26-purga": "kc26"}
ENV = {**os.environ}
for linha in (RAIZ / "chaves.env").read_text().splitlines():
    k, v = linha.replace("export ", "").split("=", 1)
    ENV[k] = v
os.environ.update(ENV)
ALVO = json.loads((RAIZ / "dados/pessoas.json").read_text())["casos"]["ALVO"]["cpf"]
HOJE = datetime.now(ZoneInfo("America/Bahia")).date()
R: dict = {"inicio": datetime.now(timezone.utc).isoformat(), "criterios": {}}


def cli(*args, bg=False):
    cmd = [sys.executable, "-m", "auditor", *args]
    if bg:
        return subprocess.Popen(cmd, cwd=RAIZ, env=ENV, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    p = subprocess.run(cmd, cwd=RAIZ, env=ENV, capture_output=True, text=True)
    if p.returncode != 0:
        raise RuntimeError(p.stdout[-2000:] + p.stderr[-3000:])
    return p.stdout


def aud():
    return psycopg.connect(AUD, autocommit=True)


def ultima_inv() -> int:
    with aud() as cx:
        return cx.execute("SELECT max(id) FROM investigacao").fetchone()[0]


def instancia(nome, porta, base="", conc=2, rps=5, esperados=""):
    cli("instancia-add", "--nome", nome, "--url", f"http://127.0.0.1:{porta}{base}", "--client-id", "kc-auditor",
        "--segredo", "troque-este-segredo", "--concorrencia", str(conc), "--req-por-s", str(rps),
        "--realms-esperados", esperados, "--homologacao", "homologacao", "--sonda", "sonda")
    with aud() as cx:
        return cx.execute("SELECT sondas FROM instancia WHERE nome=%s", (nome,)).fetchone()[0]


def comparar(inv_id: int) -> list[dict]:
    """Compara, id a id, os eventos coletados com a tabela EVENT_ENTITY do Keycloak."""
    out = []
    with aud() as cx:
        inv = cx.execute("SELECT inicio_ms, fim_ms, parametros FROM investigacao WHERE id=%s", (inv_id,)).fetchone()
        base = (inv[2].get("base_dias") or 0) * 86400_000
        contas = cx.execute("SELECT c.id, i.nome, c.realm, c.user_id, c.via FROM conta c JOIN instancia i "
                            "ON i.id=c.instancia_id WHERE c.investigacao_id=%s AND c.incluida", (inv_id,)).fetchall()
        for cid, inst, realm, uid, via in contas:
            fim = min(inv[1], cx.execute("SELECT max(fim_ms) FROM tarefa WHERE conta_id=%s", (cid,)).fetchone()[0]
                      or inv[1])
            if via == "realm":   # realm inteiro: eventos de contas localizadas ficam gravados sob a própria conta
                col = {r[0] for r in cx.execute("SELECT e.id FROM evento e JOIN instancia i ON i.id=e.instancia_id "
                                                "WHERE e.investigacao_id=%s AND i.nome=%s AND e.realm=%s",
                                                (inv_id, inst, realm))}
            else:
                col = {r[0] for r in cx.execute("SELECT id FROM evento WHERE conta_id=%s", (cid,))}
            with psycopg.connect(f"postgresql://postgres@127.0.0.1/{KCDB[inst]}") as kc:
                rid, exp = kc.execute("SELECT id, events_expiration FROM realm WHERE name=%s", (realm,)).fetchone()
                sql = "SELECT id FROM event_entity WHERE realm_id=%s AND event_time>=%s AND event_time<%s"
                a = [rid, inv[0] - base, fim]
                if via == "varredura":
                    sql += " AND user_id IS NULL AND type='LOGIN_ERROR' AND details_json ~ %s"
                    a.append(r'"username":"(' + ALVO + '|' + f"{ALVO[:3]}\\.{ALVO[3:6]}\\.{ALVO[6:9]}-{ALVO[9:]}" + ')"')
                elif uid:
                    sql += " AND user_id=%s"; a.append(uid)
                ref = {r[0] for r in kc.execute(sql, a)}
                agora = int(time.time() * 1000)
            faltando, extras = ref - col, col - ref
            # extras só são aceitáveis se expiraram (expurgo) depois de coletados
            extras_exp = 0
            if extras and exp:
                with aud() as cx2:
                    extras_exp = cx2.execute("SELECT count(*) FROM evento WHERE investigacao_id=%s AND id = ANY(%s) AND "
                                             "time_ms < %s", (inv_id, list(extras), agora - exp * 1000 + 600_000)
                                             ).fetchone()[0]
            ok = not faltando and len(extras) == extras_exp
            out.append({"instancia": inst, "realm": realm, "via": via, "coletados": len(col), "sql": len(ref),
                        "faltando": len(faltando), "extras": len(extras), "extras_expirados": extras_exp, "ok": ok})
    return out


def registrar(nome, ok, **dados):
    R["criterios"][nome] = {"ok": bool(ok), **dados}
    print(f"[{'OK ' if ok else 'FALHA'}] {nome}: {json.dumps(dados, ensure_ascii=False, default=str)[:600]}",
          flush=True)
    (RAIZ / "dados/resultados_aceite.json").write_text(json.dumps(R, ensure_ascii=False, indent=1, default=str))


def max_req_por_s(inv_id):
    with aud() as cx:
        return {r[0]: r[1] for r in cx.execute("""
            SELECT i.nome, max(n) FROM (SELECT instancia_id, count(*) OVER (PARTITION BY instancia_id ORDER BY inicio
                RANGE BETWEEN CURRENT ROW AND interval '999 milliseconds' FOLLOWING) n FROM requisicao
                WHERE investigacao_id=%s) x JOIN instancia i ON i.id=x.instancia_id GROUP BY 1""", (inv_id,))}


def main():
    de180 = (HOJE - timedelta(days=180)).isoformat()
    de60 = (HOJE - timedelta(days=60)).isoformat()
    ate = HOJE.isoformat()

    # ---------------- A: investigação principal (2 instâncias, 180 dias, varredura) ----------------
    t0 = time.time()
    cli("investigar", "--cpf", ALVO, "--de", de180, "--ate", ate, "--operador", "auditor.teste",
        "--justificativa", "Teste de aceite - processo 0001/2026", "--varredura", "--instancias", "kc26,rhsso")
    inv = ultima_inv()
    dur = time.time() - t0
    comp = comparar(inv)
    registrar("1_contagem_independente", all(c["ok"] for c in comp), investigacao=inv, duracao_s=round(dur),
              contas=comp)
    with aud() as cx:
        cob = cx.execute("SELECT i.nome, realm, classe, status FROM cobertura c JOIN instancia i ON "
                         "i.id=c.instancia_id WHERE investigacao_id=%s ORDER BY 1,2", (inv,)).fetchall()
    rh = [c for c in cob if c[1] == "rh"]
    registrar("3_eventos_desligados", any(c[2] in ("coberto",) and c[3] == "pesquisado_sem_conta" for c in rh) or
              any(c[2] == "sem_dados" for c in rh), cobertura=cob,
              observacao="rh tem eventos desligados; sem conta do alvo, o realm aparece 'pesquisado, sem conta'")
    registrar("4_realm_esperado_invisivel", any(c[1] == "parceiros" and c[3] == "esperado_invisivel" for c in cob),
              realm="kc26/parceiros")
    mx = max_req_por_s(inv)
    registrar("10_orcamento_de_carga", all(v <= 5 for v in mx.values()), max_req_em_1s=mx, orcamento=5)

    # ---------------- 7/8/9: exportação, verificação e trilha ----------------
    out = cli("exportar", "--id", str(inv), "--saida", "saida", "--operador", "auditor.teste")
    zp = RAIZ / f"saida/investigacao_{inv}.zip"
    ver = cli("verificar", str(zp), "--chave-publica", "chaves/assinatura.pub.pem")
    # adulteração: altera uma célula no CSV dentro do pacote
    adult = RAIZ / "saida/adulterado.zip"
    with zipfile.ZipFile(zp) as zi, zipfile.ZipFile(adult, "w") as zo:
        for n in zi.namelist():
            b = zi.read(n)
            if n.startswith("eventos_"):
                b = b.replace(b"Login", b"Logim", 1)
            zo.writestr(n, b)
    p = subprocess.run([sys.executable, "-m", "auditor", "verificar", str(adult), "--chave-publica",
                        "chaves/assinatura.pub.pem"], cwd=RAIZ, env=ENV, capture_output=True, text=True)
    # pacote sem máscara (com eventos brutos) reproduz o hash; um evento alterado invalida
    cli("exportar", "--id", str(inv), "--saida", "saida", "--operador", "supervisor.teste", "--sem-mascara")
    zs = RAIZ / f"saida/investigacao_{inv}_sem_mascara.zip"
    ver2 = cli("verificar", str(zs), "--chave-publica", "chaves/assinatura.pub.pem")
    adult2 = RAIZ / "saida/adulterado2.zip"
    with zipfile.ZipFile(zs) as zi, zipfile.ZipFile(adult2, "w") as zo:
        for n in zi.namelist():
            b = zi.read(n)
            if n == "eventos.jsonl":
                b = b.replace(b'"LOGIN"', b'"LOGOUT"', 1)
            zo.writestr(n, b)
    p2 = subprocess.run([sys.executable, "-m", "auditor", "verificar", str(adult2), "--chave-publica",
                         "chaves/assinatura.pub.pem"], cwd=RAIZ, env=ENV, capture_output=True, text=True)
    registrar("8_manifesto_verificavel", p.returncode != 0 and p2.returncode != 0 and "FALHA" not in ver + ver2,
              verificacao_ok=ver.strip().splitlines(), adulterado_csv=p.stdout.strip().splitlines()[-1:],
              adulterado_evento=p2.stdout.strip().splitlines()[-1:])
    # XLSX: abre no openpyxl e converte no LibreOffice; CSV com BOM e ';'
    from openpyxl import load_workbook
    xl = RAIZ / f"saida/investigacao_{inv}.xlsx"
    wb = load_workbook(xl)
    abas = wb.sheetnames
    tipos = type(wb["Eventos detalhados"]["A2"].value).__name__
    lo = subprocess.run(["soffice", "--headless", "--convert-to", "csv", "--outdir", "/tmp/lo", str(xl)],
                        capture_output=True, text=True, timeout=180)
    with zipfile.ZipFile(zp) as z:
        csvb = z.read(f"eventos_{inv}.csv")
    registrar("7_planilhas", tipos == "datetime" and lo.returncode == 0 and csvb.startswith(b"\xef\xbb\xbf")
              and b";" in csvb[:200] and "Leia-me" in abas, abas=abas, tipo_coluna_data=tipos,
              libreoffice=lo.stdout.strip()[-200:])
    with aud() as cx:
        acoes = [r[0] for r in cx.execute("SELECT DISTINCT acao FROM trilha_auditoria WHERE investigacao_id=%s",
                                          (inv,))]
        try:
            cx.execute("UPDATE trilha_auditoria SET operador='x' WHERE investigacao_id=%s", (inv,))
            bloqueado = False
        except psycopg.Error:
            bloqueado = True
    registrar("9_trilha", {"abrir_investigacao", "preparar_investigacao", "exportar", "exportar_sem_mascara"} <=
              set(acoes) and bloqueado, acoes=acoes, update_bloqueado=bloqueado)

    # ---------------- 2: kill -9 no meio e retomada (realm inteiro, ~390 mil e ~470 mil eventos) ----------------
    instancia("kc26-carga", 8126, conc=4, rps=40)
    instancia("rhsso-carga", 8118, base="/auth", conc=4, rps=40)
    for inst, realm, espera in (("kc26-carga", "intranet", 60), ("rhsso-carga", "legado", 30)):
        t0 = time.time()
        p = cli("investigar", "--cpf", ALVO, "--de", de180, "--ate", ate, "--operador", "auditor.teste",
                "--justificativa", "Teste de carga - realm inteiro", "--instancias", inst,
                "--conta", f"{inst}:{realm}:*", bg=True)
        time.sleep(espera)
        os.kill(p.pid, signal.SIGKILL)
        p.wait()
        inv2 = ultima_inv()
        with aud() as cx:
            antes = cx.execute("SELECT count(*) FROM evento WHERE investigacao_id=%s", (inv2,)).fetchone()[0]
            st = dict(cx.execute("SELECT status, count(*) FROM tarefa WHERE investigacao_id=%s GROUP BY 1",
                                 (inv2,)).fetchall())
            # a retomada só reaproveita tarefas com lease vencido: simula a passagem do tempo
            cx.execute("UPDATE tarefa SET lease_ate = now() - interval '1 second' WHERE investigacao_id=%s "
                       "AND status='executando'", (inv2,))
        cli("retomar", "--id", str(inv2))
        comp = comparar(inv2)
        conta_realm = [c for c in comp if c["via"] == "realm"]
        registrar(f"2_kill9_retomada_{inst}", all(c["ok"] for c in conta_realm), investigacao=inv2,
                  eventos_antes_do_kill=antes, tarefas_no_kill=st, resultado=conta_realm,
                  duracao_total_s=round(time.time() - t0))

    # ---------------- 5: variantes de comportamento detectadas pelas sondas ----------------
    variantes = {}
    for nome, porta in (("kc26-bugdateto", 8127), ("kc26-semdir", 8128), ("kc26-curinga", 8129)):
        s = instancia(nome, porta)
        cli("investigar", "--cpf", ALVO, "--de", de60, "--ate", ate, "--operador", "auditor.teste",
            "--justificativa", f"Teste de sonda {nome}", "--instancias", nome)
        comp = comparar(ultima_inv())
        variantes[nome] = {"modo": s.get("modo"), "sem_dateTo": s.get("sem_dateTo"), "S3": s.get("S3_direction"),
                           "S4": s.get("S4_exact"), "ok": all(c["ok"] for c in comp),
                           "eventos": sum(c["coletados"] for c in comp)}
    variantes["rhsso (18.0.2)"] = {"modo": instancia("rhsso", 8118, base="/auth", esperados="portal-cidadao,legado,rh")
                                   .get("modo"), "ok": R["criterios"]["1_contagem_independente"]["ok"]}
    esperado = {"kc26-bugdateto": ("epoch_asc", True), "kc26-semdir": ("epoch_desc", None),
                "kc26-curinga": ("epoch_asc", None)}
    registrar("5_sondas_e_modos", all(v["ok"] for v in variantes.values()) and
              all(variantes[k]["modo"] == m and (sd is None or variantes[k]["sem_dateTo"] == sd)
                  for k, (m, sd) in esperado.items()) and variantes["rhsso (18.0.2)"]["modo"] == "dia",
              variantes=variantes)

    # ---------------- 6: expurgo rodando durante a coleta ----------------
    instancia("kc26-purga", 8130, conc=4, rps=40)
    cli("investigar", "--cpf", ALVO, "--de", de180, "--ate", ate, "--operador", "auditor.teste",
        "--justificativa", "Teste de expurgo durante a coleta", "--instancias", "kc26-purga",
        "--conta", "kc26-purga:servicos:*")
    inv6 = ultima_inv()
    comp = [c for c in comparar(inv6) if c["via"] == "realm"]
    with aud() as cx:
        rel = dict(cx.execute("SELECT coalesce(releitura,'(sem releitura)'), count(*) FROM tarefa WHERE "
                              "investigacao_id=%s GROUP BY 1", (inv6,)).fetchall())
    registrar("6_expurgo_durante_coleta", all(c["ok"] for c in comp), investigacao=inv6, resultado=comp,
              releituras=rel)
    R["fim"] = datetime.now(timezone.utc).isoformat()
    (RAIZ / "dados/resultados_aceite.json").write_text(json.dumps(R, ensure_ascii=False, indent=1, default=str))
    print("TODOS OK" if all(c["ok"] for c in R["criterios"].values()) else "HÁ FALHAS")


if __name__ == "__main__":
    main()

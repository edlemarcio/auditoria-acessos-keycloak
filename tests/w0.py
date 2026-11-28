"""Critérios de aceite da etapa W-0 (docs/PROPOSTA_WEB.md, §1.2 e §11) contra a stack real.

  AUDITOR_DSN=<papel dono> AUDITOR_DSN_APP=<kc_auditor_app> python tests/w0.py <investigacao>

D1  o pacote mascarado não contém o identificador do alvo (nenhuma variante) nem userId em nenhum arquivo
D2  eventos.jsonl e o total do manifesto seguem as contas incluídas; as excluídas aparecem no manifesto
D3  o manifesto só traz snapshots lidos pela própria investigação
D4  cifras no formato v2 com contexto da linha; trocar o cifrado de linha faz a decifração falhar; HMAC v2
D5  a trilha recusa TRUNCATE; o papel da aplicação não altera a trilha nem faz DDL
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path

import psycopg
from psycopg.rows import dict_row

RAIZ = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(RAIZ))
from auditor import chaves, cripto  # noqa: E402
from auditor.identificador import variantes  # noqa: E402

DSN = os.environ["AUDITOR_DSN"]
DSN_APP = os.environ.get("AUDITOR_DSN_APP")
falhas: list[str] = []


def checar(ok: bool, nome: str, detalhe: str = ""):
    print(f"{'OK   ' if ok else 'FALHA'} {nome}{(' — ' + detalhe) if detalhe else ''}")
    if not ok:
        falhas.append(nome)


def exportar(inv: int, saida: Path, sem_mascara=False, dsn=DSN) -> Path:
    cmd = [sys.executable, "-m", "auditor", "exportar", "--id", str(inv), "--saida", str(saida),
           "--operador", "teste-w0", "--formato", "1"] + (["--sem-mascara"] if sem_mascara else [])   # regressão do v1
    subprocess.run(cmd, check=True, cwd=RAIZ, env={**os.environ, "AUDITOR_DSN": dsn, "AUDITOR_MODO": "local"}, capture_output=True)
    return saida / f"investigacao_{inv}{'_sem_mascara' if sem_mascara else ''}.zip"


def verificar(zp: Path) -> bool:
    r = subprocess.run([sys.executable, "-m", "auditor", "verificar", str(zp), "--chave-publica",
                        str(RAIZ / "chaves/assinatura.pub.pem")], cwd=RAIZ, capture_output=True, text=True,
                       env={**os.environ, "AUDITOR_MODO": "local"})
    return r.returncode == 0


def main(inv: int):
    cx = psycopg.connect(DSN, autocommit=True, row_factory=dict_row)
    i = cx.execute("SELECT * FROM investigacao WHERE id=%s", (inv,)).fetchone()
    dig = chaves.alvo(i, "exportar")
    user_ids = [r["user_id"] for r in cx.execute(
        "SELECT user_id FROM conta WHERE investigacao_id=%s AND user_id IS NOT NULL", (inv,))]
    tmp = Path(tempfile.mkdtemp(prefix="w0_"))

    # ---- D1
    zp = exportar(inv, tmp)
    achados = {}
    with zipfile.ZipFile(zp) as z:
        for nome in z.namelist():
            dados = z.read(nome)
            if nome.endswith(".xlsx"):   # XLSX é zip: procura nas partes XML
                import io
                with zipfile.ZipFile(io.BytesIO(dados)) as x:
                    dados = b"".join(x.read(n) for n in x.namelist())
            texto = dados.decode("utf-8", errors="replace")
            for v in variantes(i["tipo"], dig):
                if v in texto:
                    achados.setdefault(nome, set()).add("identificador")
            if nome == "requisicoes.jsonl" and any(u in texto for u in user_ids):
                achados.setdefault(nome, set()).add("userId")
        m = json.loads(z.read("manifesto.json"))
    checar(not achados, "D1 pacote mascarado sem identificador do alvo e sem userId nas requisições",
           str(achados) if achados else zp.name)
    checar(m["requisicoes"].get("redigido") is True, "D1 manifesto marca requisicoes.jsonl como redigido")
    checar(verificar(zp), "D1 pacote mascarado verifica")

    # ---- D2: exclui temporariamente a conta com mais eventos
    alvo_c = cx.execute("SELECT c.id, count(e.*) n FROM conta c JOIN evento e ON e.conta_id=c.id "
                        "WHERE c.investigacao_id=%s AND c.incluida GROUP BY c.id ORDER BY n DESC LIMIT 1",
                        (inv,)).fetchone()
    total = cx.execute("SELECT count(*) n FROM evento e JOIN conta c ON c.id=e.conta_id "
                       "WHERE e.investigacao_id=%s AND c.incluida", (inv,)).fetchone()["n"]
    cx.execute("UPDATE conta SET incluida=false WHERE id=%s", (alvo_c["id"],))
    try:
        zs = exportar(inv, tmp, sem_mascara=True)
        with zipfile.ZipFile(zs) as z:
            linhas = [x for x in z.read("eventos.jsonl").splitlines() if x]
            ms = json.loads(z.read("manifesto.json"))
        esperado = total - alvo_c["n"]
        checar(len(linhas) == esperado == ms["eventos"]["total"], "D2 eventos.jsonl e manifesto sem a conta excluída",
               f"{len(linhas)} linhas, manifesto {ms['eventos']['total']}, esperado {esperado}")
        exc = [c for c in ms["contas_excluidas"] if c["id"] == alvo_c["id"]]
        checar(len(exc) == 1 and exc[0]["eventos"] == alvo_c["n"], "D2 conta excluída listada no manifesto com a "
               "contagem de eventos", str(exc))
        checar(verificar(zs), "D2 pacote sem máscara verifica")
    finally:
        cx.execute("UPDATE conta SET incluida=true WHERE id=%s", (alvo_c["id"],))

    # ---- D3
    proprios = cx.execute("SELECT count(*) n FROM realm_snapshot WHERE investigacao_id=%s", (inv,)).fetchone()["n"]
    outros = cx.execute("SELECT count(*) n FROM realm_snapshot WHERE investigacao_id IS DISTINCT FROM %s",
                        (inv,)).fetchone()["n"]
    if proprios:
        checar(len(m["snapshots"]) == proprios, "D3 manifesto só com os snapshots da investigação",
               f"{len(m['snapshots'])} no manifesto, {proprios} da investigação, {outros} de outras/antigos")
    else:   # investigação anterior à 0.2.0: snapshots sem vínculo, na janela entre criação e conclusão
        janela = cx.execute("SELECT count(*) n FROM realm_snapshot WHERE investigacao_id IS NULL AND lido_em >= %s "
                            "AND lido_em <= COALESCE(%s, now())", (i["criado_em"], i["concluido_em"])).fetchone()["n"]
        checar(i["concluido_em"] is not None and len(m["snapshots"]) == janela,
               "D3 (investigação anterior à 0.2.0) manifesto só com os snapshots da janela da investigação",
               f"{len(m['snapshots'])} no manifesto, {janela} na janela, {outros} no total")

    # ---- D4
    # a partir da W0b o alvo fica cifrado com a DEK da investigação (formato v3, AAD por linha)
    checar(bytes(i["alvo_cifrado"])[:1] == cripto.V3, "D4 alvo cifrado com a DEK da investigação (v3)")
    checar(i["alvo_hmac"] == cripto.hmac_alvo(i["tipo"], dig) != cripto.hmac_alvo_v1(i["tipo"], dig),
           "D4 HMAC do alvo com chave derivada (diferente da chave de cifra)")
    try:
        cripto.decifrar_dek(chaves.dek(i["id"], "exportar"), i["alvo_cifrado"],
                            cripto.aad(i["id"], "investigacao", "alvo_cifrado", i["id"] + 1))
        trocado = False
    except Exception:  # noqa: BLE001
        trocado = True
    checar(trocado, "D4 cifrado não decifra com o contexto de outra linha")

    # ---- D5
    try:
        with cx.transaction():
            cx.execute("TRUNCATE trilha_auditoria")
        checar(False, "D5 TRUNCATE na trilha recusado")
    except psycopg.Error as e:
        checar("somente inserção" in str(e), "D5 TRUNCATE na trilha recusado pelo trigger", type(e).__name__)
    if DSN_APP:
        app = psycopg.connect(DSN_APP, autocommit=True)
        for sql, nome in [("UPDATE trilha_auditoria SET acao=acao WHERE id=(SELECT min(id) FROM trilha_auditoria)",
                           "UPDATE"), ("TRUNCATE trilha_auditoria", "TRUNCATE"),
                          ("CREATE TABLE w0_teste (x int)", "DDL")]:
            try:
                app.execute(sql)
                checar(False, f"D5 papel da aplicação recusado em {nome}")
            except psycopg.errors.InsufficientPrivilege:
                checar(True, f"D5 papel da aplicação recusado em {nome}")
        zp_app = exportar(inv, tmp / "app", dsn=DSN_APP)
        checar(verificar(zp_app), "D5 exportação funciona com o papel da aplicação")
    else:
        print("--    D5 papel da aplicação: defina AUDITOR_DSN_APP para testar")

    print(f"\n{'APROVADO' if not falhas else 'REPROVADO'}: {len(falhas)} falha(s)")
    sys.exit(1 if falhas else 0)


if __name__ == "__main__":
    main(int(sys.argv[1]))

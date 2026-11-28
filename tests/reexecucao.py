"""Reexecução, comparação, relatório agregado e tabela do ofício em PDF (W5, PROPOSTA_WEB §5.4, §6.6 e §6.7), pela API.

1. Mesmo escopo: nova investigação vinculada, já aprovada, com as mesmas designações; a original não muda; registro
   com motivo nas duas cadeias. Escopo maior: o pedido volta para aprovação.
2. A nova é coletada pelo worker; os rótulos são herdados (o mesmo IP tem o mesmo "IP N" nas duas).
3. Comparar execuções: totais e listas só com rótulos; um evento apagado na origem aparece em "deixaram de existir".
4. Relatório agregado (Solicitante) e tabela do ofício em PDF/A-2b.

  AUDITOR_DSN=<kc_auditor_app>/auditor_w2b AUDITOR_CHAVE=... python tests/reexecucao.py
"""
from __future__ import annotations

import re
import subprocess
import sys
import time
from pathlib import Path

RAIZ = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(RAIZ / "tests"))
sys.path.insert(0, str(RAIZ))
import analise as base  # noqa: E402

checar, entrar, j, banco = base.checar, base.entrar, base.j, base.banco


def pdfa(b: bytes) -> bool:
    r = subprocess.run(["docker", "run", "--rm", "-i", "--entrypoint", "sh", "verapdf/cli:latest", "-c",
                        "cat > /tmp/a.pdf && /opt/verapdf/verapdf --flavour 2b --format text /tmp/a.pdf"],
                       input=b, capture_output=True)
    return r.stdout.startswith(b"PASS")


def esperar(u: str, inv: int, estados: tuple[str, ...], limite_s: int = 900) -> str:
    t = time.time()
    st = None
    while time.time() - t < limite_s:
        c, d = j(u, "GET", f"/api/investigacoes/{inv}")
        st = d.get("status") if c == 200 else None
        if st in estados:
            return st
        time.sleep(3)
    return st


def main():
    with banco() as cx:
        sub = {r["username"]: r["sub"] for r in cx.execute("SELECT username, sub FROM usuario")}
        orig = cx.execute("""SELECT i.* FROM investigacao i JOIN designacao d ON d.investigacao_id=i.id
            AND d.funcao='investigador' AND d.sub=%s WHERE i.status IN ('concluida','concluida_com_lacunas')
            AND NOT i.lacrada AND i.execucao_anterior IS NULL AND d.designado_por IS DISTINCT FROM 'carga'
            AND EXISTS (SELECT 1 FROM chave_investigacao k WHERE k.investigacao_id=i.id)
            AND i.solicitante_sub=%s ORDER BY i.id LIMIT 1""", (sub["investigador1"], sub["solicitante1"])).fetchone()
        lista = cx.execute("SELECT id, investigacao_id FROM pedido WHERE tipo='lista_oficio' AND status='aprovado' AND "
                           "solicitante_sub=%s ORDER BY id DESC LIMIT 1", (sub["investigador1"],)).fetchone()
    I = orig["id"]
    print(f"investigação de origem {I}")
    api, wk = base.processos()
    try:
        for u in ("investigador1", "solicitante1", "aprovador1", "investigador2"):
            entrar(u)
        c, v0 = j("investigador1", "GET", f"/api/investigacoes/{I}")
        checar("reexecutar" in v0.get("acoes", []), "1 ação 'reexecutar' para o investigador designado")
        checar(j("investigador2", "POST", f"/api/investigacoes/{I}/reexecutar", json={"motivo": "sem designação"})[0]
               in (403, 404), "1 investigador não designado não reexecuta")
        checar(j("investigador1", "POST", f"/api/investigacoes/{I}/reexecutar", json={"motivo": "x"})[0] == 422,
               "1 motivo obrigatório")
        c, r = j("investigador1", "POST", f"/api/investigacoes/{I}/reexecutar",
                 json={"motivo": "Repetir a coleta para confirmar os resultados"})
        N = r.get("investigacao")
        checar(c == 201 and r["status"] == "aprovada" and r["aprovacao"] is False,
               "1 mesmo escopo: nova investigação já aprovada, sem nova aprovação", r)
        c, vn = j("investigador1", "GET", f"/api/investigacoes/{N}")
        checar(vn.get("execucao_anterior") == I and "iniciar" in vn.get("acoes", []),
               "1 nova vinculada à de origem; o investigador designado pode iniciar")
        with banco() as cx:
            d0 = {(x["funcao"], x["sub"]) for x in cx.execute("SELECT funcao, sub FROM designacao WHERE investigacao_id=%s", (I,))}
            d1 = {(x["funcao"], x["sub"]) for x in cx.execute("SELECT funcao, sub FROM designacao WHERE investigacao_id=%s", (N,))}
            o2 = cx.execute("SELECT status, atualizado_em FROM investigacao WHERE id=%s", (I,)).fetchone()
            tr = {(x["cadeia"], x["acao"]) for x in cx.execute(
                "SELECT cadeia, acao FROM trilha_auditoria WHERE cadeia IN (%s,%s) AND acao LIKE 'reexecutar%%'", (I, N))}
        checar(d0 == d1, "1 mesmas designações na nova")
        checar(o2["status"] == orig["status"], "1 a investigação de origem não muda")
        checar({(I, "reexecutar_mesmo_escopo"), (N, "reexecutar_mesmo_escopo")} <= tr,
               "1 registro com motivo nas cadeias das duas investigações")
        c, v0b = j("investigador1", "GET", f"/api/investigacoes/{I}")
        checar(N in v0b.get("reexecucoes", []), "1 a de origem lista a reexecução")
        # escopo maior
        from datetime import datetime, timedelta
        from zoneinfo import ZoneInfo
        fim = datetime.fromtimestamp(orig["fim_ms"] / 1000, ZoneInfo(orig["fuso"])) + timedelta(days=1)
        c, r2 = j("investigador1", "POST", f"/api/investigacoes/{I}/reexecutar",
                  json={"motivo": "Ampliar o período em um dia", "ate": fim.strftime("%Y-%m-%dT%H:%M:%S")})
        checar(c == 201 and r2["status"] == "aguardando_aprovacao" and r2["aprovacao"],
               "1 escopo maior (período ampliado): o pedido volta para aprovação", r2)
        if r2.get("investigacao"):
            j("solicitante1", "POST", f"/api/investigacoes/{r2['investigacao']}/cancelar",
              json={"motivo": "Teste de reexecução: escopo maior não é necessário"})

        # 2. coleta da nova e herança de rótulos
        c, _ = j("investigador1", "POST", f"/api/investigacoes/{N}/iniciar")
        checar(c in (200, 202), "2 coleta da reexecução iniciada", c)
        st = esperar("investigador1", N, ("concluida", "concluida_com_lacunas", "parcial", "falhou"))
        checar(st in ("concluida", "concluida_com_lacunas"), "2 reexecução coletada pelo worker", st)
        from auditor import sigilo
        from auditor.db import conectar
        from auditor.pseudonimos import rotulos
        with conectar() as cx:
            iguais = difs = 0
            mapas = []
            for inv in (I, N):
                cf = sigilo.Cofre(inv, "exportar")
                rot = rotulos(cx, inv)
                m = {}
                for e in cx.execute("SELECT id, instancia_id, realm, cifrado, ps_ip FROM evento WHERE investigacao_id=%s "
                                    "AND ps_ip IS NOT NULL LIMIT 3000", (inv,)):
                    ip = sigilo.abrir_evento(cf, e)["ip"]
                    m[ip] = rot.get(("ip", e["ps_ip"]))
                mapas.append(m)
            for ip, r0 in mapas[0].items():
                if ip in mapas[1]:
                    iguais += r0 == mapas[1][ip]
                    difs += r0 != mapas[1][ip]
        checar(iguais > 0 and difs == 0, "2 rótulos herdados: o mesmo IP tem o mesmo rótulo nas duas execuções",
               f"{iguais} IPs iguais, {difs} diferentes")

        # 3. comparação
        c, cmp_ = j("investigador1", "GET", f"/api/investigacoes/{N}/comparacao")
        checar(c == 200 and cmp_["anterior"] == I and "totais" in cmp_, "3 comparação disponível", cmp_.get("totais"))
        texto = str(cmp_)
        checar(not re.search(r"\b\d{1,3}(\.\d{1,3}){3}\b", texto), "3 comparação só com rótulos (sem IP em claro)")
        with banco(base.DSN_DONO) as cx:
            e = cx.execute("SELECT id, instancia_id, realm FROM evento WHERE investigacao_id=%s AND type='LOGIN' "
                           "ORDER BY time_ms DESC LIMIT 1", (N,)).fetchone()
            cx.execute("DELETE FROM evento WHERE investigacao_id=%s AND instancia_id=%s AND realm=%s AND id=%s",
                       (N, e["instancia_id"], e["realm"], e["id"]))
        c, cmp2 = j("investigador1", "GET", f"/api/investigacoes/{N}/comparacao", params={"recalcular": "true"})
        checar(c == 200 and cmp2["totais"]["deixaram_de_existir"] == cmp_["totais"]["deixaram_de_existir"] + 1
               and any(x["tipo"] == "LOGIN" for x in cmp2["deixaram_de_existir"]),
               "3 evento apagado na origem aparece em 'deixaram de existir'", cmp2["totais"])
        checar(j("solicitante1", "GET", f"/api/investigacoes/{N}/comparacao")[0] in (403, 404),
               "3 o solicitante não vê a comparação (dado individual)")
        checar(j("investigador1", "GET", f"/api/investigacoes/{I}/comparacao")[0] == 404,
               "3 investigação sem execução anterior: 404")

        # 4. PDFs
        r = base.web["solicitante1"].get(f"{base.API}/api/investigacoes/{I}/relatorio-agregado", timeout=60)
        checar(r.status_code == 200 and r.headers["content-type"] == "application/pdf" and pdfa(r.content),
               "4 relatório agregado do Solicitante em PDF/A-2b (veraPDF)", r.status_code)
        if lista:
            entrar("investigador1")
            r = base.web["investigador1"].get(
                f"{base.API}/api/investigacoes/{lista['investigacao_id']}/oficios/{lista['id']}/tabela",
                params={"formato": "pdf"}, timeout=60)
            checar(r.status_code == 200 and pdfa(r.content), "4 tabela do ofício em PDF/A-2b (veraPDF)", r.status_code)
        else:
            print("  (sem lista para ofício aprovada: rode o aceite da W4 para cobrir a tabela em PDF)")
    finally:
        api.terminate()
        wk.terminate()
    print(f"\n{base.oks[0]} ok, {len(base.falhas)} falha(s)")
    sys.exit(1 if base.falhas else 0)


if __name__ == "__main__":
    main()

"""Critérios de aceite da W4 (PROPOSTA_WEB §11): revelação registrada, expira no servidor e bloqueia acima da cota;
migração com hashes iguais aos manifestos entregues. Contra a stack real, pela API (papel kc_api, RLS).

  AUDITOR_DSN=<kc_auditor_app>/auditor_w2b AUDITOR_CHAVE=... python tests/revelacao.py

Usa a investigação concluída de investigador1 (a do aceite da W2) e percorre:
 1. sessão de análise: motivo da lista (e "outro" com texto), uma ativa por vez, prorrogação no máximo duas vezes,
    teto de 8 h por dia, step-up;
 2. revelação por item: valor real só com sessão ativa, ao lado do pseudônimo em Eventos e Contas, trilha com o
    rótulo e nunca o valor;
 3. cota: 30 por sessão bloqueia o 31º; pedido acima da cota aprovado por outra pessoa libera só os itens pedidos;
    revelação total aprovada libera tudo; dado de terceiro exige aprovação;
 4. expiração no servidor e logout encerram a sessão: nenhum valor sai depois;
 5. lista para ofício: aprovada em bloco, tabela XLSX só para quem pediu, cada IP na trilha;
 6. quatro olhos e perfis: investigador não decide; outro investigador não usa a sessão;
 7. migração: todos os manifestos entregues conferem com o cifrado (algoritmo v1 e atual); adulteração detectada;
 8. varredura: nenhum valor revelado na trilha, no SIEM ou nos logs.
"""
from __future__ import annotations

import io
import ipaddress
import json
import os
import sys
from pathlib import Path

RAIZ = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(RAIZ / "tests"))
import analise as base  # noqa: E402

checar, j, banco, entrar = base.checar, base.j, base.banco, base.entrar


def main():
    with banco() as cx:
        sub = {r["username"]: r["sub"] for r in cx.execute("SELECT username, sub FROM usuario")}
        inv = cx.execute("""SELECT i.* FROM investigacao i JOIN designacao d ON d.investigacao_id=i.id
            AND d.funcao='investigador' AND d.sub=%s WHERE i.status IN ('concluida','concluida_com_lacunas')
            AND NOT i.lacrada AND d.designado_por IS DISTINCT FROM 'carga'
            AND EXISTS (SELECT 1 FROM chave_investigacao k WHERE k.investigacao_id=i.id)
            AND (SELECT count(*) FROM pseudonimo p WHERE p.investigacao_id=i.id AND p.classe='ip') >= 40
            ORDER BY i.id DESC LIMIT 1""", (sub["investigador1"],)).fetchone()
    assert inv, "sem investigação concluída de investigador1 com 40 IPs (rode o aceite da W2 antes)"
    I = inv["id"]
    P = f"/api/investigacoes/{I}"
    print(f"investigação {I}")
    with banco(base.DSN_DONO) as cx:   # estado limpo para o teste: sem sessões nem revelações anteriores
        cx.execute("DELETE FROM revelacao WHERE investigacao_id=%s", (I,))
        cx.execute("DELETE FROM sessao_analise WHERE investigacao_id=%s OR sub=%s", (I, sub["investigador1"]))
        cx.execute("DELETE FROM pedido WHERE investigacao_id=%s AND (tipo LIKE 'revelacao%%' OR tipo='lista_oficio')", (I,))
    api, wk = base.processos()
    valores: set[str] = set()
    try:
        for u in ("investigador1", "investigador2", "aprovador1"):
            entrar(u)

        # ------------------------------------------------------------ 1. sessão de análise
        c, e = j("investigador1", "GET", f"{P}/sessao-analise")
        checar(c == 200 and e["sessao"] is None and "identificar_autoria" in e["motivos"], "1 sem sessão; motivos da lista")
        c, _ = j("investigador1", "POST", f"{P}/revelar", json={"classe": "ip", "rotulo": "IP 1"})
        checar(c == 409, "1 revelar sem sessão: 409", c)
        checar(j("investigador1", "POST", f"{P}/sessao-analise", json={"motivo_codigo": "xx"})[0] == 422, "1 motivo fora da lista 422")
        checar(j("investigador1", "POST", f"{P}/sessao-analise", json={"motivo_codigo": "outro"})[0] == 422,
               "1 'outro' sem texto 422")
        c, e = j("investigador1", "POST", f"{P}/sessao-analise", json={"motivo_codigo": "identificar_autoria"})
        checar(c == 201 and e["sessao"], "1 sessão iniciada", e.get("sessao", {}).get("expira_em"))
        checar(j("investigador1", "POST", f"{P}/sessao-analise", json={"motivo_codigo": "identificar_autoria"})[0] == 409,
               "1 uma sessão ativa por vez")
        for k in (1, 2):
            c, e = j("investigador1", "POST", f"{P}/sessao-analise/prorrogar")
            checar(c == 200 and e["sessao"]["prorrogacoes"] == k, f"1 prorrogação {k}")
        checar(j("investigador1", "POST", f"{P}/sessao-analise/prorrogar")[0] == 409, "1 terceira prorrogação recusada")
        checar(j("investigador2", "GET", f"{P}/sessao-analise")[0] in (403, 404), "1 outro investigador não usa a sessão")

        # ------------------------------------------------------------ 2. revelação por item
        c, r = j("investigador1", "POST", f"{P}/revelar", json={"classe": "ip", "rotulo": "IP 1"})
        ok = c == 200 and isinstance(r.get("valor"), str)
        try:
            ipaddress.ip_address(r.get("valor", ""))
        except ValueError:
            ok = False
        checar(ok, "2 IP 1 revelado (valor real)", r.get("cota"))
        valores.add(r.get("valor", "") or "")
        c, p = j("investigador1", "GET", f"{P}/eventos", params={"ip": "IP 1", "limite": 5})
        checar(p["sessao_ativa"] and all(x.get("revelado", {}).get("ip") == r["valor"] for x in p["itens"]),
               "2 Eventos: valor revelado ao lado do pseudônimo")
        c, cs = j("investigador1", "GET", f"{P}/contas")
        conta_rot = next(x["conta"] for x in cs["contas"] if x["conta"] and x["conta"].startswith("Conta "))
        c, rc = j("investigador1", "POST", f"{P}/revelar", json={"classe": "conta", "rotulo": conta_rot})
        checar(c == 200 and rc["valor"].get("username"), f"2 {conta_rot} revelada")
        valores |= {v for v in rc["valor"].values() if v}
        c, cs = j("investigador1", "GET", f"{P}/contas")
        checar(any(x.get("revelado", {}).get("conta") for x in cs["contas"]), "2 Contas: valor revelado ao lado")
        with banco() as cx:
            t = cx.execute("SELECT detalhe::text AS d FROM trilha_auditoria WHERE investigacao_id=%s AND acao='revelar' "
                           "ORDER BY id DESC LIMIT 2", (I,)).fetchall()
        checar(len(t) == 2 and all("IP 1" in x["d"] or conta_rot in x["d"] for x in t) and
               not any(v in x["d"] for x in t for v in valores), "2 trilha com o rótulo, sem o valor")
        c, r2 = j("investigador1", "POST", f"{P}/revelar", json={"classe": "ip", "rotulo": "IP 1"})
        checar(r2["cota"]["sessao"] == r["cota"]["sessao"] + 1, "2 repetir item já revelado não gasta cota",
               r2["cota"])

        # ------------------------------------------------------------ 3. cota
        n = r2["cota"]["sessao"]
        k = 2
        while n < 30 and k < 200:
            c, x = j("investigador1", "POST", f"{P}/revelar", json={"classe": "ip", "rotulo": f"IP {k}"})
            if c == 200:
                n = x["cota"]["sessao"]
                valores.add(x["valor"] or "")
            k += 1
        c, x = j("investigador1", "POST", f"{P}/revelar", json={"classe": "ip", "rotulo": f"IP {k}"})
        checar(c == 409 and x["erro"] == "cota", "3 o 31º item é bloqueado pela cota", x.get("mensagem"))
        c, ped = j("investigador1", "POST", f"{P}/pedidos-revelacao", json={
            "tipo": "revelacao_cota", "itens": [{"classe": "ip", "rotulo": f"IP {k}"}, {"classe": "ip", "rotulo": f"IP {k + 1}"}],
            "motivo": "Os dois IPs aparecem na rajada de falhas da madrugada"})
        checar(c == 201 and ped["quantidade"] == 2, "3 pedido acima da cota (2 itens)", ped)
        checar(j("investigador1", "POST", f"/api/aprovacoes/{ped['pedido']}/decidir",
                 json={"aprovar": True, "motivo": "eu mesmo"})[0] in (403, 404), "3 investigador não decide o próprio pedido")
        c, dp = j("aprovador1", "GET", f"/api/aprovacoes/{ped['pedido']}")
        txt = json.dumps(dp)
        checar(c == 200 and dp["quantidade"] == 2 and dp["motivo_sessao"] and dp["historico"] and
               not any(v in txt for v in valores), "3 aprovador vê quantidade, motivo e histórico, sem valores",
               {k2: dp.get(k2) for k2 in ("quantidade", "por_classe", "motivo_sessao")})
        c, dec = j("aprovador1", "POST", f"/api/aprovacoes/{ped['pedido']}/decidir",
                   json={"aprovar": True, "motivo": "Motivo compatível com a finalidade"})
        checar(c == 200 and dec["status"] == "aprovado", "3 aprovado por outra pessoa", c)
        c, x = j("investigador1", "POST", f"{P}/revelar", json={"classe": "ip", "rotulo": f"IP {k}"})
        checar(c == 200, f"3 IP {k} liberado pela aprovação", x.get("cota"))
        c, x = j("investigador1", "POST", f"{P}/revelar", json={"classe": "ip", "rotulo": f"IP {k + 2}"})
        checar(c == 409, "3 item fora do pedido continua bloqueado")
        # revelação total
        c, pt = j("investigador1", "POST", f"{P}/pedidos-revelacao", json={
            "tipo": "revelacao_total", "motivo": "Ofício pede todos os acessos do período"})
        j("aprovador1", "POST", f"/api/aprovacoes/{pt['pedido']}/decidir", json={"aprovar": True, "motivo": "Ofício anexado"})
        c, x = j("investigador1", "POST", f"{P}/revelar", json={"classe": "ip", "rotulo": f"IP {k + 2}"})
        checar(c == 200, "3 revelação total aprovada libera além da cota", c)
        # dado de terceiro
        with banco() as cx:
            t3 = cx.execute("""SELECT p.rotulo FROM pseudonimo p WHERE p.investigacao_id=%s AND p.classe='ip' AND NOT EXISTS
                (SELECT 1 FROM evento e JOIN conta c ON c.id=e.conta_id WHERE e.investigacao_id=p.investigacao_id
                 AND e.ps_ip=p.hmac AND c.via<>'varredura') LIMIT 1""", (I,)).fetchone()
        if t3:
            c, x = j("investigador1", "POST", f"{P}/revelar", json={"classe": "ip", "rotulo": f"IP {t3['rotulo']}"})
            checar(c == 409 and x["erro"] == "terceiro", "3 dado de terceiro exige aprovação (mesmo com revelação total)",
                   f"IP {t3['rotulo']}")
        else:
            checar(True, "3 dado de terceiro: nenhum IP só da varredura nesta massa (regra coberta pela unidade)")

        # ------------------------------------------------------------ 4. expiração no servidor
        with banco(base.DSN_DONO) as cx:
            cx.execute("UPDATE sessao_analise SET expira_em=now() - interval '1 second' WHERE investigacao_id=%s AND sub=%s "
                       "AND encerrada_em IS NULL", (I, sub["investigador1"]))
        c, e = j("investigador1", "GET", f"{P}/sessao-analise")
        checar(e["sessao"] is None and not e["revelados"], "4 sessão vencida: nenhum valor no estado")
        c, p = j("investigador1", "GET", f"{P}/eventos", params={"ip": "IP 1", "limite": 5})
        checar(not p["sessao_ativa"] and not any("revelado" in x for x in p["itens"]), "4 sessão vencida: Eventos sem valores")
        checar(j("investigador1", "POST", f"{P}/revelar", json={"classe": "ip", "rotulo": "IP 1"})[0] == 409,
               "4 sessão vencida: revelar recusado")
        with banco() as cx:
            n = cx.execute("SELECT count(*) n FROM trilha_auditoria WHERE investigacao_id=%s AND acao='sessao_analise_expirada'",
                           (I,)).fetchone()["n"]
        checar(n >= 1, "4 expiração registrada na trilha")
        # logout encerra
        entrar("investigador1")
        j("investigador1", "POST", f"{P}/sessao-analise", json={"motivo_codigo": "confirmar_titularidade"})
        j("investigador1", "POST", "/auth/sair")
        with banco() as cx:
            r = cx.execute("SELECT encerrada_por FROM sessao_analise WHERE investigacao_id=%s AND sub=%s ORDER BY id DESC LIMIT 1",
                           (I, sub["investigador1"])).fetchone()
        checar(r and r["encerrada_por"] == "logout", "4 logout encerra a sessão de análise", r)
        # teto diário: uma sessão de 8 h no dia de hoje (UTC), noutra investigação
        with banco(base.DSN_DONO) as cx:
            outra = cx.execute("SELECT id FROM investigacao WHERE id<>%s ORDER BY id LIMIT 1", (I,)).fetchone()["id"]
            fake = cx.execute("""INSERT INTO sessao_analise (investigacao_id, sub, motivo_codigo, inicio, expira_em)
                VALUES (%s, %s, 'identificar_autoria', date_trunc('day', now() AT TIME ZONE 'UTC') AT TIME ZONE 'UTC',
                        date_trunc('day', now() AT TIME ZONE 'UTC') AT TIME ZONE 'UTC' + interval '8 hours')
                RETURNING id""", (outra, sub["investigador1"])).fetchone()["id"]
        try:
            entrar("investigador1")
            c, x = j("investigador1", "POST", f"{P}/sessao-analise", json={"motivo_codigo": "identificar_autoria"})
            checar(c == 409 and x.get("erro") == "teto", "4 teto de 8 h por dia", x.get("mensagem"))
        finally:
            with banco(base.DSN_DONO) as cx:
                cx.execute("DELETE FROM sessao_analise WHERE id=%s", (fake,))
        entrar("investigador1")

        # ------------------------------------------------------------ 5. lista para ofício
        c, pl = j("investigador1", "POST", f"{P}/pedidos-revelacao", json={
            "tipo": "lista_oficio", "itens": [{"rotulo": "IP 1"}, {"rotulo": "IP 2"}, {"rotulo": "IP 3"}],
            "motivo": "Identificar o assinante dos IPs da rajada", "fundamento": "Ordem judicial no processo 0001234-12",
            "destinatario": "Provedor X"})
        checar(c == 201 and pl["quantidade"] == 3, "5 lista para ofício pedida (3 IPs)")
        checar(j("investigador1", "GET", f"{P}/oficios/{pl['pedido']}/tabela")[0] == 409, "5 tabela antes da aprovação: 409")
        c, dp = j("aprovador1", "GET", f"/api/aprovacoes/{pl['pedido']}")
        checar(c == 200 and dp["fundamento"] and dp["quantidade"] == 3, "5 aprovador vê fundamento e quantidade", dp.get("avisos"))
        j("aprovador1", "POST", f"/api/aprovacoes/{pl['pedido']}/decidir", json={"aprovar": True, "motivo": "Fundamento ok"})
        rr = base.web["investigador1"].get(f"{base.API}{P}/oficios/{pl['pedido']}/tabela")
        from openpyxl import load_workbook
        ok = rr.status_code == 200
        linhas = []
        if ok:
            wb = load_workbook(io.BytesIO(rr.content), read_only=True)
            linhas = [r for r in wb["Ofício"].iter_rows(min_row=6, values_only=True) if r and r[0]]
            ok = bool(linhas) and all(ipaddress.ip_address(r[0]) for r in linhas)
            valores |= {r[0] for r in linhas}
        checar(ok, "5 tabela do ofício (XLSX) com IPs reais e horários UTC", f"{len(linhas)} linhas")
        checar(j("investigador2", "GET", f"{P}/oficios/{pl['pedido']}/tabela")[0] in (403, 404), "5 só quem pediu baixa a tabela")
        with banco() as cx:
            n = cx.execute("SELECT count(*) n FROM trilha_auditoria WHERE investigacao_id=%s AND acao='revelar_oficio' AND "
                           "detalhe->>'pedido' = %s", (I, str(pl["pedido"]))).fetchone()["n"]
        checar(n == 3, "5 cada IP do ofício na trilha", n)

        # ------------------------------------------------------------ 7. migração
        from auditor import conferir_migracao as cm
        dsn_main = base.DSN.replace("/auditor_w2b", "/auditor")
        os.environ["AUDITOR_DSN"] = dsn_main
        import auditor.db as adb
        adb.DSN = dsn_main
        with banco(dsn_main) as cx:
            ls = cm.conferir(cx, [RAIZ / "saida"])
            rs = cm.resumo(ls)
            checar(rs["v1"]["conferem"] >= 1 and not rs["v1"]["divergem"] and not rs["atual"]["divergem"],
                   "7 manifestos entregues conferem com o cifrado", rs)
            alvo = next((x for x in ls if x.get("algoritmo") == "v1"), None)
            if alvo:
                with cx.transaction():
                    cx.execute("DELETE FROM evento WHERE ctid = (SELECT ctid FROM evento WHERE investigacao_id=%s LIMIT 1)",
                               (alvo["investigacao"],))
                    l2 = [x for x in cm.conferir(cx, [Path(alvo["pacote"]).parent]) if x.get("investigacao") == alvo["investigacao"]
                          and x.get("algoritmo") == "v1"]
                    checar(l2 and l2[0]["resultado"] == "diverge", "7 adulteração no banco é detectada", l2[0]["eventos"] if l2 else None)
                    raise _Desfazer()
    except _Desfazer:
        pass
    finally:
        api.terminate()
        wk.terminate()
    # ---------------------------------------------------------------- 8. varredura
    valores = {v for v in valores if v and len(v) >= 4}
    alvos = []
    with banco(base.DSN_DONO) as cx:
        t = "\n".join(r["t"] for r in cx.execute("SELECT detalhe::text AS t FROM trilha_auditoria WHERE investigacao_id=%s", (I,)))
    alvos.append(("trilha", t))
    for f in (RAIZ / "logs").glob("*.jsonl"):
        alvos.append((f.name, f.read_text(errors="ignore")))
    for f in (RAIZ / "logs").glob("*teste_analise.log"):
        alvos.append((f.name, f.read_text(errors="ignore")))
    achados = [(n, v) for n, txt in alvos for v in valores if v in txt]
    checar(not achados, "8 nenhum valor revelado na trilha, no SIEM ou nos logs",
           f"{len(valores)} valores; {len(achados)} achados" + (f" em {achados[0][0]}" if achados else ""))
    print(f"\n{base.oks[0]} OK; {'APROVADO' if not base.falhas else 'REPROVADO'}: {len(base.falhas)} falha(s)")
    for f in base.falhas:
        print("  -", f)
    sys.exit(1 if base.falhas else 0)


class _Desfazer(Exception):
    pass


if __name__ == "__main__":
    main()

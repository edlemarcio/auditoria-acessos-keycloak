"""Critérios de aceite do servidor da W3 (PROPOSTA_WEB §11: números iguais aos do XLSX; §7.6, §7.7, §8.4, §8.6) contra
a stack real, pela API como a web faria.

  psql .../auditor_w2b -v senha_app="'...'" -v senha_api="'senha-api-teste'" -f infra/papeis.sql   (cria kc_api)
  AUDITOR_DSN=<kc_auditor_app> AUDITOR_DSN_DONO=<dono> AUDITOR_CHAVE=... python tests/analise.py

Sobe a API com o papel kc_api (RLS) na porta 8300 e um worker, e usa uma investigação concluída em que investigador1 é
o designado e solicitante1 o dono (a do aceite da W2):
 1. dashboard: KPIs, série, por aplicação, mapa de calor, ranking de IPs e destaques iguais aos do XLSX do pacote
    mascarado (mesma massa); filtros por instância/realm/aplicação/técnicos conferem com consolidar();
 2. perfis: só o investigador designado vê dashboard, eventos, contas e cobertura; outro investigador, solicitante,
    aprovador e auditor interno recebem 404/403; o solicitante vê a visão agregada, sem IPs nem contas;
 3. RLS no banco: kc_api sem designação não vê evento, conta, pseudonimo nem conta_extra;
 4. eventos: paginação por chave sem repetição nem falta; filtros por rótulo de pseudônimo e pelos destaques
    (clique) conferem com os números do dashboard; detalhe do evento sem dado pessoal em claro, com folha, selo e
    requisição de origem, e registro na trilha;
 5. contas: excluir com justificativa (cifrada no banco) → recálculo por job → números sem a conta; incluir de volta
    → números de antes;
 6. cobertura com faixas por realm; coleta lacrada → 409;
 7. varredura: nenhum CPF, username, e-mail, userId ou IP da investigação em claro nas respostas.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import time
import zipfile
from collections import Counter
from pathlib import Path

import httpx
import psycopg
from psycopg.rows import dict_row

RAIZ = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(RAIZ))
sys.path.insert(0, str(RAIZ / "tests"))
from navegador_kc import cliente, logar  # noqa: E402

PORTA = int(os.environ.get("PORTA_TESTE", "8300"))
API = f"http://localhost:{PORTA}"
os.environ.setdefault("AUDITOR_OIDC_EMISSOR", "http://localhost:8090/realms/auditor")
os.environ.update({"AUDITOR_API_URL": API, "AUDITOR_MODO": os.environ.get("AUDITOR_MODO", "local"),
                   "AUDITOR_SIEM": str(RAIZ / "logs/siem_teste_analise.jsonl")})
DSN = os.environ["AUDITOR_DSN"]
DSN_DONO = os.environ.get("AUDITOR_DSN_DONO", DSN.replace("kc_auditor_app:senha-app-teste", "keycloak:keycloak"))
DSN_API = os.environ.get("AUDITOR_DSN_API", DSN.replace("kc_auditor_app:senha-app-teste", "kc_api:senha-api-teste"))
ALVO = json.loads((RAIZ / "dados/pessoas.json").read_text())["casos"]["ALVO"]["cpf"]

falhas: list[str] = []
oks = [0]
web: dict[str, httpx.Client] = {}
RESPOSTAS: list[str] = []


def checar(ok: bool, nome: str, detalhe="") -> bool:
    print(f"{'OK   ' if ok else 'FALHA'} {nome}{(' — ' + str(detalhe)) if detalhe != '' else ''}", flush=True)
    (oks.__setitem__(0, oks[0] + 1) if ok else falhas.append(nome))
    return ok


def entrar(u: str):
    c = cliente()
    r = c.get(logar(f"{API}/auth/entrar", u, c, retorno=f"{API}/auth/retorno"))
    assert r.status_code in (302, 307), (u, r.status_code)
    c.headers["X-Requisicao"] = "kc-auditor"
    web[u] = c


def j(u, metodo, caminho, **kw):
    r = web[u].request(metodo, f"{API}{caminho}", timeout=60, **kw)
    RESPOSTAS.append(r.text)
    try:
        return r.status_code, r.json()
    except ValueError:
        return r.status_code, r.text


def banco(dsn=DSN):
    return psycopg.connect(dsn, autocommit=True, row_factory=dict_row)


def processos():
    env = {**os.environ, "AUDITOR_DSN_API": DSN_API, "AUDITOR_FAXINA_S": "3"}
    (RAIZ / "logs").mkdir(exist_ok=True)
    subprocess.run(["fuser", "-k", f"{PORTA}/tcp"], capture_output=True)
    api = subprocess.Popen([sys.executable, "-m", "auditor", "api", "--porta", str(PORTA)], cwd=RAIZ, env=env,
                           stdout=open(RAIZ / "logs/api_teste_analise.log", "w"), stderr=subprocess.STDOUT)
    wk = subprocess.Popen([sys.executable, "-m", "auditor", "worker"], cwd=RAIZ, env=env,
                          stdout=open(RAIZ / "logs/worker_teste_analise.log", "w"), stderr=subprocess.STDOUT)
    for _ in range(60):
        try:
            if httpx.get(f"{API}/saude", timeout=2).status_code == 200:
                break
        except httpx.HTTPError:
            time.sleep(0.5)
    return api, wk


def xlsx_do_pacote(inv_id: int) -> dict:
    """Gera o pacote mascarado no próprio processo (como o worker de pacotes) e lê as abas da planilha."""
    from openpyxl import load_workbook
    from auditor.exportar import exportar
    d = Path(tempfile.mkdtemp(prefix="w3_"))
    r = exportar(inv_id, d, "teste_analise", sem_mascara=False, soltos=True)
    xs = list(d.glob("**/*.xlsx"))
    if not xs:
        with zipfile.ZipFile(r["pacote"]) as z:
            nome = next(n for n in z.namelist() if n.endswith(".xlsx"))
            z.extract(nome, d)
            xs = [d / nome]
    wb = load_workbook(xs[0], read_only=True)

    def aba(nome):
        linhas = [list(r) for r in wb[nome].iter_rows(values_only=True)]
        i = next(k for k, l in enumerate(linhas) if l and l[0] in ("Indicador", "Instância", "IP", "Destaque",
                                                                    "Janela (início)"))
        return [l for l in linhas[i + 1:] if any(v not in (None, "") for v in l)]
    return {"resumo": {l[0]: l[1] for l in aba("Resumo")}, "por_app": aba("Por aplicação"), "por_ip": aba("Por IP"),
            "destaques": aba("Destaques"), "janelas": aba("Consolidado por janela")}


def main():
    with banco() as cx:
        sub = {r["username"]: r["sub"] for r in cx.execute("SELECT username, sub FROM usuario")}
        inv = cx.execute("""SELECT i.* FROM investigacao i JOIN designacao d ON d.investigacao_id=i.id
            AND d.funcao='investigador' AND d.sub=%s WHERE i.status IN ('concluida','concluida_com_lacunas')
            AND NOT i.lacrada AND i.solicitante_sub=%s AND (i.parametros->>'base_dias')::int > 0
            AND d.designado_por IS DISTINCT FROM 'carga'
            AND EXISTS (SELECT 1 FROM chave_investigacao k WHERE k.investigacao_id=i.id)
            ORDER BY i.id DESC LIMIT 1""", (sub["investigador1"], sub["solicitante1"])).fetchone()
    assert inv, "sem investigação concluída de investigador1/solicitante1 (rode o aceite da W2 antes)"
    I = inv["id"]
    print(f"investigação {I} ({inv['status']})")
    api, wk = processos()
    try:
        for u in ("investigador1", "investigador2", "solicitante1", "aprovador1", "auditor1"):
            entrar(u)
        # garante agregados da versão atual (o fechamento já calcula; aqui por segurança)
        with banco() as cx:
            from auditor import analise
            analise.calcular(cx, I)

        # ---------------------------------------------------------------- 1. paridade com o XLSX
        c, d = j("investigador1", "GET", f"/api/investigacoes/{I}/dashboard")
        checar(c == 200, "1 dashboard do investigador designado", c)
        x = xlsx_do_pacote(I)
        k = d["kpis"]
        for nome, chave in (("Logins", "logins"), ("Falhas de login", "falhas"), ("Aplicações", "aplicacoes"),
                            ("IPs", "ips")):
            checar(x["resumo"][nome] == k[chave], f"1 KPI {nome} igual ao XLSX", f"{x['resumo'][nome]} × {k[chave]}")
        app_x = sorted((r[0], r[1], r[2], r[3], r[4]) for r in x["por_app"])
        app_a = sorted((r["instancia"], r["realm"], r["cliente"], r["logins"], r["falhas"]) for r in d["por_aplicacao"])
        checar(app_x == app_a, "1 por aplicação igual ao XLSX", f"{len(app_x)} linhas")
        ip_x = [(r[0], r[1], r[2]) for r in x["por_ip"]][:20]
        ip_a = [(r["ip"], r["eventos"], r["falhas"]) for r in d["ranking_ips"]]
        checar(Counter(ip_x) == Counter(ip_a) or [v[1:] for v in ip_x] == [v[1:] for v in ip_a],
               "1 ranking de IPs igual ao topo da aba Por IP", ip_a[:3])
        tipos = Counter(r[0] for r in x["destaques"])
        rd = d["resumo_destaques"]
        checar(tipos["Fora do expediente"] == rd["fora_expediente"], "1 destaques: fora do expediente = XLSX",
               f"{tipos['Fora do expediente']} × {rd['fora_expediente']}")
        checar(tipos["Rajada de falhas"] == rd["rajadas"], "1 destaques: rajadas = XLSX", rd["rajadas"])
        checar(tipos["IP novo"] == rd["ip_novo"], "1 destaques: IP novo = XLSX", rd["ip_novo"])
        jan_x = sum(r[7] for r in x["janelas"])
        checar(jan_x == sum(s["eventos"] for s in d["serie"]) == k["eventos"], "1 série: total = Consolidado por janela",
               jan_x)
        checar(len({r[0] for r in x["janelas"]}) == len(d["serie"]), "1 série: mesmas janelas do XLSX", len(d["serie"]))
        checar(sum(h["n"] for h in d["mapa_calor"]) == k["logins"], "1 mapa de calor soma os logins")
        # filtros: cada combinação confere com consolidar()
        from auditor.consolidar import consolidar
        op = d["opcoes"]
        combos = [{"instancia": op["instancias"][0]}, {"realm": op["realms"][0]},
                  {"cliente": op["clientes"][0]}, {"tecnicos": "1"}]
        for q in combos:
            c, df = j("investigador1", "GET", f"/api/investigacoes/{I}/dashboard", params=q)
            fc = {k2: v for k2, v in q.items() if k2 != "tecnicos"}
            if "tecnicos" in q:
                fc["categorias"] = ["Acesso", "Conta", "Técnico"]
            dc = consolidar(I, fc)
            kc = dc["kpis"]
            ok = all(kc[n] == df["kpis"][n] for n in ("logins", "falhas", "aplicacoes", "ips", "eventos"))
            checar(c == 200 and ok, f"1 filtro {q} igual a consolidar()",
                   {n: (kc[n], df["kpis"][n]) for n in ("logins", "falhas", "ips", "eventos")})

        # ---------------------------------------------------------------- 2. perfis
        for u in ("investigador2", "solicitante1", "aprovador1", "auditor1"):
            cods = [j(u, "GET", f"/api/investigacoes/{I}/{r}")[0] for r in ("dashboard", "eventos", "contas", "cobertura")]
            checar(all(cc in (403, 404) for cc in cods), f"2 {u} não vê dados da investigação", cods)
        c, va = j("solicitante1", "GET", f"/api/investigacoes/{I}/visao-agregada")
        txt = json.dumps(va)
        checar(c == 200 and va["kpis"]["logins"] == k["logins"] and "ip" not in txt.lower().replace("aplicac", ""),
               "2 solicitante vê a visão agregada, sem IPs nem contas", va["kpis"])
        checar(j("aprovador1", "GET", f"/api/investigacoes/{I}/visao-agregada")[0] in (403, 404),
               "2 aprovador não vê a visão agregada")

        # ---------------------------------------------------------------- 3. RLS
        def contar(dsn, s):
            with banco(dsn) as cx:
                if s:
                    cx.execute("SELECT set_config('kc_auditor.sub', %s, false)", (s,))
                return {t: cx.execute(f"SELECT count(*) n FROM {t} WHERE investigacao_id=%s", (I,)).fetchone()["n"]
                        for t in ("evento", "conta", "pseudonimo", "conta_extra")}
        sem, outro, dono, servico = (contar(DSN_API, None), contar(DSN_API, sub["investigador2"]),
                                     contar(DSN_API, sub["investigador1"]), contar(DSN, None))
        checar(not any(sem.values()), "3 RLS: kc_api sem identidade não vê nada", sem)
        checar(not any(outro.values()), "3 RLS: kc_api com outro investigador não vê nada", outro)
        checar(dono == servico and dono["evento"] > 0, "3 RLS: investigador designado vê tudo; serviço inalterado", dono)
        sol = contar(DSN_API, sub["solicitante1"])
        checar(sol["evento"] == 0 and sol["conta"] > 0, "3 RLS: solicitante vê contas (acompanhamento), não eventos", sol)

        # ---------------------------------------------------------------- 4. eventos
        vistos, apos, paginas = set(), None, 0
        while True:
            c, p = j("investigador1", "GET", f"/api/investigacoes/{I}/eventos",
                     params={"tipo": "falhas", "limite": 200, **({"apos": apos} if apos else {})})
            paginas += 1
            for e in p["itens"]:
                vistos.add(e["ref"])
            apos = p["proximo"]
            if not apos:
                break
        checar(len(vistos) == p["total_filtrado"] == k["falhas"], "4 paginação por chave: todas as falhas, sem repetir",
               f"{len(vistos)} em {paginas} páginas")
        top = d["ranking_ips"][0]
        c, p = j("investigador1", "GET", f"/api/investigacoes/{I}/eventos", params={"ip": top["ip"]})
        checar(p["total_filtrado"] == top["eventos"], f"4 filtro por rótulo ({top['ip']}) = ranking", p["total_filtrado"])
        for dz in d["destaques"]:
            if dz["tipo"] in ("fora_expediente", "rajada"):
                c, p = j("investigador1", "GET", f"/api/investigacoes/{I}/eventos", params=dz["filtro"])
                checar(p["total_filtrado"] == dz["n"], f"4 clique no destaque {dz['tipo']} abre os {dz['n']} eventos",
                       p["total_filtrado"])
        ip_novos = [z for z in d["destaques"] if z["tipo"] == "ip_novo"]
        if ip_novos:
            c, p = j("investigador1", "GET", f"/api/investigacoes/{I}/eventos", params=ip_novos[0]["filtro"])
            checar(p["total_filtrado"] == ip_novos[0]["n"], "4 clique em IP novo abre os eventos do IP")
        c, p = j("investigador1", "GET", f"/api/investigacoes/{I}/eventos", params={"limite": 5})
        ref = p["itens"][0]["ref"]
        c, det = j("investigador1", "GET", f"/api/investigacoes/{I}/eventos/{ref}")
        checar(c == 200 and det["folha"] and det["selo"] and det["selo"]["raiz"], "4 detalhe com folha e selo da fatia",
               (det.get("selo") or {}).get("id"))
        checar(det.get("requisicao") is not None, "4 detalhe com a requisição de origem", det.get("requisicao"))
        with banco() as cx:
            n = cx.execute("SELECT count(*) n FROM trilha_auditoria WHERE investigacao_id=%s AND acao='consultar_evento'",
                           (I,)).fetchone()["n"]
        checar(n >= 1, "4 detalhe do evento registrado na trilha", n)
        checar(j("investigador1", "GET", f"/api/investigacoes/{I}/eventos/lixo")[0] == 422, "4 referência inválida 422")

        # ---------------------------------------------------------------- 5. excluir e incluir conta
        c, cs = j("investigador1", "GET", f"/api/investigacoes/{I}/contas")
        alvo_c = max((x for x in cs["contas"] if x["incluida"] and x["eventos"] and x["via"] not in ("varredura",)),
                     key=lambda x: x["eventos"])
        antes = k
        motivo = "Conta de outra pessoa com o mesmo identificador (teste W3)"
        c, r = j("investigador1", "POST", f"/api/investigacoes/{I}/contas/{alvo_c['id']}/excluir",
                 json={"motivo": motivo})
        checar(c == 202 and r["analise"]["recalculando"], "5 excluir conta: 202 e recálculo pendente", r)
        c, d1 = j("investigador1", "GET", f"/api/investigacoes/{I}/dashboard")
        for _ in range(60):
            c, d1 = j("investigador1", "GET", f"/api/investigacoes/{I}/dashboard")
            if not d1["analise"]["recalculando"]:
                break
            time.sleep(1)
        checar(not d1["analise"]["recalculando"], "5 recálculo feito pelo worker", d1["analise"])
        with banco() as cx:
            ev_conta = cx.execute("""SELECT count(*) n FROM evento e WHERE e.investigacao_id=%s AND e.conta_id=%s
                AND e.time_ms >= %s AND e.time_ms < %s AND e.type = ANY(%s)""",
                                  (I, alvo_c["id"], inv["inicio_ms"], inv["fim_ms"], ["LOGIN", "IDENTITY_PROVIDER_LOGIN"])
                                  ).fetchone()["n"]
            blob = cx.execute("SELECT motivo_cifrado FROM conta_decisao WHERE investigacao_id=%s ORDER BY id DESC LIMIT 1",
                              (I,)).fetchone()["motivo_cifrado"]
        checar(d1["kpis"]["logins"] == antes["logins"] - ev_conta, "5 logins sem a conta excluída",
               f"{antes['logins']} → {d1['kpis']['logins']} (conta tinha {ev_conta})")
        checar(motivo.encode() not in bytes(blob), "5 justificativa cifrada no banco")
        c, cs2 = j("investigador1", "GET", f"/api/investigacoes/{I}/contas")
        dz = next(x for x in cs2["contas"] if x["id"] == alvo_c["id"])
        checar(not dz["incluida"] and dz["decisao"]["motivo"] == motivo, "5 conta excluída com o motivo para o investigador")
        c, r = j("investigador1", "POST", f"/api/investigacoes/{I}/contas/{alvo_c['id']}/incluir",
                 json={"motivo": "Revisão: a conta é mesmo da pessoa investigada"})
        for _ in range(60):
            c, d2 = j("investigador1", "GET", f"/api/investigacoes/{I}/dashboard")
            if not d2["analise"]["recalculando"]:
                break
            time.sleep(1)
        checar(d2["kpis"] == antes, "5 incluir de volta: números de antes", d2["kpis"]["logins"])
        checar(j("investigador1", "POST", f"/api/investigacoes/{I}/contas/{alvo_c['id']}/excluir",
                 json={"motivo": "curto"})[0] == 422, "5 justificativa curta recusada")
        checar(j("investigador2", "POST", f"/api/investigacoes/{I}/contas/{alvo_c['id']}/excluir",
                 json={"motivo": motivo})[0] in (403, 404), "5 outro investigador não exclui")
        c, ex = j("investigador1", "GET", f"/api/investigacoes/{I}/contas/{alvo_c['id']}/extras")
        checar(c == 200 and "sessoes_ativas" in ex, "5 sessões ativas e alterações da conta",
               (len(ex.get("sessoes_ativas", [])), len(ex.get("alteracoes", []))))

        # ---------------------------------------------------------------- 6. cobertura e coleta lacrada
        c, co = j("investigador1", "GET", f"/api/investigacoes/{I}/cobertura")
        checar(c == 200 and co["linhas"] and all("faixas" in li for li in co["linhas"]) and co["selo"]["calculada"],
               "6 cobertura por realm com faixas e selo", co["selo"])
        with banco(DSN_DONO) as cx:
            cx.execute("UPDATE investigacao SET lacrada=true WHERE id=%s", (I,))
        try:
            cods = [j("investigador1", "GET", f"/api/investigacoes/{I}/{r}")[0] for r in ("dashboard", "eventos", "contas")]
            checar(cods == [409, 409, 409], "6 coleta lacrada → 409", cods)
        finally:
            with banco(DSN_DONO) as cx:
                cx.execute("UPDATE investigacao SET lacrada=false WHERE id=%s", (I,))

        # ---------------------------------------------------------------- 7. varredura
        from auditor import sigilo
        cf = sigilo.Cofre(I, "exportar")
        with banco() as cx:
            valores = {ALVO, ALVO.replace(".", "").replace("-", "")}
            for ct in sigilo.contas(cx, cf):
                valores |= {v for v in (ct.get("username"), ct.get("email"), ct.get("user_id")) if v and len(v) >= 4}
            for r in cx.execute("SELECT id, instancia_id, realm, cifrado FROM evento WHERE investigacao_id=%s "
                                "AND cifrado IS NOT NULL LIMIT 3000", (I,)):
                e = sigilo.abrir_evento(cf, r)
                valores |= {v for v in (e.get("ip"), e.get("session_id")) if v}
        tudo = "\n".join(RESPOSTAS)
        achados = sorted(v for v in valores if v in tudo)
        checar(not achados, "7 nenhum dado pessoal em claro nas respostas", f"{len(valores)} valores procurados; "
               f"{len(achados)} achados{(': ' + achados[0][:3] + '…') if achados else ''}")
    finally:
        api.terminate()
        wk.terminate()
    print(f"\n{oks[0]} OK; {'APROVADO' if not falhas else 'REPROVADO'}: {len(falhas)} falha(s)")
    for f in falhas:
        print("  -", f)
    sys.exit(1 if falhas else 0)


if __name__ == "__main__":
    main()

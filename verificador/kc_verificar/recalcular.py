"""`kc-verificar --recalcular` (FORMATO_PACOTE.md §9): refaz KPIs, consolidado por janela, destaques e cobertura a
partir dos eventos do pacote e das regras publicadas, e compara com resultados.json (de onde sai o relatório técnico),
com o CSV consolidado, com a aba Resumo da planilha e com a contagem do CSV de eventos.

Pacote sem máscara: lê eventos.jsonl (eventos originais) e confere também cada pseudônimo da planilha contra
pseudonimos.csv. Pacote mascarado: lê eventos_pseudonimizados.jsonl (contagens, IPs distintos por pseudônimo e
destaques são calculáveis sem dado real).
"""
from __future__ import annotations

import json
from datetime import datetime

from . import regras
from .pacote import Relatorio, _linhas, ler_aba_xlsx, ler_csv, percorrer_csv


def _eventos(z, m):
    if m["pacote"]["mascara"]:
        for e in _linhas(z, "eventos_pseudonimizados.jsonl"):
            yield e["t"], e["instancia"], e["realm"], e["conta_id"], e["tipo"], e["cliente"], e["ip"]
    else:
        for l in _linhas(z, "eventos.jsonl"):
            b = l["evento"]
            yield b["time"], l["instancia"], l["realm"], l["conta"], b["type"], b.get("clientId"), b.get("ipAddress")


def recalcular(z, m, r: Relatorio):
    res = json.loads(z.read("resultados.json"))
    inv = m["investigacao"]
    rg = res.get("regras") or {}
    if (rg.get("categorias") != regras.CATEGORIAS_PADRAO or list(rg.get("expediente") or []) != list(regras.EXPEDIENTE)
            or rg.get("rajada") != regras.RAJADA):
        r.falha("o pacote declara regras de cálculo diferentes das publicadas: resultados não aceitos")
        return
    rc = regras.Recalculo(inv["inicio_ms"], inv["fim_ms"], inv["fuso"], inv["granularidade"],
                          (inv.get("parametros") or {}).get("base_dias") or 0)
    for ev in _eventos(z, m):
        rc.adicionar(*ev)
    novo = rc.resultados()
    falhou = False

    def comparar(nome, a, b):
        nonlocal falhou
        if a != b:
            falhou = True
            r.falha(f"recalcular: {nome} diferente do declarado no pacote")
            return False
        return True

    comparar("KPIs", novo["kpis"], res["kpis"])
    decl = sorted(([j["janela"], j["instancia"], j["realm"], j["cliente"], j["tipo"], j["n"], j["ips"]]
                   for j in res["janelas"]), key=lambda x: (x[0], x[1], x[2], x[3] or "", x[4]))
    comparar("consolidado por janela", novo["janelas"], decl)
    d = res["destaques"]
    comparar("destaques fora do expediente", novo["destaques"]["fora_expediente"], d["fora_expediente"])
    comparar("rajadas de falhas", novo["destaques"]["rajadas"], d["rajadas"])
    comparar("IPs novos", novo["destaques"]["ip_novo"], d["ip_novo"])
    cob = regras.fracoes(inv["inicio_ms"], inv["fim_ms"], json.loads(z.read("cobertura.json")))
    comparar("cobertura", cob, res["cobertura"])
    comparar("cobertura do manifesto", cob, m["cobertura"])

    # derivados: CSV consolidado, aba Resumo da planilha, CSV de eventos
    nome_de = {i["id"]: i["nome"] for i in m["instancias"]}
    csv_c = ler_csv(z, f"consolidado_{inv['id']}.csv")[1:]
    esperado = sorted((datetime.fromisoformat(j[0]).strftime("%d/%m/%Y %H:%M:%S"), nome_de[j[1]], j[2], j[3] or "",
                       j[4], str(j[5]), str(j[6])) for j in novo["janelas"])
    lido = sorted((l[0], l[1], l[2], l[3], l[6], l[7], l[8]) for l in csv_c)
    comparar(f"consolidado_{inv['id']}.csv", lido, esperado)
    resumo = {l[0]: l[1] for l in ler_aba_xlsx(z, f"investigacao_{inv['id']}.xlsx", "Resumo") if len(l) >= 2}
    k = novo["kpis"]
    comparar("aba Resumo da planilha", [resumo.get("Logins"), resumo.get("Falhas de login"), resumo.get("Aplicações"),
                                        resumo.get("IPs")],
             [str(k["logins"]), str(k["falhas"]), str(k["aplicacoes"]), str(k["ips"])])
    n_csv = sum(1 for _ in percorrer_csv(z, f"eventos_{inv['id']}.csv")) - 1
    comparar(f"eventos_{inv['id']}.csv (linhas)", n_csv, k["eventos"])
    if not m["pacote"]["mascara"]:
        _pseudonimos(z, m, r)
    if not falhou:
        r.ok(f"recalcular: KPIs, {len(novo['janelas'])} linhas do consolidado por janela, destaques "
             f"({len(d['fora_expediente'])} fora do expediente, {len(d['rajadas'])} rajadas, "
             f"{'sem base' if d['ip_novo'] is None else len(d['ip_novo'])} IPs novos) e cobertura conferem com "
             "resultados.json, a planilha, os CSVs e o relatório")


def _pseudonimos(z, m, r: Relatorio):
    """Sem máscara: cada par valor/pseudônimo da planilha de eventos bate com pseudonimos.csv."""
    mapa = {}
    for l in ler_csv(z, "pseudonimos.csv")[1:]:
        mapa.setdefault((l[0], l[2]), set()).add(l[1])
    linhas = percorrer_csv(z, f"eventos_{m['investigacao']['id']}.csv")
    cab = next(linhas)
    ip, ip_ps = cab.index("IP"), cab.index("IP (pseudônimo)")
    ruins = 0
    for l in linhas:
        if l[ip] not in ("", "—") and l[ip_ps] not in mapa.get(("ip", l[ip]), set()):
            ruins += 1
    if ruins:
        r.falha(f"recalcular: {ruins} linha(s) do CSV de eventos com pseudônimo de IP que não bate com pseudonimos.csv")
    else:
        r.ok("recalcular: os pseudônimos de IP do CSV de eventos batem com pseudonimos.csv")

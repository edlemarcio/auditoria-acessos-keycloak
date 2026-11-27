"""Exportação: XLSX (Tabelas do Excel), CSV pt-BR, dashboard HTML, eventos brutos e manifesto assinado (ZIP)."""
from __future__ import annotations

import csv
import io
import json
import re
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from zoneinfo import ZoneInfo

from openpyxl import Workbook
from openpyxl.styles import Alignment, Font, PatternFill
from openpyxl.utils import get_column_letter
from openpyxl.worksheet.table import Table, TableStyleInfo

from . import __version__, dashboard
from .consolidar import ERROS, GLOSSARIO, categoria, consolidar, nome_evento
from .chaves import alvo as alvo_de
from .db import SNAPSHOTS_DA_INVESTIGACAO, conectar, trilha
from .identificador import mascarar_texto
from .manifesto import assinar_manifesto, linhas_eventos, sha256

LIMITE_LINHAS = 1_048_575
CLASSE = {"coberto": "Coberto", "parcial": "Parcial", "sem_dados": "Sem dados"}


# parâmetros técnicos da Admin API; qualquer outro (user, username, q, search, email, resourcePath...) é redigido
PARAMS_TECNICOS = {"type", "dateFrom", "dateTo", "first", "max", "direction", "exact", "briefRepresentation",
                   "client", "operationTypes", "resourceTypes", "enabled"}
REDIGIDO = "[redigido]"


def redigir_requisicao(r: dict, msk) -> dict:
    """Versão da requisição para o pacote mascarado: sem userId no caminho e sem parâmetros pessoais."""
    caminho = re.sub(r"/users/[^/?]+", f"/users/{REDIGIDO}", r["caminho"])
    params = r["params"]
    if isinstance(params, dict):
        params = {k: (v if k in PARAMS_TECNICOS else REDIGIDO) for k, v in params.items()}
    return {**r, "caminho": msk(caminho), "params": params}


def _linhas_requisicoes(reqs) -> bytes:
    return b"".join(json.dumps({**r, "inicio": r["inicio"].isoformat()}, ensure_ascii=False,
                               default=str).encode() + b"\n" for r in reqs)


def _naive(ms, tz):
    return datetime.fromtimestamp(ms / 1000, tz).replace(tzinfo=None) if ms is not None else None


def _aba(wb, nome, cab, linhas, larguras=None, aviso=None, fmt_data=(), num=()):
    partes = [linhas[i:i + LIMITE_LINHAS] for i in range(0, max(1, len(linhas)), LIMITE_LINHAS)] or [[]]
    for p, bloco in enumerate(partes):
        ws = wb.create_sheet(nome if p == 0 else f"{nome[:27]} ({p + 1})")
        lin0 = 1
        if aviso:
            ws.cell(1, 1, aviso).font = Font(bold=True, color="9A6700")
            lin0 = 3
        for j, c in enumerate(cab, 1):
            cel = ws.cell(lin0, j, c)
            cel.font = Font(bold=True)
        for i, l in enumerate(bloco, lin0 + 1):
            for j, v in enumerate(l, 1):
                cel = ws.cell(i, j, v)
                if j - 1 in fmt_data:
                    cel.number_format = "dd/mm/yyyy hh:mm:ss"
                elif j - 1 in num:
                    cel.number_format = "#,##0"
        ult = lin0 + max(1, len(bloco))
        if not bloco:
            ws.cell(lin0 + 1, 1, "")
        ref = f"A{lin0}:{get_column_letter(len(cab))}{ult}"
        t = Table(displayName="T_" + "".join(ch for ch in nome if ch.isalnum())[:20] + str(p), ref=ref)
        t.tableStyleInfo = TableStyleInfo(name="TableStyleMedium2", showRowStripes=True)
        ws.add_table(t)
        ws.freeze_panes = ws.cell(lin0 + 1, 2)
        for j in range(1, len(cab) + 1):
            ws.column_dimensions[get_column_letter(j)].width = (larguras or {}).get(j - 1, 18)
    return wb


def exportar(inv_id: int, saida: Path, operador: str, sem_mascara: bool = False) -> dict:
    with conectar() as cx:
        inv = cx.execute("SELECT * FROM investigacao WHERE id=%s", (inv_id,)).fetchone()
    dig = alvo_de(inv, "exportar")
    tz = ZoneInfo(inv["fuso"])
    msk = (lambda s: s) if sem_mascara else (lambda s: mascarar_texto(s, inv["tipo"], dig))
    d = consolidar(inv_id)
    with conectar() as cx:
        d["base_eventos"] = cx.execute("SELECT ip FROM evento WHERE investigacao_id=%s AND time_ms < %s",
                                       (inv_id, inv["inicio_ms"])).fetchall()
        # mesmo conjunto da planilha e do dashboard: só eventos de contas incluídas (D2)
        brutos = cx.execute("SELECT e.bruto, i.nome AS inst, e.realm FROM evento e JOIN instancia i "
                            "ON i.id=e.instancia_id JOIN conta c ON c.id=e.conta_id "
                            "WHERE e.investigacao_id=%s AND c.incluida", (inv_id,)).fetchall()
        excluidas = cx.execute("SELECT c.id, i.nome AS instancia, c.realm, c.user_id, c.username, c.via, "
                               "(SELECT count(*) FROM evento e WHERE e.conta_id=c.id) AS eventos "
                               "FROM conta c JOIN instancia i ON i.id=c.instancia_id "
                               "WHERE c.investigacao_id=%s AND NOT c.incluida ORDER BY c.id", (inv_id,)).fetchall()
        reqs = cx.execute("SELECT id, caminho, params, status, inicio, ms, sha256, bytes, coletor FROM requisicao "
                          "WHERE investigacao_id=%s ORDER BY id", (inv_id,)).fetchall()
        insts = cx.execute("SELECT nome, url, versao_declarada, sondas FROM instancia").fetchall()
        # só os snapshots lidos por esta investigação (D3)
        snaps = cx.execute("SELECT i.nome, s.realm, s.lido_em, s.visivel, s.config, s.user_profile, s.federacao, "
                           "s.status FROM realm_snapshot s JOIN instancia i ON i.id=s.instancia_id WHERE "
                           + SNAPSHOTS_DA_INVESTIGACAO + " ORDER BY s.id", {"inv": inv_id}).fetchall()
    fr = d["fracoes"]
    filtros = "categorias: " + ", ".join(d["filtros"]["categorias"])
    aviso = None if fr["completa"] else (f"ATENÇÃO: cobertura parcial — realms {fr['realms'][0]}/{fr['realms'][1]}"
                                         f" · tempo {fr['tempo'][0]}/{fr['tempo'][1]} dias. Ver aba Cobertura.")
    wb = Workbook()
    wb.remove(wb.active)
    # Leia-me
    leia = [["Objetivo", "Consolidação de acessos de uma pessoa em todas as instâncias e realms Keycloak visíveis."],
            ["Logins", "LOGIN + IDENTITY_PROVIDER_LOGIN"], ["Falhas de login", "LOGIN_ERROR + IDENTITY_PROVIDER_LOGIN_ERROR"],
            ["Aplicações", "clientId distintos em Logins"], ["IPs", "IPs distintos em Logins e Falhas"],
            ["Cobertura · realms", "pares realm×conta cobertos ÷ pesquisados ('pesquisado, sem conta' conta como coberto)"],
            ["Cobertura · tempo", "dias com dados em todas as contas com eventos ÷ dias do período"],
            ["Coberto", "OK, ou realm pesquisado sem conta com o identificador"],
            ["Parcial", "retenção insuficiente, falhas não gravadas, expirado durante a coleta, limite atingido, divergente"],
            ["Sem dados", "eventos não gravados, tipo não gravado, sem permissão, atributo não pesquisável, erro"],
            ["Horário", f"Fuso {inv['fuso']}, com coluna UTC; o horário vem do relógio do servidor Keycloak"],
            ["Máscara", "identificador mascarado" if not sem_mascara else "SEM MÁSCARA (exportação autorizada)"]]
    leia += [[f"Evento {k}", f"{v[0]} ({v[1]})"] for k, v in GLOSSARIO.items()]
    leia += [[f"Erro {k}", v] for k, v in ERROS.items()]
    _aba(wb, "Leia-me", ["Item", "Descrição"], leia, {0: 30, 1: 100})
    k = d["kpis"]
    par = [["Investigação", inv_id], ["Alvo", inv["alvo_mascarado"] if not sem_mascara else dig],
           ["Justificativa", inv["justificativa"]], ["Operador", inv["operador"]],
           ["Exportado por", operador], ["Exportado em", datetime.now(tz).replace(tzinfo=None)],
           ["Período início", _naive(inv["inicio_ms"], tz)], ["Período fim (exclusivo)", _naive(inv["fim_ms"], tz)],
           ["Fuso", inv["fuso"]], ["Granularidade", inv["granularidade"]], ["Filtros aplicados", filtros],
           ["Máscara", "aplicada" if not sem_mascara else "não aplicada"], ["Versão do coletor", __version__]]
    par += [[f"Instância {i['nome']}", f"{i['url']} · versão declarada {i['versao_declarada']} · modo "
             f"{(i['sondas'] or {}).get('modo')} · fuso medido {((i['sondas'] or {}).get('S6_fuso') or {}).get('deslocamento_horas')} h"]
            for i in insts]
    _aba(wb, "Parâmetros", ["Parâmetro", "Valor"], par, {0: 26, 1: 110}, fmt_data=())
    res = [["Logins", k["logins"]], ["Falhas de login", k["falhas"]], ["Aplicações", k["aplicacoes"]],
           ["IPs", k["ips"]], ["Primeiro acesso", _naive(k["primeiro"], tz)], ["Último acesso", _naive(k["ultimo"], tz)],
           ["Cobertura realms", f"{fr['realms'][0]}/{fr['realms'][1]}"],
           ["Cobertura tempo (dias)", f"{fr['tempo'][0]}/{fr['tempo'][1]}"]]
    _aba(wb, "Resumo", ["Indicador", "Valor"], res, {0: 26, 1: 26},
         aviso=(aviso or "Cobertura completa.") + f"  Exportação filtrada: {filtros}.")
    jan = [[r["janela"], r["instancia"], r["realm"], r["client_id"], categoria(r["type"]), nome_evento(r["type"]),
            r["type"], r["n"], r["ips"]] for r in d["janelas"]]
    _aba(wb, "Consolidado por janela", ["Janela (início)", "Instância", "Realm", "Aplicação", "Categoria", "Evento",
                                        "Código", "Quantidade", "IPs distintos"], jan, {0: 20}, fmt_data=(0,), num=(7, 8))
    _aba(wb, "Por aplicação", ["Instância", "Realm", "Aplicação", "Logins", "Falhas de login", "Primeiro", "Último"],
         [[r["instancia"], r["realm"], r["client_id"], r["logins"], r["falhas"], _naive(r["primeiro"], tz),
           _naive(r["ultimo"], tz)] for r in d["por_app"]], fmt_data=(5, 6), num=(3, 4))
    _aba(wb, "Por IP", ["IP", "Eventos", "Falhas de login", "Primeiro", "Último", "Onde"],
         [[r["ip"], r["n"], r["falhas"], _naive(r["primeiro"], tz), _naive(r["ultimo"], tz), r["onde"]]
          for r in d["por_ip"]], {5: 50}, fmt_data=(3, 4), num=(1, 2))
    dest = [["Fora do expediente", _naive(e["time_ms"], tz), e["instancia"], e["realm"], msk(e["username"]),
             e["client_id"], e["ip"], ""] for e in d["fora"]]
    dest += [["Rajada de falhas", _naive(r["inicio"], tz), r["instancia"], r["realm"], msk(r["username"]), "",
              ", ".join(r["ips"]), f"{r['n']} falhas até {_naive(r['fim'], tz):%d/%m/%Y %H:%M:%S}"] for r in d["rajadas"]]
    if d["ip_novo"] is None:
        dest.append(["IP novo", None, "", "", "", "", "", "sem base de comparação"])
    else:
        dest += [["IP novo", _naive(e["time_ms"], tz), e["instancia"], e["realm"], msk(e["username"]), e["client_id"],
                  e["ip"], "primeira ocorrência"] for e in d["ip_novo"]]
    _aba(wb, "Destaques", ["Destaque", "Data e hora", "Instância", "Realm", "Conta", "Aplicação", "IP", "Observação"],
         dest, {7: 40}, fmt_data=(1,))
    det = []
    for e in d["eventos"]:
        dd = e["details"] or {}
        det.append([_naive(e["time_ms"], tz), inv["fuso"], datetime.fromtimestamp(e["time_ms"] / 1000, timezone.utc)
                    .replace(tzinfo=None), e["instancia"], e["realm"], msk(e["username"]), nome_evento(e["type"]),
                    e["type"], e["client_id"], e["ip"], e["session_id"], ERROS.get(e["error"], e["error"] or ""),
                    e["error"], dd.get("auth_method"), msk(dd.get("redirect_uri")), e["id"]])
    _aba(wb, "Eventos detalhados", ["Data e hora local", "Fuso", "Data e hora UTC", "Instância", "Realm", "Conta",
                                    "Evento", "Código", "Aplicação", "IP", "Sessão", "Erro", "Código do erro",
                                    "Método", "Endereço de retorno", "ID do evento"], det, {14: 40, 15: 38},
         fmt_data=(0, 2))
    _aba(wb, "Cobertura", ["Instância", "Realm", "Conta", "Classe", "Status", "Situação", "Próximo passo", "Coberto desde"],
         [[c["instancia"], c["realm"], msk(c["username"]) if c["username"] else "—", CLASSE[c["classe"]], c["status"],
           msk(c["detalhe"]), c["acao"], _naive(c["desde_ms"], tz)] for c in d["cobertura"]],
         {5: 60, 6: 50}, aviso=aviso, fmt_data=(7,))
    conta_l = [["Sessão ativa", x["capturado_em"].astimezone(tz).replace(tzinfo=None), x["instancia"], x["realm"],
                msk(x["username"]), x["dados"].get("ipAddress"), ""] for x in d["extras"] if x["tipo"] == "sessao"]
    conta_l += [["Alteração administrativa", _naive(x["dados"].get("time"), tz), x["instancia"], x["realm"],
                 msk(x["username"]), x["dados"].get("operationType"), x["dados"].get("resourcePath")]
                for x in d["extras"] if x["tipo"] == "admin"]
    _aba(wb, "Conta", ["Tipo", "Data e hora", "Instância", "Realm", "Conta", "IP / Operação", "Recurso"], conta_l,
         {6: 50}, fmt_data=(1,))
    xlsx = io.BytesIO()
    wb.save(xlsx)

    def csv_bytes(cab, linhas):
        s = io.StringIO()
        w = csv.writer(s, delimiter=";")
        w.writerow(cab)
        for l in linhas:
            w.writerow([v.strftime("%d/%m/%Y %H:%M:%S") if isinstance(v, datetime) else v for v in l])
        return "﻿".encode() + s.getvalue().encode("utf-8")

    arquivos = {
        f"investigacao_{inv_id}.xlsx": xlsx.getvalue(),
        f"eventos_{inv_id}.csv": csv_bytes(["Data e hora local", "Fuso", "Data e hora UTC", "Instância", "Realm",
                                            "Conta", "Evento", "Código", "Aplicação", "IP", "Sessão", "Erro",
                                            "Código do erro", "Método", "Endereço de retorno", "ID do evento"], det),
        f"consolidado_{inv_id}.csv": csv_bytes(["Janela", "Instância", "Realm", "Aplicação", "Categoria", "Evento",
                                                "Código", "Quantidade", "IPs distintos"], jan),
        f"dashboard_{inv_id}.html": dashboard.gerar(d, msk).encode(),
    }
    ev_bytes = linhas_eventos([{**b["bruto"], "_instancia": b["inst"], "_realm": b["realm"]} for b in brutos])
    req_bytes = _linhas_requisicoes(reqs)
    if sem_mascara:
        arquivos["eventos.jsonl"] = ev_bytes
        arquivos["requisicoes.jsonl"] = req_bytes
    else:
        # D1: os parâmetros de busca levam o identificador (q=cpf:..., username=...) e o caminho leva o userId.
        # O pacote mascarado vai redigido e sem hash por linha; o manifesto guarda o hash do arquivo original inteiro.
        arquivos["requisicoes.jsonl"] = _linhas_requisicoes([redigir_requisicao(r, msk) for r in reqs])
    manifesto = {
        "versao_coletor": __version__, "gerado_em": datetime.now(timezone.utc).isoformat(),
        "investigacao": {"id": inv_id, "alvo": inv["alvo_mascarado"], "tipo": inv["tipo"],
                         "justificativa": inv["justificativa"], "operador": inv["operador"],
                         "inicio_ms": inv["inicio_ms"], "fim_ms": inv["fim_ms"], "fuso": inv["fuso"],
                         "granularidade": inv["granularidade"], "status": inv["status"],
                         "parametros": inv["parametros"]},
        "exportado_por": operador, "mascara": not sem_mascara, "filtros": d["filtros"],
        "instancias": [{"nome": i["nome"], "url": i["url"], "versao_declarada": i["versao_declarada"],
                        "sondas": i["sondas"]} for i in insts],
        "snapshots": [{**s, "lido_em": s["lido_em"].isoformat()} for s in snaps],
        "eventos": {"total": len(brutos), "sha256": sha256(ev_bytes),
                    "formato": "RFC 8785, um por linha, ordenado por (_instancia, _realm, id)"},
        "requisicoes": {"total": len(reqs), "sha256": sha256(req_bytes),
                        "redigido": not sem_mascara,
                        "formato": "um por linha; no pacote mascarado, caminho e parâmetros pessoais redigidos e "
                                   "sha256 do arquivo original"},
        "contas_excluidas": [{"id": c["id"], "instancia": c["instancia"], "realm": c["realm"], "via": c["via"],
                              "conta": msk(c["username"]) if c["username"] else None, "eventos": c["eventos"],
                              **({"user_id": c["user_id"]} if sem_mascara else {})} for c in excluidas],
        "cobertura": {"realms": list(fr["realms"]), "tempo": list(fr["tempo"])},
        "arquivos": {n: sha256(b) for n, b in arquivos.items()} | ({} if sem_mascara else
                                                                    {"eventos.jsonl": sha256(ev_bytes)}),
    }
    corpo, sig = assinar_manifesto(json.loads(json.dumps(manifesto, default=str)))
    saida.mkdir(parents=True, exist_ok=True)
    zp = saida / f"investigacao_{inv_id}{'_sem_mascara' if sem_mascara else ''}.zip"
    with zipfile.ZipFile(zp, "w", zipfile.ZIP_DEFLATED) as z:
        for n, b in arquivos.items():
            z.writestr(n, b)
        z.writestr("manifesto.json", corpo)
        z.writestr("manifesto.sig", sig)
    for n, b in arquivos.items():
        if n.endswith((".xlsx", ".html")):
            # arquivos soltos: o sufixo evita que uma exportação sem máscara sobrescreva a mascarada
            base, ext = n.rsplit(".", 1)
            (saida / f"{base}{'_SEM_MASCARA' if sem_mascara else ''}.{ext}").write_bytes(b)
    with conectar() as cx:
        trilha(cx, operador, "exportar_sem_mascara" if sem_mascara else "exportar", inv_id,
               arquivo=zp.name, sha256_manifesto=sha256(corpo))
    return {"pacote": str(zp), "eventos": len(brutos), "requisicoes": len(reqs), "manifesto_sha256": sha256(corpo)}

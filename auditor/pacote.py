"""Pacote v2 (W5, PROPOSTA_WEB §6.4; especificação pública em docs/FORMATO_PACOTE.md).

Geração em streaming: os eventos são lidos por cursor no servidor e escritos direto nas entradas do zip, um arquivo
por percurso, sem lista de eventos na memória. A mesma função serve ao exportador do modo local (CLI) e ao worker de
pacotes; a equivalência local × produção vem daí e é conferida em tests/pacote_v2.py.

Mascarado × sem máscara:
  eventos.jsonl                  só no sem máscara (eventos originais das contas incluídas, por fatia e folha)
  eventos_pseudonimizados.jsonl  só no mascarado (campos pessoais trocados pelos pseudônimos)
  folhas.jsonl                   folhas de todas as fatias incluídas, na ordem de eventos.jsonl; sais só no sem máscara
  requisicoes.jsonl              mascarado: redigido + compromisso com sal (sem o sal); sem máscara: original + sal
  pseudonimos.csv, compromissos.json, documento_origem.*   só no sem máscara
O manifesto não leva texto livre: justificativa, processo e operador vão como compromisso com sal; os atores são
`sub` OIDC. Os sais desses compromissos e os das requisições são derivados (HMAC com chave da DEK), então duas
exportações da mesma base dão os mesmos compromissos.
"""
from __future__ import annotations

import csv
import hashlib
import io
import json
import os
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from zoneinfo import ZoneInfo

import rfc8785
from openpyxl import Workbook
from openpyxl.cell import WriteOnlyCell
from openpyxl.styles import Font
from openpyxl.utils import get_column_letter
from openpyxl.worksheet.table import Table, TableColumn, TableStyleInfo

from . import __version__, custodia, dashboard, merkle, redigir, sigilo
from .chaves import alvo as alvo_de
from .consolidar import ERROS, GLOSSARIO, LOGINS, FALHAS, categoria, consolidar, nome_evento, _case_categoria
from .db import SNAPSHOTS_DA_INVESTIGACAO, conectar, percorrer, registro_trilha, trilha
from .identificador import mascarar_texto
from .pseudonimos import Visao, atribuir, rotulos

FORMATO = 2
LIMITE_LINHAS = 1_048_575
LIMITE_DASHBOARD = int(os.environ.get("AUDITOR_LIMITE_DASHBOARD", "50000"))
CLASSE = {"coberto": "Coberto", "parcial": "Parcial", "sem_dados": "Sem dados"}
EXPEDIENTE = (7, 19)
CAMPOS_NORMALIZAVEIS = ("gerado_em", "exportado_por", "Exportado em", "Exportado por")


# ------------------------------------------------------------------ utilidades
def _naive(ms, tz):
    return datetime.fromtimestamp(ms / 1000, tz).replace(tzinfo=None) if ms is not None else None


def _iso(ms):
    return datetime.fromtimestamp(ms / 1000, timezone.utc).isoformat().replace("+00:00", "Z") if ms is not None else None


def compromisso(sal: bytes, valor) -> str:
    """SHA-256(0x00 ‖ sal ‖ RFC 8785(valor)): mesmo formato das folhas e dos campos livres da trilha."""
    return hashlib.sha256(b"\x00" + sal + merkle.jcs(valor)).hexdigest()


def _sal(cf: sigilo.Cofre, finalidade: str, chave) -> bytes:
    """Sal derivado (HMAC-SHA-256 com chave da DEK): estável entre exportações e imprevisível sem a DEK."""
    return bytes.fromhex(cf.ps(f"sal_{finalidade}", str(chave)))


class _Entrada:
    """Entrada do zip escrita em streaming, com SHA-256 e contagem de linhas. `z=None`: só calcula o hash."""

    def __init__(self, z: zipfile.ZipFile | None, nome: str):
        self.nome, self.h, self.linhas, self.tamanho = nome, hashlib.sha256(), 0, 0
        self.f = z.open(nome, "w", force_zip64=True) if z is not None else None

    def write(self, b: bytes):
        self.h.update(b)
        self.tamanho += len(b)
        if self.f:
            self.f.write(b)

    def linha(self, obj):
        self.write(merkle.jcs(obj) + b"\n")
        self.linhas += 1

    def fechar(self) -> str:
        if self.f:
            self.f.close()
        return self.h.hexdigest()


class _Texto(io.TextIOBase):
    """Adaptador de texto para csv.writer sobre uma _Entrada."""

    def __init__(self, e: _Entrada):
        self.e = e

    def write(self, s):
        self.e.write(s.encode("utf-8"))
        return len(s)


def _fmt_csv(v):
    return v.strftime("%d/%m/%Y %H:%M:%S") if isinstance(v, datetime) else v


class _Planilha:
    """Workbook em modo write-only: cada aba é escrita linha a linha (Tabela do Excel com colunas declaradas)."""

    def __init__(self):
        self.wb = Workbook(write_only=True)
        self.n_tab = 0

    def aba(self, nome, cab, linhas, larguras=None, aviso=None, fmt_data=(), num=()):
        parte, ws, n = 0, None, 0

        def nova():
            nonlocal ws, n, parte
            parte += 1
            ws = self.wb.create_sheet(nome if parte == 1 else f"{nome[:27]} ({parte})")
            for j in range(len(cab)):
                ws.column_dimensions[get_column_letter(j + 1)].width = (larguras or {}).get(j, 18)
            lin0 = 1
            if aviso:
                c = WriteOnlyCell(ws, aviso)
                c.font = Font(bold=True, color="9A6700")
                ws.append([c])
                ws.append([])
                lin0 = 3
            ws.freeze_panes = f"B{lin0 + 1}"
            cabs = []
            for h in cab:
                c = WriteOnlyCell(ws, h)
                c.font = Font(bold=True)
                cabs.append(c)
            ws.append(cabs)
            n = 0
            return lin0

        def fechar(lin0):
            nonlocal n
            if n == 0:
                ws.append([""] * len(cab))
                n = 1
            self.n_tab += 1
            t = Table(displayName=f"T_{''.join(ch for ch in nome if ch.isalnum())[:20]}{self.n_tab}",
                      ref=f"A{lin0}:{get_column_letter(len(cab))}{lin0 + n}")
            t.tableColumns = [TableColumn(id=i + 1, name=str(h)) for i, h in enumerate(cab)]
            t.tableStyleInfo = TableStyleInfo(name="TableStyleMedium2", showRowStripes=True)
            ws.add_table(t)

        lin0 = nova()
        for l in linhas:
            if n >= LIMITE_LINHAS:
                fechar(lin0)
                lin0 = nova()
            cel = []
            for j, v in enumerate(l):
                if j in fmt_data or j in num:
                    c = WriteOnlyCell(ws, v)
                    c.number_format = "dd/mm/yyyy hh:mm:ss" if j in fmt_data else "#,##0"
                    cel.append(c)
                else:
                    cel.append(v)
            ws.append(cel)
            n += 1
        fechar(lin0)

    def bytes(self) -> bytes:
        b = io.BytesIO()
        self.wb.save(b)
        return b.getvalue()


# ------------------------------------------------------------------ percursos
def _fatias_incluidas(cust: dict) -> list[dict]:
    return [f for f in cust["fatias"] if f["incluida"]]


def _eventos_das_fatias(cx, inv_id: int, fatias: list[dict]):
    """Eventos de todas as fatias dadas, por (posição da fatia, folha), num percurso só."""
    return percorrer(cx, "SELECT f.ord, f.fatia, e.id, e.instancia_id, e.realm, e.cifrado, e.folha, e.ps_ip, "
                         "e.ps_sessao FROM unnest(%s::int[], %s::bigint[], %s::int[], %s::bigint[], %s::bigint[]) "
                         "AS f(ord, fatia, conta_id, ini, fim) JOIN evento e ON e.investigacao_id=%s AND "
                         "e.conta_id=f.conta_id AND e.time_ms>=f.ini AND e.time_ms<f.fim ORDER BY f.ord, e.folha",
                     (list(range(len(fatias))), [f["fatia"] for f in fatias], [f["conta_id"] for f in fatias],
                      [f["inicio_ms"] for f in fatias], [f["fim_ms"] for f in fatias], inv_id))


def _where_detalhe(inv: dict) -> tuple[str, dict]:
    """Mesmo conjunto da planilha e do dashboard: período, contas incluídas, categorias Acesso e Conta."""
    return (f"e.investigacao_id=%(inv)s AND e.time_ms >= %(ini)s AND e.time_ms < %(fim)s AND c.incluida "
            f"AND ({_case_categoria()}) = ANY(%(cats)s)",
            {"inv": inv["id"], "ini": inv["inicio_ms"], "fim": inv["fim_ms"], "cats": ["Acesso", "Conta"]})


# ------------------------------------------------------------------ gerar
def gerar(inv_id: int, saida: Path, operador: str, sem_mascara: bool = False, soltos: bool = True,
          nome: str | None = None) -> dict:
    """Gera o pacote v2 em `saida/<nome>.zip`. `soltos=False` (worker): nada além do zip em disco."""
    from . import assinador, carimbo
    with conectar() as cx:
        inv = cx.execute("SELECT * FROM investigacao WHERE id=%s", (inv_id,)).fetchone()
    dig = alvo_de(inv, "exportar")
    cf = sigilo.Cofre(inv_id, "exportar")
    tz = ZoneInfo(inv["fuso"])
    msk = (lambda s: s) if sem_mascara else (lambda s: mascarar_texto(s, inv["tipo"], dig))
    with conectar() as cx:
        atribuir(cx, cf)
        rot = rotulos(cx, inv_id)
        cust = custodia.exigir(cx, cf, inv_id, operador)   # selos conferem, ou não há pacote
        insts = {i["id"]: i for i in cx.execute(
            "SELECT id, uuid::text AS uuid, nome, url, versao_declarada, sondas FROM instancia ORDER BY id")}
    d = consolidar(inv_id, com_eventos=False, amostra=LIMITE_DASHBOARD)
    vis = Visao(sem_mascara, msk, rot, cf)
    vis.conhecer(d["contas"], [])
    vis.conhecer_valores(d["valores"])
    contas = {c["id"]: c for c in d["contas"]}
    uuid = {i: v["uuid"] for i, v in insts.items()}

    def conta_ev(conta_id):
        c = contas.get(conta_id) or {}
        return vis.conta(c)

    fr = d["fracoes"]
    k = d["kpis"]
    filtros_txt = "categorias: " + ", ".join(d["filtros"]["categorias"])
    aviso = None if fr["completa"] else (f"ATENÇÃO: cobertura parcial — realms {fr['realms'][0]}/{fr['realms'][1]}"
                                         f" · tempo {fr['tempo'][0]}/{fr['tempo'][1]} dias. Ver aba Cobertura.")
    just = sigilo.justificativa(cf, inv)
    with conectar() as cx:
        from .casos import _abrir_extras
        extras_inv = _abrir_extras(cf, inv)
        dec = {r["conta_id"]: r for r in cx.execute(
            "SELECT DISTINCT ON (conta_id) * FROM conta_decisao WHERE investigacao_id=%s "
            "ORDER BY conta_id, quando DESC", (inv_id,))}
        snaps = cx.execute("SELECT i.uuid::text AS instancia, s.realm, s.lido_em, s.visivel, s.config, "
                           "s.user_profile, s.federacao, s.status FROM realm_snapshot s JOIN instancia i ON "
                           "i.id=s.instancia_id WHERE " + SNAPSHOTS_DA_INVESTIGACAO + " ORDER BY s.id",
                           {"inv": inv_id}).fetchall()
        doc = cx.execute("SELECT * FROM documento WHERE investigacao_id=%s", (inv_id,)).fetchone()
        n_ev = {r["conta_id"]: r["n"] for r in cx.execute(
            "SELECT conta_id, count(*) n FROM evento WHERE investigacao_id=%s GROUP BY 1", (inv_id,))}
    processo = extras_inv.get("processo")
    nome = nome or f"investigacao_{inv_id}{'_sem_mascara' if sem_mascara else ''}"
    saida.mkdir(parents=True, exist_ok=True)
    zp = saida / f"{nome}.zip"
    parcial = saida / f".{nome}.parcial"
    arquivos: dict[str, str] = {}
    contagens: dict[str, int] = {}
    z = zipfile.ZipFile(parcial, "w", zipfile.ZIP_DEFLATED, allowZip64=True)

    def pequeno(n: str, b: bytes):
        z.writestr(n, b)
        arquivos[n] = hashlib.sha256(b).hexdigest()

    try:
        # ---- 1. eventos.jsonl (sem máscara) ou só o hash (mascarado); pseudônimos dos eventos exportados
        valores_pseudo: dict[tuple[str, str], str] = {}
        ev = _Entrada(z if sem_mascara else None, "eventos.jsonl")
        incl = _fatias_incluidas(cust)
        with conectar() as cx:
            for r in _eventos_das_fatias(cx, inv_id, incl):
                e = sigilo.abrir_evento(cf, r)
                ev.linha({"fatia": r["fatia"], "conta": incl[r["ord"]]["conta_id"],
                          "instancia": uuid[r["instancia_id"]], "realm": r["realm"], "evento": e["bruto"]})
                if sem_mascara:
                    if r["ps_ip"] and e["ip"]:
                        valores_pseudo[("ip", r["ps_ip"])] = e["ip"]
                    if r["ps_sessao"] and e["session_id"]:
                        valores_pseudo[("sessao", r["ps_sessao"])] = e["session_id"]
        sha_eventos, n_eventos = ev.fechar(), ev.linhas
        if sem_mascara:
            arquivos["eventos.jsonl"] = sha_eventos

        # ---- 2. folhas.jsonl (mesma ordem; sal só no sem máscara)
        fo = _Entrada(z, "folhas.jsonl")
        with conectar() as cx:
            for r in _eventos_das_fatias(cx, inv_id, incl):
                linha = {"fatia": r["fatia"], "folha": r["folha"]}
                if sem_mascara:
                    linha["sal"] = sigilo.abrir_evento(cf, r)["sal"]
                fo.linha(linha)
        arquivos["folhas.jsonl"] = fo.fechar()
        contagens["folhas.jsonl"] = fo.linhas

        # ---- 3. eventos_pseudonimizados.jsonl (mascarado): todas as fatias incluídas, por horário
        n_pseudo = 0
        if not sem_mascara:
            ep = _Entrada(z, "eventos_pseudonimizados.jsonl")
            with conectar() as cx:
                for r in percorrer(cx, "SELECT e.time_ms, e.id, e.instancia_id, e.realm, e.conta_id, e.type, "
                                       "e.client_id, e.error, e.ps_ip, e.ps_sessao, e.cifrado, c.via FROM evento e "
                                       "JOIN conta c ON c.id=e.conta_id AND c.incluida WHERE e.investigacao_id=%s "
                                       "ORDER BY e.time_ms, e.id", (inv_id,)):
                    e = sigilo.abrir_evento(cf, r)
                    ep.linha({"t": r["time_ms"], "instancia": uuid[r["instancia_id"]], "realm": r["realm"],
                              "conta_id": r["conta_id"], "conta": conta_ev(r["conta_id"]), "tipo": r["type"],
                              "cliente": r["client_id"], "erro": r["error"],
                              "ip": vis.ip(r["ps_ip"], e["ip"]) if (r["ps_ip"] or e["ip"]) else None,
                              "sessao": vis.sessao(r["ps_sessao"], e["session_id"])
                              if (r["ps_sessao"] or e["session_id"]) else None,
                              "detalhes": vis.json(e["details"] or {})})
            arquivos[ep.nome] = ep.fechar()
            n_pseudo = contagens[ep.nome] = ep.linhas

        # ---- 4. eventos_N.csv e aba "Eventos detalhados" no mesmo percurso
        pl = _Planilha()
        # planilha: abas pequenas primeiro; "Eventos detalhados" no percurso abaixo, junto com o CSV
        leia = [["Objetivo", "Consolidação de acessos de uma pessoa em todas as instâncias e realms Keycloak visíveis."],
                ["Logins", "LOGIN + IDENTITY_PROVIDER_LOGIN"],
                ["Falhas de login", "LOGIN_ERROR + IDENTITY_PROVIDER_LOGIN_ERROR"],
                ["Aplicações", "clientId distintos em Logins"], ["IPs", "IPs distintos em Logins e Falhas"],
                ["Cobertura · realms", "pares realm×conta cobertos ÷ pesquisados ('pesquisado, sem conta' conta como coberto)"],
                ["Cobertura · tempo", "dias com dados em todas as contas com eventos ÷ dias do período"],
                ["Horário", f"Fuso {inv['fuso']}, com coluna UTC; o horário vem do relógio do servidor Keycloak"],
                ["Máscara", "pseudônimos (Conta N, IP N, Sessão N)" if not sem_mascara else
                 "SEM MÁSCARA: valores reais e pseudônimos lado a lado (exportação autorizada)"],
                ["Formato", f"pacote v{FORMATO}; especificação em docs/FORMATO_PACOTE.md"]]
        leia += [[f"Evento {kk}", f"{v[0]} ({v[1]})"] for kk, v in GLOSSARIO.items()]
        leia += [[f"Erro {kk}", v] for kk, v in ERROS.items()]
        pl.aba("Leia-me", ["Item", "Descrição"], leia, {0: 30, 1: 100})
        par = [["Investigação", inv_id], ["Alvo", inv["alvo_mascarado"] if not sem_mascara else dig],
               ["Justificativa", vis.texto(just)], ["Processo", vis.texto(processo) if processo else "—"],
               ["Operador", inv["operador"]], ["Exportado por", operador],
               ["Exportado em", datetime.now(tz).replace(tzinfo=None)],
               ["Período início", _naive(inv["inicio_ms"], tz)], ["Período fim (exclusivo)", _naive(inv["fim_ms"], tz)],
               ["Fuso", inv["fuso"]], ["Granularidade", inv["granularidade"]], ["Filtros aplicados", filtros_txt],
               ["Máscara", "aplicada" if not sem_mascara else "não aplicada"], ["Versão do coletor", __version__]]
        par += [[f"Instância {i['nome']}", f"{i['url']} · versão declarada {i['versao_declarada']} · modo "
                 f"{(i['sondas'] or {}).get('modo')} · id {i['uuid']}"] for i in insts.values()]
        pl.aba("Parâmetros", ["Parâmetro", "Valor"], par, {0: 26, 1: 110}, fmt_data=())
        res = [["Logins", k["logins"]], ["Falhas de login", k["falhas"]], ["Aplicações", k["aplicacoes"]],
               ["IPs", k["ips"]], ["Primeiro acesso", _naive(k["primeiro"], tz)],
               ["Último acesso", _naive(k["ultimo"], tz)],
               ["Cobertura realms", f"{fr['realms'][0]}/{fr['realms'][1]}"],
               ["Cobertura tempo (dias)", f"{fr['tempo'][0]}/{fr['tempo'][1]}"]]
        pl.aba("Resumo", ["Indicador", "Valor"], res, {0: 26, 1: 26},
               aviso=(aviso or "Cobertura completa.") + f"  Exportação filtrada: {filtros_txt}.")
        jan = [[r["janela"], r["instancia"], r["realm"], r["client_id"], categoria(r["type"]), nome_evento(r["type"]),
                r["type"], r["n"], r["ips"]] for r in d["janelas"]]
        cab_jan = ["Janela (início)", "Instância", "Realm", "Aplicação", "Categoria", "Evento", "Código", "Quantidade",
                   "IPs distintos"]
        pl.aba("Consolidado por janela", cab_jan, jan, {0: 20}, fmt_data=(0,), num=(7, 8))
        pl.aba("Por aplicação", ["Instância", "Realm", "Aplicação", "Logins", "Falhas de login", "Primeiro", "Último"],
               [[r["instancia"], r["realm"], r["client_id"], r["logins"], r["falhas"], _naive(r["primeiro"], tz),
                 _naive(r["ultimo"], tz)] for r in d["por_app"]], fmt_data=(5, 6), num=(3, 4))
        pl.aba("Por IP", ["IP", "Eventos", "Falhas de login", "Primeiro", "Último", "Onde"],
               [[vis.ip(r["ps_ip"], r["ip"]), r["n"], r["falhas"], _naive(r["primeiro"], tz), _naive(r["ultimo"], tz),
                 r["onde"]] for r in d["por_ip"]], {5: 50}, fmt_data=(3, 4), num=(1, 2))
        dest = [["Fora do expediente", _naive(e["time_ms"], tz), e["instancia"], e["realm"], conta_ev(e["conta_id"]),
                 e["client_id"], vis.ip(e["ps_ip"], e["ip"]), ""] for e in d["fora"]]
        dest += [["Rajada de falhas", _naive(r["inicio"], tz), r["instancia"], r["realm"],
                  conta_ev(r["conta"]["conta_id"]), "", ", ".join(vis.ip(ps, ip) for ps, ip in r["ips"]),
                  f"{r['n']} falhas até {_naive(r['fim'], tz):%d/%m/%Y %H:%M:%S}"] for r in d["rajadas"]]
        if d["ip_novo"] is None:
            dest.append(["IP novo", None, "", "", "", "", "", "sem base de comparação"])
        else:
            dest += [["IP novo", _naive(e["time_ms"], tz), e["instancia"], e["realm"], conta_ev(e["conta_id"]),
                      e["client_id"], vis.ip(e["ps_ip"], e["ip"]), "primeira ocorrência"] for e in d["ip_novo"]]
        pl.aba("Destaques", ["Destaque", "Data e hora", "Instância", "Realm", "Conta", "Aplicação", "IP", "Observação"],
               dest, {7: 40}, fmt_data=(1,))
        pl.aba("Cobertura", ["Instância", "Realm", "Conta", "Classe", "Status", "Situação", "Próximo passo",
                             "Coberto desde"],
               [[c["instancia"], c["realm"], vis.conta(c) if c["conta_id"] else "—", CLASSE[c["classe"]], c["status"],
                 vis.texto(c["detalhe"]), c["acao"], _naive(c["desde_ms"], tz)] for c in d["cobertura"]],
               {5: 60, 6: 50}, aviso=aviso, fmt_data=(7,))
        conta_l = [["Sessão ativa", x["capturado_em"].astimezone(tz).replace(tzinfo=None), x["instancia"], x["realm"],
                    vis.conta(x), vis.ip_valor(x["dados"].get("ipAddress")), ""]
                   for x in d["extras"] if x["tipo"] == "sessao"]
        conta_l += [["Alteração administrativa", _naive(x["dados"].get("time"), tz), x["instancia"], x["realm"],
                     vis.conta(x), x["dados"].get("operationType"), vis.texto(x["dados"].get("resourcePath"))]
                    for x in d["extras"] if x["tipo"] == "admin"]
        pl.aba("Conta", ["Tipo", "Data e hora", "Instância", "Realm", "Conta", "IP / Operação", "Recurso"], conta_l,
               {6: 50}, fmt_data=(1,))
        cab_det = ["Data e hora local", "Fuso", "Data e hora UTC", "Instância", "Realm", "Conta", "Evento", "Código",
                   "Aplicação", "IP", "Sessão", "Erro", "Código do erro", "Método", "Endereço de retorno",
                   "ID do evento"]
        if sem_mascara:
            cab_det[6:6] = ["Conta (pseudônimo)", "IP (pseudônimo)", "Sessão (pseudônimo)"]
        ce = _Entrada(z, f"eventos_{inv_id}.csv")
        ce.write("﻿".encode())
        w = csv.writer(_Texto(ce), delimiter=";", lineterminator="\r\n")
        w.writerow(cab_det)
        W, A = _where_detalhe(inv)
        n_det = 0

        def linhas_det():
            nonlocal n_det
            with conectar() as cx:
                for r in percorrer(cx, f"SELECT e.time_ms, e.id, e.instancia_id, e.realm, e.conta_id, e.type, "
                                       f"e.client_id, e.error, e.ps_ip, e.ps_sessao, e.cifrado FROM evento e JOIN "
                                       f"conta c ON c.id=e.conta_id WHERE {W} ORDER BY e.time_ms, e.id", A):
                    e = sigilo.abrir_evento(cf, r)
                    dd = e["details"] or {}
                    c = contas.get(r["conta_id"]) or {}
                    l = [_naive(r["time_ms"], tz), inv["fuso"], _naive(r["time_ms"], timezone.utc),
                         insts[r["instancia_id"]]["nome"], r["realm"], vis.conta(c), nome_evento(r["type"]),
                         r["type"], r["client_id"], vis.ip(r["ps_ip"], e["ip"]),
                         vis.sessao(r["ps_sessao"], e["session_id"]), ERROS.get(r["error"], r["error"] or ""),
                         r["error"], dd.get("auth_method"), vis.texto(dd.get("redirect_uri")), r["id"]]
                    if sem_mascara:
                        l[6:6] = [_rotulo_conta(rot, c),
                                  rot.get(("ip", r["ps_ip"])) or "—", rot.get(("sessao", r["ps_sessao"])) or "—"]
                    w.writerow([_fmt_csv(v) for v in l])
                    n_det += 1
                    yield l

        pl.aba("Eventos detalhados", cab_det, linhas_det(), {len(cab_det) - 2: 40, len(cab_det) - 1: 38},
               fmt_data=(0, 2))
        arquivos[ce.nome] = ce.fechar()
        contagens[ce.nome] = n_det

        # ---- 5. requisições (compromisso com sal por linha)
        rq_m = _Entrada(z if not sem_mascara else None, "requisicoes.jsonl")
        rq_s = _Entrada(z if sem_mascara else None, "requisicoes.jsonl")
        comp_req = []
        with conectar() as cx:
            for r in percorrer(cx, "SELECT id, instancia_id, metodo, caminho, params, status, inicio, ms, sha256, "
                                   "bytes, coletor, cifrado FROM requisicao WHERE investigacao_id=%s ORDER BY id",
                               (inv_id,)):
                if r["cifrado"] is not None:   # original (o claro é a versão redigida)
                    r.update(cf.decifrar("requisicao", "cifrado", r["id"], r["cifrado"]))
                orig = {"id": r["id"], "instancia": uuid.get(r["instancia_id"]), "metodo": r["metodo"],
                        "caminho": r["caminho"], "params": r["params"], "status": r["status"],
                        "inicio": r["inicio"].astimezone(timezone.utc).isoformat().replace("+00:00", "Z"),
                        "ms": r["ms"], "sha256": r["sha256"], "bytes": r["bytes"], "coletor": r["coletor"]}
                sal = _sal(cf, "requisicao", r["id"])
                c = compromisso(sal, orig)
                comp_req.append(c)
                rq_s.linha({**orig, "sal": sal.hex(), "compromisso": c})
                rq_m.linha({**orig, "caminho": msk(redigir.caminho(orig["caminho"])),
                            "params": redigir.params(orig["params"]), "compromisso": c})
        sha_req_s, sha_req_m = rq_s.fechar(), rq_m.fechar()
        arquivos["requisicoes.jsonl"] = sha_req_s if sem_mascara else sha_req_m
        contagens["requisicoes.jsonl"] = len(comp_req)

        # ---- 6. arquivos pequenos

        excluidas = []
        for c in d["contas"]:
            if c["incluida"]:
                continue
            x = dec.get(c["id"])
            excluidas.append({"conta": vis.conta(c), "conta_id": c["id"], "instancia": uuid[c["instancia_id"]],
                              "realm": c["realm"], "via": c["via"], "eventos": n_ev.get(c["id"], 0),
                              "motivo": vis.texto(cf.decifrar("conta_decisao", "motivo_cifrado", x["id"],
                                                              bytes(x["motivo_cifrado"]))) if x else None,
                              "por": x["por"] if x else None,
                              "quando": x["quando"].astimezone(timezone.utc).isoformat() if x else None})
        pequeno("contas_excluidas.json", json.dumps(excluidas, ensure_ascii=False, indent=1).encode())

        fatias_doc = []
        for f in cust["fatias"]:
            fatias_doc.append({"fatia": f["fatia"], "conta_id": f["conta_id"], "conta": conta_ev(f["conta_id"]),
                               "instancia": uuid[f["instancia_id"]], "realm": f["realm"], "inicio_ms": f["inicio_ms"],
                               "fim_ms": f["fim_ms"], "eventos": f["eventos"], "raiz": f["raiz"],
                               "versao": f["versao"], "origem": f["origem"], "incluida": f["incluida"]})
        pequeno("fatias.json", json.dumps(fatias_doc, ensure_ascii=False, indent=1).encode())

        cob_doc = [{"instancia": uuid[c["instancia_id"]], "realm": c["realm"], "conta_id": c["conta_id"],
                    "conta": vis.conta(c) if c["conta_id"] else None, "classe": c["classe"], "status": c["status"],
                    "detalhe": vis.texto(c["detalhe"]), "acao": c["acao"], "desde_ms": c["desde_ms"]}
                   for c in d["cobertura"]]
        pequeno("cobertura.json", json.dumps(cob_doc, ensure_ascii=False, indent=1).encode())

        janelas = [{"janela": r["janela"].isoformat(), "instancia": insts_nome_para_uuid(insts, r["instancia"]),
                    "realm": r["realm"], "cliente": r["client_id"], "tipo": r["type"], "n": r["n"], "ips": r["ips"]}
                   for r in d["janelas"]]
        resultados = {
            "formato": FORMATO, "investigacao": inv_id, "fuso": inv["fuso"], "granularidade": inv["granularidade"],
            "periodo": {"inicio_ms": inv["inicio_ms"], "fim_ms": inv["fim_ms"]},
            "regras": {"categorias": d["filtros"]["categorias"], "expediente": list(EXPEDIENTE),
                       "rajada": {"minimo": 5, "janela_ms": 600_000}, "base_dias": inv["parametros"].get("base_dias") or 0},
            "kpis": {"logins": k["logins"], "falhas": k["falhas"], "aplicacoes": k["aplicacoes"], "ips": k["ips"],
                     "eventos": k["eventos"], "primeiro_ms": k["primeiro"], "ultimo_ms": k["ultimo"]},
            "janelas": janelas,
            "destaques": {
                "fora_expediente": sorted([e["time_ms"], uuid[e["instancia_id"]], e["realm"]] for e in d["fora"]),
                "rajadas": sorted([uuid_de_nome(insts, r["instancia"]), r["realm"], r["conta"]["conta_id"],
                                   r["inicio"], r["fim"], r["n"]] for r in d["rajadas"]),
                "ip_novo": None if d["ip_novo"] is None else sorted(e["time_ms"] for e in d["ip_novo"])},
            "cobertura": {"realms": list(fr["realms"]), "tempo": list(fr["tempo"]), "completa": fr["completa"]},
            "eventos_detalhados": n_det,
        }
        b_res = json.dumps(resultados, ensure_ascii=False, indent=1).encode()
        pequeno("resultados.json", b_res)

        pequeno(f"investigacao_{inv_id}.xlsx", pl.bytes())

        s = io.StringIO()
        cw = csv.writer(s, delimiter=";", lineterminator="\r\n")
        cw.writerow(["Janela", "Instância", "Realm", "Aplicação", "Categoria", "Evento", "Código", "Quantidade",
                     "IPs distintos"])
        for l in jan:
            cw.writerow([_fmt_csv(v) for v in l])
        pequeno(f"consolidado_{inv_id}.csv", "﻿".encode() + s.getvalue().encode("utf-8"))
        d["eventos_truncados"] = d["n_eventos"] > len(d["eventos"])
        pequeno(f"dashboard_{inv_id}.html", dashboard.gerar(d, vis).encode())

        if sem_mascara:
            s = io.StringIO()
            cw = csv.writer(s, delimiter=";", lineterminator="\r\n")
            cw.writerow(["Classe", "Pseudônimo", "Valor"])
            for c in d["contas"]:
                r = rot.get(("conta", c.get("ps_conta")))
                if r and c["incluida"]:
                    cw.writerow(["conta", r, " · ".join(str(v) for v in (c.get("username"), c.get("email"),
                                                                         c.get("user_id")) if v)])
            for (classe, ps), v in sorted(valores_pseudo.items(), key=lambda x: (x[0][0], rot.get(x[0], ""))):
                r = rot.get((classe, ps))
                if r:
                    cw.writerow([classe, r, v])
            pequeno("pseudonimos.csv", "﻿".encode() + s.getvalue().encode("utf-8"))
            if doc:
                meta = cf.decifrar("documento", "meta", inv_id, doc["meta_cifrado"])
                ext = {"application/pdf": "pdf", "image/png": "png", "image/jpeg": "jpg"}.get(meta.get("tipo"), "bin")
                pequeno(f"documento_origem.{ext}", cf.decifrar_bytes("documento", "cifrado", inv_id, doc["cifrado"]))

        # compromissos dos campos livres do manifesto (sais derivados; os sais só no sem máscara e no relatório)
        livres = {"justificativa": just, "processo": processo, "operador": inv["operador"]}
        sais = {kk: _sal(cf, "manifesto", kk) for kk, v in livres.items() if v}
        comp = {kk: compromisso(sais[kk], livres[kk]) for kk in sais}
        if sem_mascara:
            pequeno("compromissos.json", json.dumps({kk: {"valor": livres[kk], "sal": sais[kk].hex(),
                                                         "compromisso": comp[kk]} for kk in sais},
                                                    ensure_ascii=False, indent=1).encode())

        # trilha da investigação (sem textos livres) e âncoras
        from .ancora import ancorar_agora, provas_da_cadeia
        with conectar() as cx:
            if not soltos:
                ancorar_agora(cx)
            tr = cx.execute("SELECT * FROM trilha_auditoria WHERE cadeia=%s ORDER BY seq", (inv_id,)).fetchall()
            provas = provas_da_cadeia(cx, inv_id)
        pequeno("trilha.jsonl", b"".join(rfc8785.dumps({**registro_trilha(r), "hash": r["hash"]}) + b"\n" for r in tr))
        for pr in provas:
            base = f"ancoras/{pr['ate'][:19].replace(':', '')}"
            c = dict(pr["carimbo"])
            if c.get("tipo") == "rfc3161":
                import base64
                pequeno(base + ".tsr", base64.b64decode(c["tsr"]))
            pequeno(base + ".json", json.dumps(pr, ensure_ascii=False, indent=1).encode())

        # relatório técnico (PDF/A-2b), gerado de resultados.json e do manifesto parcial
        from . import relatorio
        ident = assinador.identidade_remota()
        n_exc = sum(f["eventos"] for f in cust["fatias"] if not f["incluida"])
        manifesto = {
            "formato": FORMATO, "versao_coletor": __version__,
            "gerado_em": datetime.now(timezone.utc).isoformat(),
            "pacote": {"nome": nome, "mascara": not sem_mascara},
            "investigacao": {"id": inv_id, "alvo": inv["alvo_mascarado"], "tipo": inv["tipo"],
                             "inicio_ms": inv["inicio_ms"], "fim_ms": inv["fim_ms"], "fuso": inv["fuso"],
                             "granularidade": inv["granularidade"], "status": inv["status"],
                             "tipo_processo": inv["tipo_processo"], "execucao_anterior": inv["execucao_anterior"],
                             "parametros": {"varredura": inv["parametros"].get("varredura"),
                                            "base_dias": inv["parametros"].get("base_dias"),
                                            "instancias": inv["parametros"].get("instancias")}},
            "compromissos": comp,
            "atores": {"solicitante": inv["solicitante_sub"], "exportado_por": operador},
            "filtros": d["filtros"],
            "instancias": [{"id": i["uuid"], "nome": i["nome"], "url": i["url"],
                            "versao_declarada": i["versao_declarada"], "sondas": i["sondas"]} for i in insts.values()],
            "snapshots": [{**sn, "lido_em": sn["lido_em"].isoformat()} for sn in snaps],
            "eventos": {"total": n_eventos, "sha256": sha_eventos, "excluidos": n_exc,
                        "pseudonimizados": n_pseudo, "detalhados": n_det},
            "requisicoes": {"total": len(comp_req), "raiz": merkle.raiz(comp_req), "sha256": sha_req_s,
                            "sha256_redigido": sha_req_m},
            "custodia": {"raiz_merkle": cust["raiz"], "fatias_seladas": len(cust["fatias"]),
                         "fatias_excluidas": sum(1 for f in cust["fatias"] if not f["incluida"]),
                         "eventos_selados": cust["eventos_selados"], "eventos_sem_selo": cust["eventos_sem_selo"],
                         "versoes_divergentes": cust["divergencias"]},
            "cobertura": resultados["cobertura"],
            "trilha": {"entradas": len(tr), "cabeca": {"seq": tr[-1]["seq"], "hash": tr[-1]["hash"]} if tr else None,
                       "ancoras": [{"dia": p["dia"], "tipo": p["tipo"], "carimbo": p["carimbo"].get("tipo")}
                                   for p in provas]},
            "documento_origem": {"sha256": doc["sha256"], "tamanho": doc["tamanho"]} if doc else None,
            "carimbo": {"tipo": "rfc3161" if carimbo.configurado() else "ausente",
                        "politica": "carimbo RFC 3161 sobre SHA-256(manifesto.json) em manifesto.tsr"},
            "assinatura": {k2: ident[k2] for k2 in ("key_id", "algoritmo", "impressao_digital")},
        }
        pdf = relatorio.tecnico(manifesto, resultados, b_res, sem_mascara=sem_mascara, sais=sais if sem_mascara
                                else None, livres=livres if sem_mascara else None, extras=_cadeia_custodia(tr))
        pequeno(f"relatorio_{inv_id}.pdf", pdf)
        manifesto["arquivos"] = dict(sorted(arquivos.items()))
        manifesto["contagens"] = dict(sorted(contagens.items()))
        corpo = rfc8785.dumps(json.loads(json.dumps(manifesto, default=str)))
        sig = assinador.assinar(corpo)
        z.writestr("manifesto.json", corpo)
        z.writestr("manifesto.sig", sig)
        tsr = None
        if carimbo.configurado():
            tsr = carimbo.pedir(hashlib.sha256(corpo).digest())
            z.writestr("manifesto.tsr", tsr)
            for nlcr, b in carimbo.lcrs(tsr).items():
                z.writestr(f"lcr/{nlcr}", b)
        z.close()
    except BaseException:
        z.close()
        parcial.unlink(missing_ok=True)
        raise
    os.replace(parcial, zp)
    sha_m = hashlib.sha256(corpo).hexdigest()
    with conectar() as cx:
        trilha(cx, operador, "exportar_sem_mascara" if sem_mascara else "exportar", inv_id, arquivo=zp.name,
               sha256_manifesto=sha_m, formato=FORMATO)
    if soltos:   # modo local: planilha e dashboard também soltos, como na v1
        with zipfile.ZipFile(zp) as zz:
            for n in (f"investigacao_{inv_id}.xlsx", f"dashboard_{inv_id}.html", f"relatorio_{inv_id}.pdf"):
                b, ext = n.rsplit(".", 1)
                (saida / f"{b}{'_SEM_MASCARA' if sem_mascara else ''}.{ext}").write_bytes(zz.read(n))
    return {"pacote": str(zp), "eventos": n_eventos, "detalhados": n_det, "requisicoes": len(comp_req),
            "manifesto_sha256": sha_m, "formato": FORMATO, "carimbo": bool(tsr)}


def revelar_evento(inv_id: int, evento_id: str, operador: str, motivo: str) -> dict:
    """Revelação seletiva verificável (§6.4): o evento original, o seu sal e a prova de inclusão até a raiz da fatia.
    Quem recebe confere com o pacote (mascarado ou não) já entregue: kc-verificar pacote.zip --revelacao arquivo.json.
    `evento_id` é o "ID do evento" da planilha (o id gravado). Vai para a trilha com o motivo."""
    if not motivo or len(motivo.strip()) < 10:
        raise ValueError("Motivo obrigatório (mínimo de 10 caracteres)")
    cf = sigilo.Cofre(inv_id, "exportar")
    with conectar() as cx:
        e = cx.execute("SELECT e.*, i.uuid::text AS inst_uuid FROM evento e JOIN instancia i ON i.id=e.instancia_id "
                       "WHERE e.investigacao_id=%s AND e.id=%s", (inv_id, evento_id)).fetchone()
        if not e:
            raise ValueError("Evento inexistente nesta investigação")
        s_ = cx.execute("SELECT DISTINCT ON (tarefa_id) * FROM selo WHERE investigacao_id=%s AND conta_id=%s AND "
                        "inicio_ms<=%s AND fim_ms>%s ORDER BY tarefa_id, versao DESC",
                        (inv_id, e["conta_id"], e["time_ms"], e["time_ms"])).fetchone()
        if not s_:
            raise ValueError("Evento fora de fatia selada: sem prova de inclusão")
        folhas = [r["folha"] for r in cx.execute(
            "SELECT folha FROM evento WHERE investigacao_id=%s AND conta_id=%s AND time_ms>=%s AND time_ms<%s "
            "ORDER BY folha", (inv_id, s_["conta_id"], s_["inicio_ms"], s_["fim_ms"]))]
        d = sigilo.abrir_evento(cf, e)
        from .ancora import prova
        i = folhas.index(e["folha"])
        out = {"formato": 1, "investigacao": inv_id, "fatia": s_["tarefa_id"], "instancia": e["inst_uuid"],
               "realm": e["realm"], "evento": d["bruto"], "sal": d["sal"], "folha": e["folha"],
               "prova": prova(folhas, i), "raiz_fatia": s_["raiz"]}
        trilha(cx, operador, "revelar_evento_pacote", inv_id, evento=evento_id[:16], fatia=s_["tarefa_id"],
               motivo=motivo)
    return out


def _rotulo_conta(rot: dict, c: dict) -> str:
    if c.get("via") == "varredura":
        return "Tentativas com o identificador"
    if c.get("via") == "realm":
        return "(realm inteiro)"
    return rot.get(("conta", c.get("ps_conta"))) or "—"


def insts_nome_para_uuid(insts: dict, nome: str) -> str:
    return next(i["uuid"] for i in insts.values() if i["nome"] == nome)


uuid_de_nome = insts_nome_para_uuid


def _cadeia_custodia(tr: list[dict]) -> list[dict]:
    """Quem coletou, revelou, exportou e baixou, com datas (relatório, item 6): só ação, ator e horário."""
    acoes = {"criar_investigacao", "pedir_investigacao", "aprovar_investigacao", "designar", "iniciar", "selar_fatia",
             "fechar", "iniciar_sessao_analise", "revelar", "encerrar_sessao_analise", "excluir_conta",
             "incluir_conta", "pedir_pacote", "aprovar_pacote_sem_mascara", "exportar", "exportar_sem_mascara",
             "baixar_pacote", "assinar_manifesto", "aprovar_revelacao", "decidir_pedido"}
    out, selos = [], 0
    for r in tr:
        if r["acao"] == "selar_fatia":
            selos += 1
            continue
        if r["acao"] in acoes or r["acao"].startswith(("aprovar_", "recusar_", "revelar")):
            out.append({"quando": r["quando"], "acao": r["acao"], "ator": r["operador"]})
    if selos:
        out.append({"quando": None, "acao": f"{selos} fatias seladas na coleta", "ator": "coletor"})
    return out

"""Relatório técnico para os autos e relatório agregado, em PDF/A-2b (W5, PROPOSTA_WEB §6.6).

O relatório técnico é gerado a partir de `resultados.json` (os números que a planilha, os CSVs e o dashboard usam) e
do manifesto, e leva o SHA-256 de `resultados.json` nos metadados (palavra-chave `resultados_sha256=`): o
verificador offline recalcula os resultados a partir dos eventos, confere `resultados.json` e confere que o
relatório declara esse mesmo arquivo. Fica pronto para a assinatura do servidor responsável, feita fora do auditor.

O relatório agregado (para o Solicitante) traz só estado, cobertura, totais e série por dia e por aplicação: sem
pseudônimos, IPs, contas ou destaques individuais.

Fontes DejaVu (licença em static/pdf/LICENCA_DEJAVU.txt) e perfil sRGB embutidos, como pede o PDF/A.
"""
from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from pathlib import Path
from zoneinfo import ZoneInfo

from fpdf import FPDF
from fpdf.enums import OutputIntentSubType, XPos, YPos
from fpdf.output import PDFICCProfile

STATIC = Path(__file__).parent / "static" / "pdf"
AZUL = (19, 81, 180)       # gov.br DS primária (#1351b4)
CINZA = (51, 51, 51)
AVISO = (122, 74, 0)       # texto de atenção, contraste > 7:1 no branco


class _Pdf(FPDF):
    def __init__(self, titulo: str, rodape: str):
        super().__init__(enforce_compliance="PDFA_2B")
        self.titulo_doc, self.rodape = titulo, rodape
        self.add_font("dejavu", "", STATIC / "DejaVuSans.ttf")
        self.add_font("dejavu", "B", STATIC / "DejaVuSans-Bold.ttf")
        self.add_font("mono", "", STATIC / "DejaVuSansMono.ttf")
        self.add_output_intent(OutputIntentSubType.PDFA, output_condition_identifier="sRGB IEC61966-2.1",
                               output_condition="sRGB", registry_name="http://www.color.org",
                               dest_output_profile=PDFICCProfile(contents=(STATIC / "sRGB.icc").read_bytes(), n=3,
                                                                 alternate="DeviceRGB"),
                               info="sRGB IEC61966-2.1")
        self.set_lang("pt-BR")
        self.set_title(titulo)
        self.set_creator("kc-auditor")
        self.set_auto_page_break(True, 18)
        self.set_margins(18, 18, 18)

    def header(self):
        self.set_font("dejavu", "", 8)
        self.set_text_color(*CINZA)
        self.cell(0, 5, self.titulo_doc, new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        self.ln(2)

    def footer(self):
        self.set_y(-12)
        self.set_font("dejavu", "", 8)
        self.set_text_color(*CINZA)
        self.cell(0, 5, f"{self.rodape} · página {self.page_no()}/{{nb}}", align="C")

    # ---- blocos
    def h1(self, t):
        self.set_font("dejavu", "B", 16)
        self.set_text_color(*AZUL)
        self.multi_cell(0, 8, t, new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        self.ln(2)

    def h2(self, t):
        if self.get_y() > self.h - 50:
            self.add_page()
        self.ln(3)
        self.set_font("dejavu", "B", 12)
        self.set_text_color(*AZUL)
        self.multi_cell(0, 6.5, t, new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        self.ln(1)

    def p(self, t, cor=CINZA, negrito=False, tam=10):
        self.set_font("dejavu", "B" if negrito else "", tam)
        self.set_text_color(*cor)
        self.multi_cell(0, 5.2, t, new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        self.ln(1)

    def pares(self, linhas, largura=55):
        for k, v in linhas:
            self.set_font("dejavu", "B", 9.5)
            self.set_text_color(*CINZA)
            y = self.get_y()
            self.multi_cell(largura, 5, str(k), new_x=XPos.RIGHT, new_y=YPos.TOP)
            self.set_font("mono" if isinstance(v, str) and _tecnico(v) else "dejavu", "", 9)
            self.multi_cell(0, 5, "—" if v in (None, "") else str(v), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
            self.set_y(max(self.get_y(), y + 5))
        self.ln(1)

    def tabela(self, cab, linhas, larguras=None):
        self.set_font("dejavu", "", 8.5)
        self.set_text_color(*CINZA)
        with self.table(col_widths=larguras, headings_style=_estilo_cab(), line_height=4.8,
                        text_align="LEFT", first_row_as_headings=True) as t:
            r = t.row()
            for c in cab:
                r.cell(str(c))
            for l in linhas:
                r = t.row()
                for c in l:
                    r.cell("—" if c in (None, "") else str(c))
        self.ln(2)


def _estilo_cab():
    from fpdf.fonts import FontFace
    return FontFace(family="dejavu", emphasis="BOLD", color=(255, 255, 255), fill_color=AZUL)


def _tecnico(v: str) -> bool:
    return len(v) >= 32 and all(ch in "0123456789abcdef:-" for ch in v.lower())


def _dt(ms, tz) -> str:
    return datetime.fromtimestamp(ms / 1000, tz).strftime("%d/%m/%Y %H:%M:%S") if ms is not None else "—"


def _n(v) -> str:
    return f"{v:,}".replace(",", ".") if isinstance(v, int) else str(v)


# ------------------------------------------------------------------ técnico
def tecnico(m: dict, res: dict, b_res: bytes, sem_mascara: bool, sais=None, livres=None, extras=None,
            designados=None) -> bytes:
    inv = m["investigacao"]
    tz = ZoneInfo(inv["fuso"])
    sha_res = hashlib.sha256(b_res).hexdigest()
    titulo = f"Relatório técnico · investigação nº {inv['id']}" + (" · SEM MÁSCARA" if sem_mascara else "")
    pdf = _Pdf(titulo, "kc-auditor · relatório técnico para os autos")
    pdf.set_subject("Relatório técnico de auditoria de acessos (Keycloak)")
    pdf.set_keywords(f"kc-auditor formato={m['formato']} resultados_sha256={sha_res}")
    pdf.add_page()
    pdf.h1(f"Relatório técnico — investigação nº {inv['id']}")
    if sem_mascara:
        pdf.p("Pacote SEM MÁSCARA: contém valores reais do alvo e dos terceiros incluídos por decisão registrada. "
              "Juntar ao processo eletrônico com o nível de sigilo adequado.", AVISO, True)
    else:
        pdf.p("Pacote mascarado: contas, IPs e sessões aparecem como pseudônimos (Conta N, IP N, Sessão N).")

    # 1. objeto
    pdf.h2("1. Objeto")
    obj = [("Investigação", f"nº {inv['id']}"), ("Alvo (mascarado)", inv["alvo"]),
           ("Tipo de processo", inv.get("tipo_processo")),
           ("Período", f"{_dt(inv['inicio_ms'], tz)} a {_dt(inv['fim_ms'], tz)} (fim exclusivo), fuso {inv['fuso']}"),
           ("Execução anterior", f"nº {inv['execucao_anterior']}" if inv.get("execucao_anterior") else "—")]
    if livres:
        obj += [("Processo", livres.get("processo")), ("Justificativa", livres.get("justificativa"))]
    else:
        obj += [("Processo", "compromisso " + m["compromissos"].get("processo", "—")),
                ("Justificativa", "compromisso " + m["compromissos"].get("justificativa", "—"))]
    pdf.pares(obj)
    if designados:
        pdf.tabela(["Função", "Pessoa", "Identificador (sub OIDC)"],
                   [[d["funcao"], d.get("nome") or "—", d["sub"]] for d in designados], (35, 55, 84))

    # 2. metodologia
    pdf.h2("2. Metodologia")
    pdf.p("Os eventos foram lidos da Admin API de cada instância Keycloak, com registro do SHA-256 e do tamanho de "
          "toda resposta. Cada evento recebeu, na gravação, um compromisso com sal (folha Merkle); ao concluir cada "
          "tarefa de coleta, a raiz das folhas da fatia foi selada na cadeia da investigação. O horário é o do "
          "relógio do servidor Keycloak.")
    pdf.tabela(["Instância", "Versão declarada", "Modo de coleta (sondas)", "Id imutável"],
               [[i["nome"], i.get("versao_declarada"), (i.get("sondas") or {}).get("modo"), i["id"]]
                for i in m["instancias"]], (30, 30, 40, 74))
    c = m["custodia"]
    pdf.pares([("Fatias seladas", _n(c["fatias_seladas"])), ("Fatias excluídas", _n(c["fatias_excluidas"])),
               ("Eventos selados", _n(c["eventos_selados"])), ("Eventos sem selo", _n(c["eventos_sem_selo"])),
               ("Versões divergentes", ", ".join(f"{k}: {v}" for k, v in (c.get("versoes_divergentes") or {}).items())
                or "nenhuma"),
               ("Granularidade", inv["granularidade"]), ("Categorias", ", ".join(res["regras"]["categorias"]))])

    # 3. cobertura e limitações (antes dos resultados)
    pdf.h2("3. Cobertura e limitações")
    cob = res["cobertura"]
    if not cob["completa"]:
        pdf.p(f"ATENÇÃO: cobertura parcial — realms {cob['realms'][0]}/{cob['realms'][1]}, tempo "
              f"{cob['tempo'][0]}/{cob['tempo'][1]} dias. Os resultados abaixo valem só para o que foi coberto.",
              AVISO, True)
    else:
        pdf.p(f"Cobertura completa: realms {cob['realms'][0]}/{cob['realms'][1]}, tempo "
              f"{cob['tempo'][0]}/{cob['tempo'][1]} dias.")
    pdf.p("Limitações: (a) eventos que o Keycloak já expirou pela retenção configurada não podem ser lidos; (b) o "
          "auditor só detecta alteração na origem entre duas leituras (releitura), não antes da primeira; (c) na "
          "varredura de falhas sem conta e nas buscas de usuário, a prova é o hash do corpo inteiro da resposta mais "
          "as linhas aproveitadas com a posição: um terceiro não consegue verificar que essas linhas pertencem ao "
          "corpo; (d) no pacote mascarado, os eventos pseudonimizados não se ligam às folhas sem os sais.")

    # 4. resultados
    pdf.h2("4. Resultados")
    k = res["kpis"]
    pdf.pares([("Logins", _n(k["logins"])), ("Falhas de login", _n(k["falhas"])),
               ("Aplicações distintas", _n(k["aplicacoes"])), ("IPs distintos", _n(k["ips"])),
               ("Eventos no período", _n(k["eventos"])), ("Primeiro login", _dt(k["primeiro_ms"], tz)),
               ("Último login", _dt(k["ultimo_ms"], tz))])
    por_dia: dict[str, list[int]] = {}
    for j in res["janelas"]:
        dia = j["janela"][:10]
        x = por_dia.setdefault(dia, [0, 0])
        if j["tipo"] in ("LOGIN", "IDENTITY_PROVIDER_LOGIN"):
            x[0] += j["n"]
        elif j["tipo"] in ("LOGIN_ERROR", "IDENTITY_PROVIDER_LOGIN_ERROR"):
            x[1] += j["n"]
    if por_dia:
        dias = sorted(por_dia)
        pdf.p(f"Série por dia ({len(dias)} dias com eventos; mostrados até 40):", negrito=True, tam=9.5)
        pdf.tabela(["Dia", "Logins", "Falhas de login"],
                   [[datetime.fromisoformat(dd).strftime("%d/%m/%Y"), _n(por_dia[dd][0]), _n(por_dia[dd][1])]
                    for dd in dias[:40]], (50, 40, 40))
    ds = res["destaques"]
    pdf.p("Destaques: indícios para análise humana, calculados por regra automática, e não conclusão (LGPD, "
          "art. 20). Critérios: fora do expediente = login em sábado, domingo ou fora de "
          f"{res['regras']['expediente'][0]}h–{res['regras']['expediente'][1]}h (hora local); rajada = "
          f"{res['regras']['rajada']['minimo']} ou mais falhas de login em "
          f"{res['regras']['rajada']['janela_ms'] // 60000} minutos na mesma conta, com sobreposições unidas; IP "
          "novo = IP sem uso no período de base de comparação.", tam=9.5)
    pdf.pares([("Fora do expediente", _n(len(ds["fora_expediente"]))), ("Rajadas de falhas", _n(len(ds["rajadas"]))),
               ("IPs novos", "sem base de comparação" if ds["ip_novo"] is None else _n(len(ds["ip_novo"])))])
    if ds["rajadas"]:
        pdf.tabela(["Início", "Fim", "Realm", "Falhas"],
                   [[_dt(r[3], tz), _dt(r[4], tz), r[1], _n(r[5])] for r in ds["rajadas"][:30]], (50, 50, 44, 30))
    pdf.pares([("Eventos exportados", _n(m["eventos"]["total"])),
               ("Eventos de contas excluídas", _n(m["eventos"]["excluidos"]) + " (por decisão registrada; não entram "
                                                                               "nos arquivos de eventos)")])

    # 5. integridade
    pdf.h2("5. Integridade")
    pdf.pares([("Formato do pacote", f"v{m['formato']} (docs/FORMATO_PACOTE.md)"),
               ("Raiz Merkle da investigação", c["raiz_merkle"]),
               ("Raiz das requisições", m["requisicoes"]["raiz"]),
               ("SHA-256 de eventos.jsonl", m["eventos"]["sha256"]),
               ("SHA-256 de resultados.json", sha_res),
               ("Chave de assinatura", m["assinatura"]["key_id"]),
               ("Impressão digital", m["assinatura"]["impressao_digital"]),
               ("Carimbo do tempo", "RFC 3161 sobre o SHA-256 do manifesto (manifesto.tsr)"
                if m["carimbo"]["tipo"] == "rfc3161" else "sem carimbo do tempo de terceiro neste pacote"),
               ("Âncoras diárias", ", ".join(f"{a['dia']} ({a['carimbo']})" for a in m["trilha"]["ancoras"]) or "—")],
              60)
    pdf.p("O SHA-256 do manifesto e do arquivo do pacote não cabem neste relatório (ele próprio é um arquivo do "
          "pacote): constam do registro de exportação na trilha e são mostrados pelo verificador "
          "(kc-verificar pacote.zip).", tam=9)

    # 6. cadeia de custódia
    pdf.h2("6. Cadeia de custódia")
    if extras:
        pdf.tabela(["Quando (UTC)", "Ação", "Ator (sub OIDC)"],
                   [[(e["quando"].astimezone(timezone.utc).strftime("%d/%m/%Y %H:%M") if e["quando"] else ""),
                     e["acao"], e["ator"]] for e in extras[:120]], (34, 60, 80))
    pdf.p("Segregação: pedido, aprovação e investigação por pessoas distintas (quatro olhos), conferida pelo "
          "servidor em cada decisão; no pedido externo, aprovador diferente do investigador.", tam=9.5)

    # 7. nota metodológica
    pdf.h2("7. Nota metodológica")
    pdf.p("Pseudônimos: cada conta, IP e sessão recebe um rótulo sequencial (Conta 1, IP 12, Sessão 41) calculado "
          "no servidor por HMAC-SHA-256 com chave da investigação; o rótulo nunca muda depois de atribuído e não "
          "permite recuperar o valor.")
    pdf.p("Revelação seletiva verificável: para provar a um juízo que um evento pertence ao conjunto assinado sem "
          "entregar os demais, entrega-se o evento original e o seu sal (python -m auditor revelar-evento). Com "
          "folhas.jsonl e fatias.json deste pacote, qualquer pessoa recalcula a folha SHA-256(0x00 ‖ sal ‖ RFC "
          "8785(evento)), a prova de inclusão até a raiz da fatia e desta até a raiz da investigação, assinada no "
          "manifesto (kc-verificar pacote.zip --revelacao arquivo.json).")
    if sais:
        pdf.h2("Compromissos do manifesto (sais)")
        pdf.p("O manifesto não traz texto livre: justificativa, processo e operador aparecem só como compromisso "
              "SHA-256(0x00 ‖ sal ‖ RFC 8785(texto)). Os sais abaixo permitem conferir.", tam=9)
        pdf.tabela(["Campo", "Sal", "Compromisso"],
                   [[kk, v.hex(), m["compromissos"][kk]] for kk, v in sais.items()], (24, 75, 75))
    pdf.ln(6)
    pdf.p("Local, data e assinatura do servidor responsável (ICP-Brasil ou no processo eletrônico):", negrito=True)
    pdf.ln(14)
    pdf.p("_" * 60)
    return bytes(pdf.output())


# ------------------------------------------------------------------ agregado (solicitante)
def agregado(inv: dict, visao: dict, status: str) -> bytes:
    tz = ZoneInfo(inv["fuso"])
    titulo = f"Relatório agregado · investigação nº {inv['id']}"
    pdf = _Pdf(titulo, "kc-auditor · relatório agregado (sem dados individuais)")
    pdf.set_subject("Relatório agregado de auditoria de acessos")
    pdf.add_page()
    pdf.h1(f"Relatório agregado — investigação nº {inv['id']}")
    pdf.p("Este relatório traz só totais, cobertura e séries por dia e por aplicação: sem pseudônimos, IPs, contas "
          "ou destaques individuais. O relatório técnico completo acompanha o pacote da investigação.")
    pdf.pares([("Estado", status),
               ("Período", f"{_dt(inv['inicio_ms'], tz)} a {_dt(inv['fim_ms'], tz)} (fim exclusivo)"),
               ("Fuso", inv["fuso"]), ("Gerado em", datetime.now(tz).strftime("%d/%m/%Y %H:%M"))])
    pdf.h2("Cobertura")
    cob = visao.get("cobertura") or {}
    if cob.get("calculada"):
        txt = (f"Realms {cob.get('realms_cobertos')}/{cob.get('realms')} · dias {cob.get('dias_cobertos')}/"
               f"{cob.get('dias')}")
        pdf.p(("Cobertura completa: " if cob.get("completa") else "ATENÇÃO: cobertura parcial — ") + txt,
              CINZA if cob.get("completa") else AVISO, not cob.get("completa"))
    else:
        pdf.p("Cobertura ainda não calculada.")
    pdf.h2("Totais")
    k = visao["kpis"]
    pdf.pares([("Logins", _n(k["logins"])), ("Falhas de login", _n(k["falhas"])),
               ("Aplicações", _n(k["aplicacoes"]))])
    if visao.get("serie_dia"):
        pdf.h2("Série por dia")
        pdf.tabela(["Dia", "Logins", "Falhas de login"],
                   [[datetime.fromisoformat(s["dia"]).strftime("%d/%m/%Y"), _n(s["logins"]), _n(s["falhas"])]
                    for s in visao["serie_dia"][:62]], (50, 40, 40))
    if visao.get("aplicacoes"):
        pdf.h2("Logins por aplicação")
        pdf.tabela(["Aplicação", "Logins"], [[a["aplicacao"], _n(a["logins"])] for a in visao["aplicacoes"][:40]],
                   (120, 40))
    return bytes(pdf.output())


# ------------------------------------------------------------------ tabela do ofício (W4) em PDF/A
def tabela_oficio(inv_id: int, pedido: int, linhas: list[list], cab: list[str], meta: dict) -> bytes:
    pdf = _Pdf(f"Tabela para ofício · lista nº {pedido} · investigação nº {inv_id}",
               "kc-auditor · tabela para ofício (dados identificados: sigilo)")
    pdf.add_page()
    pdf.h1(f"Tabela para ofício — lista nº {pedido}")
    pdf.p("Documento com dados identificados, aprovado por quatro olhos. Uso restrito ao ofício indicado.", AVISO,
          True)
    pdf.pares([(k, v) for k, v in meta.items()])
    pdf.tabela(cab, linhas)
    return bytes(pdf.output())

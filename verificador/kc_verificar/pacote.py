"""Verificação de um pacote v2 (FORMATO_PACOTE.md). Sem banco e sem rede: só o zip, as chaves públicas publicadas,
as raízes confiáveis e as LCRs que vieram no pacote.

Cada conferência vira um item do relatório: ok, aviso ou falha. O pacote é íntegro quando não há falha.
"""
from __future__ import annotations

import base64
import csv
import hashlib
import io
import json
import re
import zipfile
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from xml.etree import ElementTree as ET

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from . import merkle, rfc3161

AQUI = Path(__file__).parent
LIMITE_ZIP = 2 * 1024 ** 3            # 2 GB descompactados
LIMITE_TAXA = 200                     # descompactado ÷ compactado, por arquivo (zip bomb)
LIMITE_ARQUIVOS = 10_000
FIXOS = {"manifesto.json", "manifesto.sig", "manifesto.tsr"}


@dataclass
class Item:
    nivel: str          # ok | aviso | falha
    texto: str


@dataclass
class Relatorio:
    itens: list[Item] = field(default_factory=list)
    resumo: dict = field(default_factory=dict)

    def ok(self, t):
        self.itens.append(Item("ok", t))

    def aviso(self, t):
        self.itens.append(Item("aviso", t))

    def falha(self, t):
        self.itens.append(Item("falha", t))

    @property
    def integro(self) -> bool:
        return not any(i.nivel == "falha" for i in self.itens)


# ------------------------------------------------------------------ confiança
def chaves_publicadas(extra: Path | None = None) -> list[dict]:
    lista = json.loads((AQUI / "chaves" / "chaves.json").read_text())["chaves"]
    if extra:
        lista += json.loads(extra.read_text())["chaves"]
    return lista


def raizes(homologacao: bool = False, extra: Path | None = None) -> list[x509.Certificate]:
    pastas = [AQUI / "raizes" / "icp-brasil"] + ([AQUI / "raizes" / "homologacao"] if homologacao else [])
    if extra:
        pastas.append(extra)
    out = []
    for p in pastas:
        for f in sorted(p.glob("*.pem")) + sorted(p.glob("*.crt")) if p.exists() else ():
            dados = f.read_bytes()
            out.append(x509.load_pem_x509_certificate(dados) if b"-----BEGIN" in dados
                       else x509.load_der_x509_certificate(dados))
    return out


# ------------------------------------------------------------------ zip
def _abrir(caminho: Path, r: Relatorio) -> zipfile.ZipFile | None:
    try:
        z = zipfile.ZipFile(caminho)
    except zipfile.BadZipFile:
        r.falha("o arquivo não é um zip válido")
        return None
    infos = z.infolist()
    total = sum(i.file_size for i in infos)
    if len(infos) > LIMITE_ARQUIVOS or total > LIMITE_ZIP:
        r.falha(f"pacote acima dos limites ({len(infos)} arquivos, {total} bytes descompactados)")
        return None
    for i in infos:
        n = i.filename
        if n.startswith("/") or ".." in Path(n).parts or "\\" in n:
            r.falha(f"nome de arquivo inseguro no zip: {n!r}")
            return None
        if i.compress_size and i.file_size / i.compress_size > LIMITE_TAXA and i.file_size > 1024 ** 2:
            r.falha(f"{n}: taxa de compressão suspeita (zip bomb)")
            return None
    return z


def _sha_arquivo(p: Path) -> str:
    h = hashlib.sha256()
    with p.open("rb") as f:
        for bloco in iter(lambda: f.read(1 << 20), b""):
            h.update(bloco)
    return h.hexdigest()


def _sha(z: zipfile.ZipFile, nome: str) -> str:
    h = hashlib.sha256()
    with z.open(nome) as f:
        for bloco in iter(lambda: f.read(1 << 20), b""):
            h.update(bloco)
    return h.hexdigest()


def _linhas(z: zipfile.ZipFile, nome: str):
    with z.open(nome) as f:
        for l in io.TextIOWrapper(f, encoding="utf-8", newline="\n"):
            if l.strip():
                yield json.loads(l)


# ------------------------------------------------------------------ verificação
def verificar(caminho: Path, homologacao: bool = False, chaves_extra: Path | None = None,
              raizes_extra: Path | None = None, recalcular: bool = False, revelacao: Path | None = None) -> Relatorio:
    r = Relatorio()
    z = _abrir(caminho, r)
    if z is None:
        return r
    with z:
        nomes = set(z.namelist())
        for n in ("manifesto.json", "manifesto.sig"):
            if n not in nomes:
                r.falha(f"{n} ausente")
                return r
        corpo = z.read("manifesto.json")
        try:
            m = json.loads(corpo)
        except ValueError:
            r.falha("manifesto.json ilegível")
            return r
        if m.get("formato") != 2:
            r.falha(f"formato {m.get('formato', 1)}: este verificador confere o formato 2 (pacotes v1: "
                    "python -m auditor verificar)")
            return r
        sha_m = hashlib.sha256(corpo).hexdigest()
        r.resumo.update(manifesto_sha256=sha_m, pacote_sha256=_sha_arquivo(caminho),
                        investigacao=m["investigacao"]["id"], mascara=m["pacote"]["mascara"])
        if merkle.jcs(m) != corpo:
            r.falha("manifesto.json não está em JSON canônico (RFC 8785)")
        _assinatura(z, m, corpo, r, chaves_extra)
        _carimbo(z, m, corpo, r, homologacao, raizes_extra)
        _arquivos(z, m, nomes, r)
        fatias = _custodia(z, m, r)
        if not m["pacote"]["mascara"]:
            _eventos_originais(z, m, r)
        _requisicoes(z, m, r)
        cab = _trilha(z, m, fatias, r)
        _ancoras(z, m, cab, r, homologacao, raizes_extra)
        _sem_mascara(z, m, nomes, r)
        _relatorio_pdf(z, m, r)
        if recalcular:
            from .recalcular import recalcular as rec
            rec(z, m, r)
        if revelacao:
            revelacao_seletiva(z, m, revelacao, r)
    return r


def _assinatura(z, m, corpo, r: Relatorio, extra):
    a = m.get("assinatura") or {}
    ch = next((k for k in chaves_publicadas(extra) if k["key_id"] == a.get("key_id")
               and k["impressao_digital"] == a.get("impressao_digital")), None)
    if ch is None:
        r.falha(f"chave {a.get('key_id')} não está entre as chaves publicadas")
        return
    bruta = base64.b64decode(ch["chave_publica"])
    if hashlib.sha256(bruta).hexdigest() != ch["impressao_digital"]:
        r.falha("impressão digital da chave publicada não confere")
        return
    try:
        Ed25519PublicKey.from_public_bytes(bruta).verify(z.read("manifesto.sig"), corpo)
    except (InvalidSignature, ValueError):
        r.falha("assinatura do manifesto não confere")
        return
    r.resumo.update(key_id=ch["key_id"], chave_publicada_em=ch.get("publicada_em"))
    if ch.get("revogada_em"):
        r.aviso(f"a chave {ch['key_id']} foi revogada em {ch['revogada_em']}: vale só se o carimbo do tempo for "
                "anterior")
        r.resumo["chave_revogada_em"] = ch["revogada_em"]
    r.ok(f"assinatura do manifesto confere (chave {ch['key_id']}, publicada em {ch.get('publicada_em')})")


def _carimbo(z, m, corpo, r: Relatorio, homologacao, raizes_extra):
    if "manifesto.tsr" not in z.namelist():
        if (m.get("carimbo") or {}).get("tipo") == "rfc3161":
            r.falha("o manifesto declara carimbo do tempo, mas manifesto.tsr está ausente")
        else:
            r.aviso("pacote sem carimbo do tempo de terceiro: a data é só a declarada pelo sistema")
        return
    lcrs = []
    for n in z.namelist():
        if n.startswith("lcr/"):
            try:
                lcrs.append(x509.load_der_x509_crl(z.read(n)))
            except ValueError:
                r.aviso(f"{n}: LCR ilegível")
    v = rfc3161.verificar(z.read("manifesto.tsr"), hashlib.sha256(corpo).digest(), raizes(homologacao, raizes_extra),
                          lcrs)
    for a in v.avisos:
        r.aviso(a)
    if not v.ok:
        for p in v.problemas:
            r.falha(f"carimbo do tempo: {p}")
        return
    r.resumo.update(carimbado_em=v.gen_time.isoformat(), act=v.act, raiz_act=v.raiz,
                    revogacao_conferida_ate=v.revogacao_ate.isoformat() if v.revogacao_ate else None)
    if "homologacao" in (v.raiz or "").lower():
        r.aviso("carimbo de uma ACT de HOMOLOGAÇÃO (raiz de teste, não ICP-Brasil): não atesta data perante terceiros")
    rev = r.resumo.get("chave_revogada_em")
    if rev and v.gen_time.date().isoformat() >= rev:
        r.falha(f"assinatura feita com a chave já revogada (carimbo de {v.gen_time.date()}, revogação {rev})")
    r.ok(f"carimbo do tempo RFC 3161 confere ({v.gen_time:%d/%m/%Y %H:%M:%S} UTC; revogação conferida até "
         f"{v.revogacao_ate:%d/%m/%Y %H:%M} pelas LCRs do pacote)" if v.revogacao_ate else
         f"carimbo do tempo RFC 3161 confere ({v.gen_time:%d/%m/%Y %H:%M:%S} UTC; revogação não conferida)")


def _arquivos(z, m, nomes, r: Relatorio):
    declarados = m.get("arquivos") or {}
    ruins = 0
    for n, h in declarados.items():
        if n not in nomes:
            r.falha(f"{n}: declarado no manifesto e ausente do pacote")
            ruins += 1
        elif _sha(z, n) != h:
            r.falha(f"{n}: SHA-256 diferente do manifesto (arquivo alterado)")
            ruins += 1
    extras = sorted(n for n in nomes - set(declarados) - FIXOS if not n.startswith("lcr/") and not n.endswith("/"))
    for n in extras:
        r.falha(f"{n}: arquivo no pacote que o manifesto não declara")
    if not ruins and not extras:
        r.ok(f"{len(declarados)} arquivos conferem com o SHA-256 do manifesto")
    for n, esperado in (m.get("contagens") or {}).items():
        if n in nomes:
            with z.open(n) as f:
                k = sum(1 for _ in f) - (1 if n.endswith(".csv") else 0)
            if k != esperado:
                r.falha(f"{n}: {k} linhas, o manifesto declara {esperado}")


def _custodia(z, m, r: Relatorio) -> list[dict]:
    fatias = json.loads(z.read("fatias.json"))
    incl = [f for f in fatias if f["incluida"]]
    pos = {f["fatia"]: i for i, f in enumerate(incl)}
    folhas_por = [[] for _ in incl]
    ordem_ok, ultimo = True, (-1, "")
    for l in _linhas(z, "folhas.jsonl"):
        i = pos.get(l["fatia"])
        if i is None:
            r.falha(f"folhas.jsonl: folha de fatia não incluída ou desconhecida ({l['fatia']})")
            continue
        if (i, l["folha"]) < ultimo:
            ordem_ok = False
        ultimo = (i, l["folha"])
        folhas_por[i].append(l["folha"])
    if not ordem_ok:
        r.falha("folhas.jsonl fora da ordem (fatia de fatias.json, folha)")
    ruins = 0
    for f, fs in zip(incl, folhas_por):
        if len(fs) != f["eventos"] or merkle.raiz(fs) != f["raiz"]:
            ruins += 1
            if ruins <= 5:
                r.falha(f"fatia {f['fatia']}: as folhas não reproduzem a raiz selada ({len(fs)} folhas, selo com "
                        f"{f['eventos']} eventos)")
    raiz = merkle.raiz([f["raiz"] for f in fatias])
    c = m["custodia"]
    if raiz != c["raiz_merkle"]:
        r.falha("a raiz das fatias não é a raiz Merkle assinada no manifesto")
    if len(fatias) != c["fatias_seladas"] or sum(f["eventos"] for f in fatias) != c["eventos_selados"]:
        r.falha("número de fatias ou de eventos selados diferente do manifesto")
    exc = [f for f in fatias if not f["incluida"]]
    if not ruins and raiz == c["raiz_merkle"]:
        r.ok(f"{sum(len(x) for x in folhas_por)} folhas reproduzem as {len(incl)} raízes de fatia incluídas, e as "
             f"{len(fatias)} raízes reproduzem a raiz Merkle assinada")
    if exc:
        decisoes = {x["conta_id"]: x for x in json.loads(z.read("contas_excluidas.json"))}
        sem = {f["conta_id"] for f in exc if not (decisoes.get(f["conta_id"]) or {}).get("quando")}
        if sem:
            r.falha(f"{len(sem)} conta(s) com fatias fora do pacote sem decisão de exclusão registrada")
        n = sum(f["eventos"] for f in exc)
        r.ok(f"{n} eventos de {len({f['conta_id'] for f in exc})} conta(s) excluídas por decisão registrada; nada "
             "mais foi omitido (todas as raízes seladas entram na raiz da investigação)")
        if n != m["eventos"]["excluidos"]:
            r.falha("contagem de eventos excluídos diferente do manifesto")
    if c.get("eventos_sem_selo"):
        r.aviso(f"{c['eventos_sem_selo']} evento(s) sem selo de fatia ficaram fora do pacote")
    r.resumo.update(raiz_merkle=c["raiz_merkle"], fatias=len(fatias), fatias_excluidas=len(exc))
    return fatias


def _eventos_originais(z, m, r: Relatorio):
    if "eventos.jsonl" not in z.namelist():
        r.falha("pacote sem máscara sem eventos.jsonl")
        return
    folhas = _linhas(z, "folhas.jsonl")
    n = ruins = 0
    for e in _linhas(z, "eventos.jsonl"):
        f = next(folhas, None)
        n += 1
        if f is None or f["fatia"] != e["fatia"] or "sal" not in f or \
                merkle.folha(bytes.fromhex(f["sal"]), e["evento"]) != f["folha"]:
            ruins += 1
            if ruins <= 5:
                r.falha(f"evento {n} de eventos.jsonl não reproduz a sua folha (evento ou sal alterado)")
    if next(folhas, None) is not None:
        r.falha("folhas.jsonl tem mais linhas que eventos.jsonl")
    if n != m["eventos"]["total"]:
        r.falha(f"eventos.jsonl tem {n} eventos, o manifesto declara {m['eventos']['total']}")
    if not ruins:
        r.ok(f"cada um dos {n} eventos originais, com o seu sal, reproduz a sua folha")


def _requisicoes(z, m, r: Relatorio):
    comps, ruins, n = [], 0, 0
    mascara = m["pacote"]["mascara"]
    for l in _linhas(z, "requisicoes.jsonl"):
        n += 1
        comps.append(l["compromisso"])
        if not mascara:
            orig = {k: v for k, v in l.items() if k not in ("sal", "compromisso")}
            if merkle.compromisso(bytes.fromhex(l["sal"]), orig) != l["compromisso"]:
                ruins += 1
        elif "sal" in l:
            r.falha("requisicoes.jsonl do pacote mascarado traz sal")
            return
    q = m["requisicoes"]
    if merkle.raiz(comps) != q["raiz"] or n != q["total"]:
        r.falha("compromissos das requisições não reproduzem a raiz do manifesto")
    elif ruins:
        r.falha(f"{ruins} requisição(ões) não reproduzem o compromisso (linha ou sal alterado)")
    else:
        r.ok(f"{n} requisições à Admin API: compromissos reproduzem a raiz assinada"
             + ("" if mascara else ", e cada linha original reproduz o seu compromisso"))


def _trilha(z, m, fatias, r: Relatorio) -> dict | None:
    cadeia = m["investigacao"]["id"]
    ant, esperado, ruins, cab = merkle.genese(cadeia), 1, 0, None
    selos = {}
    for l in _linhas(z, "trilha.jsonl"):
        h = l.pop("hash")
        if l["seq"] != esperado or l["anterior"] != ant or l["cadeia"] != cadeia:
            ruins += 1
        if hashlib.sha256(merkle.jcs(l)).hexdigest() != h:
            ruins += 1
        if l["acao"] == "selar_fatia":
            dd = l["detalhe"]
            selos[(dd.get("tarefa"), dd.get("versao"))] = dd.get("raiz")
        ant, esperado, cab = h, l["seq"] + 1, {"cadeia": cadeia, "seq": l["seq"], "hash": h}
    if ruins:
        r.falha(f"trilha.jsonl: {ruins} problema(s) de encadeamento ou de hash (registro alterado ou faltando)")
    tc = (m.get("trilha") or {}).get("cabeca")
    if tc and (not cab or cab["seq"] != tc["seq"] or cab["hash"] != tc["hash"]):
        r.falha("a cabeça da trilha não é a declarada no manifesto")
    sem = [f["fatia"] for f in fatias if selos.get((f["fatia"], f["versao"])) != f["raiz"]]
    if sem:
        r.falha(f"{len(sem)} fatia(s) sem o selo correspondente na trilha")
    if not ruins and not sem:
        r.ok(f"trilha da investigação íntegra ({esperado - 1} registros encadeados); cada raiz de fatia está selada "
             "na trilha")
    return cab


def _ancoras(z, m, cab, r: Relatorio, homologacao, raizes_extra):
    ancs = sorted(n for n in z.namelist() if n.startswith("ancoras/") and n.endswith(".json"))
    if not ancs:
        r.aviso("pacote sem âncora diária")
        return
    trilha = {}
    for l in _linhas(z, "trilha.jsonl"):
        trilha[l["seq"]] = l["hash"]
    ok, simulados = 0, 0
    for n in ancs:
        a = json.loads(z.read(n))
        c = a["cabeca"]
        if trilha.get(c["seq"]) != c["hash"]:
            r.falha(f"{n}: a cabeça ancorada não está na trilha do pacote")
            continue
        if merkle.folha_cabeca(c) != a["folha"] or merkle.subir(a["folha"], a["prova"]) != a["raiz"]:
            r.falha(f"{n}: a prova de inclusão não leva à raiz do dia")
            continue
        car = a["carimbo"]
        if car.get("tipo") == "rfc3161":
            tsr = n[:-5] + ".tsr"
            dados = z.read(tsr) if tsr in z.namelist() else base64.b64decode(car["tsr"])
            v = rfc3161.verificar(dados, bytes.fromhex(a["raiz"]), raizes(homologacao, raizes_extra))
            if not v.ok:
                r.falha(f"{n}: carimbo da âncora não confere ({'; '.join(v.problemas)})")
                continue
        else:
            simulados += 1
            corpo = {"raiz": car["raiz"], "carimbado_em": car["carimbado_em"], "politica": car["politica"]}
            try:
                Ed25519PublicKey.from_public_bytes(base64.b64decode(car["chave_publica"])).verify(
                    base64.b64decode(car["assinatura"]), merkle.jcs(corpo))
            except (InvalidSignature, ValueError):
                r.falha(f"{n}: carimbo simulado não confere")
                continue
            if car["raiz"] != a["raiz"]:
                r.falha(f"{n}: carimbo de outra raiz")
                continue
        ok += 1
    if ok:
        r.ok(f"{ok} âncora(s): a cabeça da trilha está na árvore do dia e o carimbo confere")
    if simulados:
        r.aviso(f"{simulados} âncora(s) com carimbo SIMULADO (anteriores à ACT): não atestam data perante terceiros")


def _sem_mascara(z, m, nomes, r: Relatorio):
    if m["pacote"]["mascara"]:
        proibidos = [n for n in ("eventos.jsonl", "pseudonimos.csv", "compromissos.json") if n in nomes]
        if proibidos or any(n.startswith("documento_origem.") for n in nomes):
            r.falha(f"pacote mascarado contém arquivos do sem máscara: {', '.join(proibidos) or 'documento_origem'}")
        with z.open("folhas.jsonl") as f:
            if b'"sal"' in f.read(1 << 16):
                r.falha("folhas.jsonl do pacote mascarado traz sais")
        return
    if "compromissos.json" in nomes:
        cs = json.loads(z.read("compromissos.json"))
        ruins = [k for k, v in cs.items() if merkle.compromisso(bytes.fromhex(v["sal"]), v["valor"]) != v["compromisso"]
                 or m["compromissos"].get(k) != v["compromisso"]]
        if ruins:
            r.falha(f"compromissos do manifesto não conferem: {', '.join(ruins)}")
        else:
            r.ok(f"compromissos do manifesto conferem com os textos e sais ({', '.join(cs)})")
    doc = m.get("documento_origem")
    if doc:
        arq = next((n for n in nomes if n.startswith("documento_origem.")), None)
        if not arq or _sha(z, arq) != doc["sha256"]:
            r.falha("documento de origem ausente ou diferente do hash declarado")
        else:
            r.ok("documento de origem confere com o hash declarado")


def _relatorio_pdf(z, m, r: Relatorio):
    n = f"relatorio_{m['investigacao']['id']}.pdf"
    if n not in z.namelist():
        r.falha("relatório técnico ausente")
        return
    pdf = z.read(n)
    sha_res = _sha(z, "resultados.json")
    if not pdf.startswith(b"%PDF-"):
        r.falha("relatório técnico não é PDF")
    elif not re.search(rb"pdfaid:part[^0-9]{0,4}2", pdf):
        r.falha("relatório técnico não se declara PDF/A-2")
    elif f"resultados_sha256={sha_res}".encode() not in pdf:
        r.falha("o relatório técnico não foi gerado do resultados.json deste pacote")
    else:
        r.ok("relatório técnico (PDF/A-2b) gerado do resultados.json deste pacote")


# ------------------------------------------------------------------ revelação seletiva
def revelacao_seletiva(z, m, arq: Path, r: Relatorio):
    """Um evento entregue depois, com o seu sal, pertence ao conjunto assinado deste pacote?"""
    rv = json.loads(arq.read_text())
    folha = merkle.folha(bytes.fromhex(rv["sal"]), rv["evento"])
    fatias = json.loads(z.read("fatias.json"))
    f = next((x for x in fatias if x["fatia"] == rv["fatia"]), None)
    if f is None:
        r.falha("revelação: fatia desconhecida neste pacote")
        return
    if merkle.subir(folha, rv["prova"]) != f["raiz"]:
        r.falha("revelação: o evento, com o sal entregue, NÃO pertence à fatia selada")
        return
    idx = fatias.index(f)
    if merkle.subir(f["raiz"], merkle.prova([x["raiz"] for x in fatias], idx)) != m["custodia"]["raiz_merkle"]:
        r.falha("revelação: a fatia não leva à raiz assinada")
        return
    if f["incluida"]:
        presentes = {l["folha"] for l in _linhas(z, "folhas.jsonl") if l["fatia"] == f["fatia"]}
        if folha not in presentes:
            r.falha("revelação: a folha não está em folhas.jsonl")
            return
    r.ok(f"revelação seletiva: o evento entregue pertence ao conjunto assinado (fatia {f['fatia']}, folha "
         f"{folha[:16]}…, raiz {m['custodia']['raiz_merkle'][:16]}…)")


# ------------------------------------------------------------------ leitura de planilha e CSV (recalcular)
def percorrer_csv(z, nome):
    """Linhas de um CSV do pacote, em streaming (o CSV de eventos pode ter centenas de milhares de linhas)."""
    with z.open(nome) as f:
        yield from csv.reader(io.TextIOWrapper(f, encoding="utf-8-sig", newline=""), delimiter=";")


def ler_csv(z, nome) -> list[list[str]]:
    texto = z.read(nome).decode("utf-8-sig")
    return list(csv.reader(io.StringIO(texto), delimiter=";"))


def ler_aba_xlsx(z_pacote, nome_xlsx: str, aba: str) -> list[list[str]]:
    """Valores de uma aba de um .xlsx com a biblioteca padrão (xml + zip), sem openpyxl."""
    ns = {"m": "http://schemas.openxmlformats.org/spreadsheetml/2006/main",
          "r": "http://schemas.openxmlformats.org/officeDocument/2006/relationships"}
    with zipfile.ZipFile(io.BytesIO(z_pacote.read(nome_xlsx))) as x:
        wb = ET.fromstring(x.read("xl/workbook.xml"))
        rid = next(s.get(f"{{{ns['r']}}}id") for s in wb.find("m:sheets", ns) if s.get("name") == aba)
        rels = ET.fromstring(x.read("xl/_rels/workbook.xml.rels"))
        alvo = next(e.get("Target") for e in rels if e.get("Id") == rid).lstrip("/")
        alvo = alvo if alvo.startswith("xl/") else "xl/" + alvo
        comp = []
        if "xl/sharedStrings.xml" in x.namelist():
            for si in ET.fromstring(x.read("xl/sharedStrings.xml")).findall("m:si", ns):
                comp.append("".join(t.text or "" for t in si.iter(f"{{{ns['m']}}}t")))
        linhas = []
        for row in ET.fromstring(x.read(alvo)).iter(f"{{{ns['m']}}}row"):
            l = []
            for c in row.findall("m:c", ns):
                t, v = c.get("t"), c.find("m:v", ns)
                if t == "s":
                    l.append(comp[int(v.text)])
                elif t == "inlineStr":
                    l.append("".join(x2.text or "" for x2 in c.iter(f"{{{ns['m']}}}t")))
                else:
                    l.append(v.text if v is not None else "")
            linhas.append(l)
        return linhas


def agora() -> str:
    return datetime.now(timezone.utc).isoformat()

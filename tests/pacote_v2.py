"""Aceite da W5 — pacote v2 e prova (PROPOSTA_WEB §6.4 a §6.6):

1. Pacotes mascarado e sem máscara gerados em streaming; o verificador offline (kc-verificar, sem banco e sem rede)
   aprova os dois, e `--recalcular` confere relatório, consolidado, destaques e cobertura.
2. Adulterações detectadas: arquivo alterado, arquivo a mais, manifesto sem assinatura válida, evento original
   alterado, chave não publicada, e um worker comprometido que re-assina resultados falsos (pego pelo --recalcular).
3. Conta excluída por decisão: sai dos arquivos de eventos, o verificador mostra "N eventos de K contas excluídas" e
   confere que nada mais foi omitido.
4. Revelação seletiva verificável: um evento e o seu sal, entregues depois, conferem com o pacote mascarado; o
   evento alterado não confere.
5. Força bruta de IPv4 e de CPF contra as folhas, as linhas de requisição e todo hash do pacote mascarado: nenhuma
   confirmação (com controle positivo: com o sal, a folha é encontrada). Nenhum valor real em claro no mascarado.
6. Equivalência local × produção: o exportador da CLI (chave local) e o worker de pacotes (assinador HTTP com a chave
   do Vault Transit) dão a mesma raiz Merkle, os mesmos eventos.sha256, requisicoes.sha256, fatias.json e os
   derivados (XLSX, CSV, HTML, resultados do PDF) iguais depois de normalizados os campos de geração.

  source env; AUDITOR_TSA_URL=http://localhost:8318/tsa AUDITOR_TSA_HOMOLOGACAO=1 python tests/pacote_v2.py [--inv 14]

Precisa da ACT de homologação (infra/act_homologacao.py --porta 8318) e do Vault da stack (chaves/vault/assinador.token).
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import io
import json
import os
import re
import secrets
import shutil
import subprocess
import sys
import tempfile
import time
import zipfile
from pathlib import Path

RAIZ = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(RAIZ))
sys.path.insert(0, str(RAIZ / "verificador"))

from kc_verificar import merkle as vm  # noqa: E402
from kc_verificar.pacote import verificar  # noqa: E402

FALHAS: list[str] = []
SAIDA = RAIZ / "saida" / "teste_pacote_v2"


def checar(ok: bool, nome: str, det: str = ""):
    print(f"[{'ok' if ok else 'FALHA'}] {nome}" + (f" — {det}" if det else ""))
    if not ok:
        FALHAS.append(nome)


def niveis(r, nivel="falha") -> list[str]:
    return [i.texto for i in r.itens if i.nivel == nivel]


def regravar(origem: Path, destino: Path, trocar: dict[str, bytes | None], extra: dict[str, bytes] | None = None):
    with zipfile.ZipFile(origem) as zi, zipfile.ZipFile(destino, "w", zipfile.ZIP_DEFLATED) as zo:
        for i in zi.infolist():
            if i.filename in trocar:
                if trocar[i.filename] is not None:
                    zo.writestr(i.filename, trocar[i.filename])
            else:
                zo.writestr(i.filename, zi.read(i.filename))
        for n, b in (extra or {}).items():
            zo.writestr(n, b)


def jcs(o) -> bytes:
    import rfc8785
    return rfc8785.dumps(o)


# ------------------------------------------------------------------ 1
def gerar(inv: int):
    from auditor.exportar import exportar
    shutil.rmtree(SAIDA, ignore_errors=True)
    t = time.time()
    m = exportar(inv, SAIDA / "cli", "teste-pacote-v2", sem_mascara=False, soltos=False)
    s = exportar(inv, SAIDA / "cli", "teste-pacote-v2", sem_mascara=True, soltos=False)
    print(f"  pacotes gerados em {time.time() - t:.1f} s ({m['eventos']} eventos)")
    return Path(m["pacote"]), Path(s["pacote"])


def aceite_verificador(pm: Path, ps: Path):
    for p, rot in ((pm, "mascarado"), (ps, "sem máscara")):
        r = verificar(p, homologacao=True, recalcular=True)
        checar(r.integro, f"1 kc-verificar aprova o pacote {rot}", "; ".join(niveis(r)) or r.resumo.get("key_id"))
        checar(any("recalcular: KPIs" in i.texto and i.nivel == "ok" for i in r.itens),
               f"1 --recalcular confere relatório, consolidado, destaques e cobertura ({rot})")
        checar(any("carimbo do tempo RFC 3161 confere" in i.texto for i in r.itens),
               f"1 carimbo do tempo RFC 3161 do manifesto confere ({rot})", r.resumo.get("carimbado_em", ""))
    # CLI do verificador, como um perito usaria (processo separado, só o zip)
    c = subprocess.run([sys.executable, "-m", "kc_verificar", str(pm), "--homologacao", "--json"], cwd=RAIZ,
                       env={"PATH": os.environ["PATH"], "PYTHONPATH": str(RAIZ / "verificador")},
                       capture_output=True, text=True)
    j = json.loads(c.stdout or "{}")
    checar(c.returncode == 0 and j.get("integro") and j["frase"].startswith("Pacote íntegro"),
           "1 kc-verificar na linha de comando, sem banco e sem as variáveis do auditor", j.get("frase", c.stderr[-200:]))
    with zipfile.ZipFile(pm) as z:
        nomes = set(z.namelist())
        m = json.loads(z.read("manifesto.json"))
    checar("eventos_pseudonimizados.jsonl" in nomes and "eventos.jsonl" not in nomes and "pseudonimos.csv" not in nomes,
           "1 mascarado: eventos pseudonimizados, sem eventos originais e sem pseudonimos.csv")
    texto = json.dumps(m, ensure_ascii=False)
    checar(all(k not in m["investigacao"] for k in ("justificativa", "operador")) and m["formato"] == 2 and
           set(m["compromissos"]) >= {"justificativa", "operador"},
           "1 manifesto v2 sem texto livre (justificativa, processo e operador só como compromisso com sal)")
    checar(not re.search(r"\b\d{3}\.\d{3}\.\d{3}-\d{2}\b", texto), "1 manifesto sem CPF")


# ------------------------------------------------------------------ 2
def adulteracoes(pm: Path, ps: Path):
    d = SAIDA / "adulterado"
    d.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(pm) as z:
        ep = z.read("eventos_pseudonimizados.jsonl")
        man = z.read("manifesto.json")
        res = z.read("resultados.json")
    # (a) uma linha alterada
    linhas = ep.split(b"\n")
    linhas[3] = linhas[3].replace(b'"tipo":"LOGIN"', b'"tipo":"LOGOUT"') if b'"tipo":"LOGIN"' in linhas[3] else \
        linhas[3].replace(b'"realm":"', b'"realm":"x')
    a = d / "a.zip"
    regravar(pm, a, {"eventos_pseudonimizados.jsonl": b"\n".join(linhas)})
    r = verificar(a, homologacao=True)
    checar(not r.integro and any("eventos_pseudonimizados.jsonl: SHA-256" in t for t in niveis(r)),
           "2 evento pseudonimizado alterado: hash do arquivo não confere")
    # (b) arquivo a mais
    b = d / "b.zip"
    regravar(pm, b, {}, {"leia_isto.txt": b"inserido depois"})
    r = verificar(b, homologacao=True)
    checar(not r.integro and any("leia_isto.txt" in t for t in niveis(r)), "2 arquivo inserido no pacote é acusado")
    # (c) manifesto alterado (hash de arquivo trocado) sem nova assinatura
    m = json.loads(man)
    m["custodia"]["raiz_merkle"] = "00" * 32
    c = d / "c.zip"
    regravar(pm, c, {"manifesto.json": jcs(m)})
    r = verificar(c, homologacao=True)
    checar(not r.integro and any("assinatura do manifesto não confere" in t for t in niveis(r)),
           "2 manifesto alterado: assinatura não confere")
    # (d) sem máscara: evento original alterado (o hash do arquivo é corrigido no manifesto e re-assinado por uma
    #     chave que não é a publicada)
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    with zipfile.ZipFile(ps) as z:
        ev = z.read("eventos.jsonl").split(b"\n")
        ms = json.loads(z.read("manifesto.json"))
    e0 = json.loads(ev[0])
    e0["evento"]["ipAddress"] = "203.0.113.77"
    ev[0] = jcs(e0)
    nev = b"\n".join(ev)
    ms["arquivos"]["eventos.jsonl"] = hashlib.sha256(nev).hexdigest()
    ms["eventos"]["sha256"] = ms["arquivos"]["eventos.jsonl"]
    k = Ed25519PrivateKey.generate()
    from cryptography.hazmat.primitives import serialization
    bruta = k.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    ms["assinatura"] = {"key_id": "atacante:1", "algoritmo": "Ed25519",
                        "impressao_digital": hashlib.sha256(bruta).hexdigest()}
    corpo = jcs(ms)
    dd = d / "d.zip"
    regravar(ps, dd, {"eventos.jsonl": nev, "manifesto.json": corpo, "manifesto.sig": k.sign(corpo),
                      "manifesto.tsr": None})
    r = verificar(dd, homologacao=True)
    checar(not r.integro and any("não reproduz a sua folha" in t for t in niveis(r)),
           "2 evento original alterado: a folha não confere")
    checar(any("não está entre as chaves publicadas" in t for t in niveis(r)),
           "2 manifesto re-assinado por chave não publicada é recusado")
    # (e) worker comprometido com a chave verdadeira: resultados falsos re-assinados. Só o --recalcular pega.
    from auditor.cripto import assinar
    rr = json.loads(res)
    rr["kpis"]["logins"] += 1
    nres = json.dumps(rr, ensure_ascii=False, indent=1).encode()
    mm = json.loads(man)
    mm["arquivos"]["resultados.json"] = hashlib.sha256(nres).hexdigest()
    mm["carimbo"]["tipo"] = "ausente"
    corpo = jcs(mm)
    e = d / "e.zip"
    regravar(pm, e, {"resultados.json": nres, "manifesto.json": corpo, "manifesto.sig": assinar(corpo),
                     "manifesto.tsr": None})
    r0 = verificar(e, homologacao=True)
    r1 = verificar(e, homologacao=True, recalcular=True)
    checar(any("assinatura do manifesto confere" in i.texto for i in r1.itens) and
           any("recalcular: KPIs diferente" in t for t in niveis(r1)),
           "2 worker comprometido (assinatura válida, KPIs falsos): --recalcular acusa os KPIs",
           "; ".join(niveis(r1))[:160])
    checar(any("relatório técnico não foi gerado" in t for t in niveis(r0)),
           "2 o relatório técnico não corresponde aos resultados falsos")


# ------------------------------------------------------------------ 3
def conta_excluida(inv: int):
    """Exclui temporariamente uma conta (com decisão registrada), gera o pacote e desfaz."""
    from auditor import sigilo
    from auditor.db import conectar
    from auditor.exportar import exportar
    cf = sigilo.Cofre(inv, "exportar")
    with conectar() as cx:
        c = cx.execute("SELECT c.id, count(e.*) n FROM conta c JOIN evento e ON e.conta_id=c.id WHERE "
                       "c.investigacao_id=%s AND c.incluida GROUP BY 1 ORDER BY 2 LIMIT 1", (inv,)).fetchone()
        did = cx.execute("SELECT nextval(pg_get_serial_sequence('conta_decisao','id')) AS n").fetchone()["n"]
        cx.execute("INSERT INTO conta_decisao (id, investigacao_id, conta_id, incluida, motivo_cifrado, por) VALUES "
                   "(%s,%s,%s,false,%s,'teste-pacote-v2')",
                   (did, inv, c["id"], cf.cifrar("conta_decisao", "motivo_cifrado", did, "homônimo, não é o alvo")))
        cx.execute("UPDATE conta SET incluida=false WHERE id=%s", (c["id"],))
    try:
        r = exportar(inv, SAIDA / "excluida", "teste-pacote-v2", sem_mascara=True, soltos=False)
        v = verificar(Path(r["pacote"]), homologacao=True, recalcular=True)
        with zipfile.ZipFile(r["pacote"]) as z:
            n_ev = sum(1 for x in z.read("eventos.jsonl").splitlines() if x)
            fat = json.loads(z.read("fatias.json"))
            exc = json.loads(z.read("contas_excluidas.json"))
        checar(v.integro, "3 pacote com conta excluída verifica (raiz sobre todas as fatias, incluídas e excluídas)",
               "; ".join(niveis(v)))
        checar(any(f"{c['n']} eventos de 1 conta(s) excluídas por decisão registrada" in i.texto for i in v.itens),
               "3 verificador mostra os eventos da conta excluída e que nada mais foi omitido")
        checar(any(not f["incluida"] for f in fat) and len(exc) == 1 and exc[0]["motivo"] and exc[0]["por"]
               and n_ev == r["eventos"],
               "3 eventos da conta excluída fora de eventos.jsonl; decisão com motivo, quem e quando",
               f"{n_ev} eventos exportados, {c['n']} excluídos")
    finally:
        with conectar() as cx:
            cx.execute("UPDATE conta SET incluida=true WHERE id=%s", (c["id"],))
            cx.execute("DELETE FROM conta_decisao WHERE id=%s", (did,))


# ------------------------------------------------------------------ 4
def revelacao(inv: int, pm: Path):
    from auditor.db import conectar
    from auditor.pacote import revelar_evento
    with conectar() as cx:
        eid = cx.execute("SELECT id FROM evento WHERE investigacao_id=%s AND type='LOGIN' ORDER BY time_ms DESC "
                         "LIMIT 1", (inv,)).fetchone()["id"]
    rv = revelar_evento(inv, eid, "teste-pacote-v2", "Pedido do juízo: provar um login específico")
    arq = SAIDA / "revelacao.json"
    arq.write_text(json.dumps(rv, ensure_ascii=False))
    r = verificar(pm, homologacao=True, revelacao=arq)
    checar(r.integro and any("revelação seletiva: o evento entregue pertence" in i.texto for i in r.itens),
           "4 evento + sal entregues depois conferem com o pacote mascarado já entregue")
    rv["evento"]["ipAddress"] = "198.51.100.9"
    arq2 = SAIDA / "revelacao_alterada.json"
    arq2.write_text(json.dumps(rv, ensure_ascii=False))
    r = verificar(pm, homologacao=True, revelacao=arq2)
    checar(not r.integro and any("NÃO pertence" in t for t in niveis(r)), "4 evento alterado não confere")


# ------------------------------------------------------------------ 5
def _hashes_do_pacote(pm: Path) -> set[str]:
    hx = re.compile(rb"[0-9a-f]{64}")
    out = set()
    with zipfile.ZipFile(pm) as z:
        for n in z.namelist():
            b = z.read(n)
            if n.endswith(".xlsx"):
                with zipfile.ZipFile(io.BytesIO(b)) as x:
                    b = b"".join(x.read(i) for i in x.namelist())
            out |= {m.decode() for m in hx.findall(b)}
    return out


def _texto_do_pacote(pm: Path) -> str:
    partes = []
    with zipfile.ZipFile(pm) as z:
        for n in z.namelist():
            if n.endswith((".pdf", ".tsr", ".crl", ".sig")):
                continue
            b = z.read(n)
            if n.endswith(".xlsx"):
                with zipfile.ZipFile(io.BytesIO(b)) as x:
                    b = b"".join(x.read(i) for i in x.namelist())
            partes.append(b.decode("utf-8", "replace"))
    return "\n".join(partes)


def _formas(v: str) -> list[str]:
    b = v.encode()
    return [hashlib.sha256(b).hexdigest(), hashlib.sha256(b"\x00" + b).hexdigest(),
            hashlib.sha256(b"\x00" + jcs(v)).hexdigest(), hashlib.sha256(jcs(v)).hexdigest()]


def _cpfs_vizinhos(cpf: str, n: int) -> list[str]:
    def dv(base):
        s = sum(int(c) * w for c, w in zip(base, range(len(base) + 1, 1, -1)))
        r = (s * 10) % 11
        return "0" if r == 10 else str(r)
    b0 = int(cpf[:9])
    out = []
    for k in range(max(0, b0 - n // 2), b0 + n // 2):
        base = f"{k:09d}"
        d1 = dv(base)
        out.append(base + d1 + dv(base + d1))
    return out


def forca_bruta(inv: int, pm: Path, ps: Path):
    import ipaddress
    from auditor import chaves, sigilo
    from auditor.db import conectar
    from auditor import merkle as am
    cf = sigilo.Cofre(inv, "exportar")
    with conectar() as cx:
        i = cx.execute("SELECT * FROM investigacao WHERE id=%s", (inv,)).fetchone()
        cpf = chaves.alvo(i, "exportar")
        ips, sessoes, eventos = set(), set(), []
        for r in cx.execute("SELECT id, instancia_id, realm, cifrado FROM evento WHERE investigacao_id=%s", (inv,)):
            e = sigilo.abrir_evento(cf, r)
            if e["ip"]:
                ips.add(e["ip"])
            if e["session_id"]:
                sessoes.add(e["session_id"])
            eventos.append(e)
        contas = sigilo.contas(cx, cf)
    alvo = _hashes_do_pacote(pm)
    print(f"  {len(alvo)} hashes distintos no pacote mascarado; {len(ips)} IPs reais, {len(eventos)} eventos")
    # controle positivo: com o sal, a folha de um evento está no pacote
    e0 = eventos[0]
    checar(am.folha(bytes.fromhex(e0["sal"]), am.canonico(e0["bruto"])) in alvo,
           "5 controle positivo: com o sal, a folha do evento é encontrada entre os hashes do pacote")
    # candidatos: valores reais (o melhor caso para quem ataca) e as vizinhanças de força bruta
    tentativas, achados = 0, []
    t = time.time()
    vizinhos_ip = set()
    for ip in sorted(ips)[:40]:
        try:
            rede = ipaddress.ip_network(f"{ip}/24", strict=False) if ":" not in ip else None
        except ValueError:
            rede = None
        if rede:
            vizinhos_ip |= {str(x) for x in rede}
    candidatos = list(ips | vizinhos_ip | sessoes)
    cpfs = _cpfs_vizinhos(cpf, 20000)
    candidatos += cpfs + [f"{c[:3]}.{c[3:6]}.{c[6:9]}-{c[9:]}" for c in cpfs]
    for c in contas:
        candidatos += [v for v in (c.get("user_id"), c.get("username"), c.get("email")) if v]
    for v in candidatos:
        for h in _formas(v):
            tentativas += 1
            if h in alvo:
                achados.append(v)
    # folha sem sal (como seria sem o compromisso) para cada evento real
    for e in eventos:
        tentativas += 1
        if hashlib.sha256(b"\x00" + am.canonico(e["bruto"])).hexdigest() in alvo:
            achados.append("folha sem sal")
    # linhas de requisição originais sem sal
    with zipfile.ZipFile(ps) as z:
        for l in z.read("requisicoes.jsonl").splitlines():
            o = json.loads(l)
            orig = {k: v for k, v in o.items() if k not in ("sal", "compromisso")}
            tentativas += 2
            if hashlib.sha256(b"\x00" + jcs(orig)).hexdigest() in alvo or hashlib.sha256(jcs(orig)).hexdigest() in alvo:
                achados.append("requisição sem sal")
    checar(not achados, f"5 força bruta de IPv4 e CPF contra as folhas, as requisições e todo hash do mascarado: "
                        f"nenhuma confirmação", f"{tentativas:,} tentativas em {time.time() - t:.1f} s; "
                                                f"achados: {achados[:3]}")
    texto = _texto_do_pacote(pm)
    claros = [v for v in [cpf, f"{cpf[:3]}.{cpf[3:6]}.{cpf[6:9]}-{cpf[9:]}"] + sorted(ips) +
              [c.get("user_id") for c in contas] + [c.get("email") for c in contas]
              if v and re.search(r"(?<![0-9a-zA-Z.])" + re.escape(v) + r"(?![0-9a-zA-Z])", texto)]
    checar(not claros, "5 nenhum CPF, IP, userId ou e-mail real em claro no pacote mascarado",
           f"{len(claros)} encontrados: {claros[:3]}")


# ------------------------------------------------------------------ 6
def _normalizar_xlsx(b: bytes) -> list:
    from openpyxl import load_workbook
    wb = load_workbook(io.BytesIO(b), read_only=True)
    out = []
    for ws in wb.worksheets:
        for row in ws.iter_rows(values_only=True):
            if ws.title == "Parâmetros" and row and row[0] in ("Exportado por", "Exportado em"):
                continue
            out.append((ws.title, row))
    return out


def equivalencia(inv: int, pm_cli: Path):
    from auditor import casos
    from auditor.db import conectar
    segredo = secrets.token_urlsafe(24)
    env = {**os.environ, "ASSINADOR_DSN": os.environ["AUDITOR_DSN"], "ASSINADOR_SEGREDO": segredo,
           "ASSINADOR_VAULT_TOKEN_FILE": str(RAIZ / "chaves/vault/assinador.token")}
    porta = 8319
    srv = subprocess.Popen([sys.executable, "-m", "auditor", "assinador", "--porta", str(porta)], cwd=RAIZ, env=env,
                           stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    try:
        import httpx
        for _ in range(50):
            try:
                httpx.get(f"http://127.0.0.1:{porta}/chave", timeout=1)
                break
            except httpx.HTTPError:
                time.sleep(0.2)
        os.environ.update(AUDITOR_ASSINADOR_URL=f"http://127.0.0.1:{porta}", AUDITOR_ASSINADOR_SEGREDO=segredo)
        r = httpx.post(f"http://127.0.0.1:{porta}/assinar", content=b'{"formato":2}',
                       headers={"Authorization": "Bearer errado"})
        checar(r.status_code == 401, "6 assinador recusa pedido sem o segredo do worker")
        from auditor.assinador import Recusado, assinar
        with zipfile.ZipFile(pm_cli) as z:
            mm = json.loads(z.read("manifesto.json"))
        mm["custodia"]["raiz_merkle"] = "11" * 32
        try:
            assinar(jcs(mm))
            recusou = False
        except Recusado as e:
            recusou = "raiz Merkle diferente" in str(e)
        checar(recusou, "6 assinador recusa manifesto cuja raiz não confere com os selos da cadeia (e alerta)")
        with conectar() as cx:
            pid = cx.execute("INSERT INTO pacote (investigacao_id, sem_mascara, pedido_por) VALUES (%s,false,%s) "
                             "RETURNING id", (inv, "teste-pacote-v2")).fetchone()["id"]
        casos.gerar_pacote_job(pid)
        with conectar() as cx:
            p = cx.execute("SELECT * FROM pacote WHERE id=%s", (pid,)).fetchone()
        checar(p["status"] == "pronto" and p["verificacao"]["integro"] and re.search(r"_v\d+\.zip$", p["nome"]),
               "6 worker de pacotes: pacote versionado, verificado logo depois de gerado",
               f"{p['nome']}: {p['verificacao']['frase']}")
        pw = Path(p["arquivo"])
    finally:
        os.environ.pop("AUDITOR_ASSINADOR_URL", None)
        srv.terminate()
        srv.wait(10)
    with zipfile.ZipFile(pm_cli) as a, zipfile.ZipFile(pw) as b:
        ma, mb = json.loads(a.read("manifesto.json")), json.loads(b.read("manifesto.json"))
        checar(ma["assinatura"]["key_id"] != mb["assinatura"]["key_id"] and mb["assinatura"]["key_id"].startswith("vault:"),
               "6 local assina com a chave local; o worker, pelo assinador, com a chave do Vault Transit",
               f"{ma['assinatura']['key_id']} × {mb['assinatura']['key_id']}")
        iguais = {
            "raiz Merkle": ma["custodia"]["raiz_merkle"] == mb["custodia"]["raiz_merkle"],
            "eventos.sha256": ma["eventos"]["sha256"] == mb["eventos"]["sha256"],
            "requisicoes.sha256": ma["requisicoes"]["sha256"] == mb["requisicoes"]["sha256"]
            and ma["requisicoes"]["raiz"] == mb["requisicoes"]["raiz"],
            "fatias.json": a.read("fatias.json") == b.read("fatias.json"),
            "compromissos": ma["compromissos"] == mb["compromissos"],
            "CSVs": all(a.read(n) == b.read(n) for n in a.namelist() if n.endswith(".csv")),
            "eventos pseudonimizados e folhas": a.read("eventos_pseudonimizados.jsonl") == b.read(
                "eventos_pseudonimizados.jsonl") and a.read("folhas.jsonl") == b.read("folhas.jsonl"),
            "resultados.json (de onde sai o PDF)": a.read("resultados.json") == b.read("resultados.json"),
            "XLSX normalizado": _normalizar_xlsx(a.read(f"investigacao_{inv}.xlsx")) ==
            _normalizar_xlsx(b.read(f"investigacao_{inv}.xlsx")),
            "HTML normalizado": re.sub(rb'"gerado": "[^"]*"', b"", a.read(f"dashboard_{inv}.html")) ==
            re.sub(rb'"gerado": "[^"]*"', b"", b.read(f"dashboard_{inv}.html")),
        }
        sha_res = hashlib.sha256(a.read("resultados.json")).hexdigest().encode()
        iguais["PDF declara os mesmos resultados"] = sha_res in a.read(f"relatorio_{inv}.pdf") and \
            sha_res in b.read(f"relatorio_{inv}.pdf")
    checar(all(iguais.values()), "6 equivalência local × produção", ", ".join(f"{k}: {'=' if v else '≠'}"
                                                                        for k, v in iguais.items()))
    r = verificar(pw, homologacao=True, recalcular=True)
    checar(r.integro, "6 pacote do worker (chave do Vault) aprovado pelo verificador offline", r.resumo.get("key_id"))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--inv", type=int, default=14)
    ap.add_argument("--inv-exclusao", type=int, default=18)
    a = ap.parse_args()
    if not os.environ.get("AUDITOR_TSA_URL"):
        raise SystemExit("defina AUDITOR_TSA_URL (ACT de homologação: python infra/act_homologacao.py --porta 8318)")
    pm, ps = gerar(a.inv)
    aceite_verificador(pm, ps)
    adulteracoes(pm, ps)
    conta_excluida(a.inv_exclusao)
    revelacao(a.inv, pm)
    forca_bruta(a.inv, pm, ps)
    equivalencia(a.inv, pm)
    print(f"\n{'APROVADO' if not FALHAS else 'REPROVADO'}: {len(FALHAS)} falha(s)")
    sys.exit(1 if FALHAS else 0)


if __name__ == "__main__":
    main()

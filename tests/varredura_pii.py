"""Critério de aceite do W0b (docs/PROPOSTA_WEB.md §5.1): varredura de dado pessoal em claro.

Procura, em **todas** as colunas de todas as tabelas do banco do auditor e nos pacotes mascarados indicados (zip, e
dentro deles XLSX, CSV, HTML, JSON), os CPFs e títulos (com e sem máscara), e-mails, userIds e usernames da massa de
teste (dados/pessoas.json), além de qualquer IPv4 ou IPv6. Resultado esperado: zero ocorrência.

  AUDITOR_DSN=<dono ou kc_auditor_app> python tests/varredura_pii.py [pacote_mascarado.zip ...]

Colunas bytea são lidas também como texto (latin-1), para pegar claro guardado em coluna binária.
"""
from __future__ import annotations

import io
import ipaddress
import json
import re
import sys
import zipfile
from collections import Counter
from pathlib import Path

RAIZ = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(RAIZ))
from auditor.db import conectar  # noqa: E402

TOKEN = re.compile(r"[\w.@+-]+")
IPV4 = re.compile(r"(?<![\w.])(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}(?![\w.])")
IPV6 = re.compile(r"(?<![\w:])(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{1,4}(?![\w:])|(?<![\w:])::1(?![\w:])")
# IPs técnicos que não são dado pessoal (endereço do próprio auditor nas URLs de serviço)
IPS_TECNICOS = {"127.0.0.1", "0.0.0.0"}


def agulhas() -> dict[str, str]:
    d = json.loads((RAIZ / "dados/pessoas.json").read_text())
    out: dict[str, str] = {}
    for p in d["pessoas"]:
        out[p["cpf"]] = "cpf"
        out[f"{p['cpf'][:3]}.{p['cpf'][3:6]}.{p['cpf'][6:9]}-{p['cpf'][9:]}"] = "cpf"
        out[p["titulo"]] = "titulo"
    for c in d["contas"]:
        for k, classe in (("username", "username"), ("email", "email"), ("id", "user_id"), ("cpf_attr", "cpf"),
                          ("titulo_attr", "titulo")):
            if c.get(k):
                out[str(c[k])] = classe
    return out


def achados(texto: str, ag: dict[str, str]) -> Counter:
    c = Counter()
    for t in TOKEN.findall(texto):
        t = t.strip(".-")
        if t in ag:
            c[ag[t]] += 1
    for m in IPV4.findall(texto):
        if m not in IPS_TECNICOS:
            c["ipv4"] += 1
    for m in IPV6.findall(texto):
        try:   # o padrão também casa horários (08:21:33); só conta endereço IPv6 válido
            ipaddress.IPv6Address(m)
            c["ipv6"] += 1
        except ValueError:
            pass
    return c


def varrer_banco(ag) -> dict[str, Counter]:
    res: dict[str, Counter] = {}
    with conectar() as cx:
        cols = cx.execute("SELECT table_name, column_name, data_type FROM information_schema.columns "
                          "WHERE table_schema='public' ORDER BY 1, 2").fetchall()
        for c in cols:
            if c["table_name"] == "alembic_version":
                continue
            q = f'SELECT "{c["column_name"]}" AS v FROM "{c["table_name"]}" WHERE "{c["column_name"]}" IS NOT NULL'
            n = Counter()
            with cx.cursor(name=None) as cur:
                for r in cur.execute(q):
                    v = r["v"]
                    if isinstance(v, (bytes, memoryview)):
                        texto = bytes(v).decode("latin-1")
                    elif isinstance(v, (dict, list)):
                        texto = json.dumps(v, ensure_ascii=False)
                    else:
                        texto = str(v)
                    n += achados(texto, ag)
            if n:
                res[f"{c['table_name']}.{c['column_name']}"] = n
    return res


def varrer_zip(dados: bytes, nome: str, ag, res: dict[str, Counter]):
    with zipfile.ZipFile(io.BytesIO(dados)) as z:
        for i in z.namelist():
            b = z.read(i)
            if i.endswith(".xlsx"):
                varrer_zip(b, f"{nome}/{i}", ag, res)
                continue
            n = achados(b.decode("utf-8", errors="replace"), ag)
            if n:
                res[f"{nome}/{i}"] = n


def main(pacotes: list[str]):
    ag = agulhas()
    print(f"{len(ag)} valores da massa de teste procurados, mais IPv4/IPv6")
    res = varrer_banco(ag)
    for p in pacotes:
        if "sem_mascara" in Path(p).name.lower():
            print(f"ignorado (pacote sem máscara): {p}")
            continue
        varrer_zip(Path(p).read_bytes(), Path(p).name, ag, res)
    for onde, n in sorted(res.items()):
        print(f"FALHA {onde}: {dict(n)}")
    total = sum(sum(n.values()) for n in res.values())
    print(f"\n{'APROVADO' if not total else 'REPROVADO'}: {total} ocorrência(s) em claro em {len(res)} lugar(es)")
    sys.exit(1 if total else 0)


if __name__ == "__main__":
    main(sys.argv[1:])

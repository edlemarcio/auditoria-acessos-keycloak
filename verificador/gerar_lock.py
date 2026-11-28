"""Regera requirements.lock: versões fixadas e o SHA-256 de todas as distribuições publicadas no PyPI de cada uma.

  python gerar_lock.py        (precisa de rede; o verificador em si não precisa)
"""
import json
import urllib.request
from pathlib import Path

PACOTES = [("cryptography", "50.0.2", ""), ("cffi", "2.1.1", ' ; platform_python_implementation == "CPython"'),
           ("pycparser", "3.12", ""), ("rfc8785", "0.1.4", ""), ("asn1crypto", "1.5.1", ""),
           ("tzdata", "2026.6", ' ; sys_platform == "win32"')]

linhas = ["# Dependências do kc-verificar fixadas por versão e hash (todas as distribuições publicadas no PyPI).",
          "# pip install --require-hashes -r requirements.lock && pip install --no-deps .",
          "# Regenerar: python gerar_lock.py (lê os hashes da API JSON do PyPI)."]
for nome, versao, marca in PACOTES:
    with urllib.request.urlopen(f"https://pypi.org/pypi/{nome}/{versao}/json", timeout=30) as r:
        hs = sorted({u["digests"]["sha256"] for u in json.load(r)["urls"]})
    linhas.append(f"{nome}=={versao}{marca} \\")
    linhas += [f"    --hash=sha256:{h} \\" for h in hs[:-1]] + [f"    --hash=sha256:{hs[-1]}"]
(Path(__file__).parent / "requirements.lock").write_text("\n".join(linhas) + "\n")

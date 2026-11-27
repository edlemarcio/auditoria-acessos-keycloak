"""Prepara o Vault da stack local para o modo vault (W0b, docs/PROPOSTA_WEB.md §5.3). Idempotente.

  docker compose -f infra/docker-compose.yml --profile vault up -d vault
  python infra/vault_setup.py                 # inicializa, abre, cria chaves, políticas, tokens e certificados
  python infra/vault_setup.py --certificados  # só reemite os certificados mTLS (validade curta)

Faz o papel do Operador do Vault na stack local. Grava em chaves/ (fora do git):

  chaves/vault/init.json          chave de abertura e token raiz (produção: auto-unseal e token raiz revogado)
  chaves/vault/chaveiro.token     token do chaveiro: datakey/decrypt da KEK, HMAC do alvo, segredos e histórico
  chaves/vault/assinador.token    token do assinador: só assinatura (usado a partir da W5)
  chaves/servicos/ca.crt          AC dos certificados mTLS (Vault PKI)
  chaves/servicos/<nome>.crt/.key chaveiro (servidor) e os clientes: worker, pacotes, operador, api
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path

import httpx

RAIZ = Path(__file__).resolve().parents[1]
VAULT = os.environ.get("VAULT_ADDR", "http://127.0.0.1:8200")
DIR_VAULT = RAIZ / "chaves" / "vault"
DIR_CERT = RAIZ / "chaves" / "servicos"
DOMINIO = "kc-auditor.local"

# chaves do Transit (§5.3). As derivadas exigem contexto: a KEK por investigação e classe, os segredos por instância
CHAVES = {
    "kc-auditor-kek": {"type": "aes256-gcm96", "derived": True},
    "kc-auditor-alvo": {"type": "aes256-gcm96"},          # usada só em /hmac
    "kc-auditor-historico": {"type": "aes256-gcm96", "derived": True},
    "kc-auditor-segredos": {"type": "aes256-gcm96", "derived": True},
    "kc-auditor-assinatura": {"type": "ed25519"},
}
POLITICAS = {
    "chaveiro": """
path "transit/datakey/plaintext/kc-auditor-kek" { capabilities = ["update"] }
path "transit/decrypt/kc-auditor-kek"           { capabilities = ["update"] }
path "transit/hmac/kc-auditor-alvo/*"           { capabilities = ["update"] }
path "transit/hmac/kc-auditor-historico/*"      { capabilities = ["update"] }
path "transit/encrypt/kc-auditor-historico"     { capabilities = ["update"] }
path "transit/decrypt/kc-auditor-historico"     { capabilities = ["update"] }
path "transit/encrypt/kc-auditor-segredos"      { capabilities = ["update"] }
path "transit/decrypt/kc-auditor-segredos"      { capabilities = ["update"] }
""",
    "assinador": """
path "transit/sign/kc-auditor-assinatura"       { capabilities = ["update"] }
path "transit/keys/kc-auditor-assinatura"       { capabilities = ["read"] }
""",
}
# clientes do chaveiro; o CN é a identidade conferida nas regras (auditor/chaveiro.py)
CLIENTES = ("worker", "pacotes", "operador", "api")


def v(cli: httpx.Client, metodo: str, caminho: str, **kw):
    r = cli.request(metodo, f"/v1/{caminho}", **kw)
    if r.status_code >= 400 and not (r.status_code == 400 and "already in use" in r.text):
        raise SystemExit(f"Vault {metodo} {caminho}: HTTP {r.status_code} {r.text[:300]}")
    return r.json() if r.content else {}


def abrir_cofre(cli: httpx.Client) -> str:
    """Inicializa (uma vez) e abre o Vault. Devolve o token raiz."""
    DIR_VAULT.mkdir(parents=True, exist_ok=True)
    arq = DIR_VAULT / "init.json"
    for _ in range(30):
        try:
            st = cli.get("/v1/sys/seal-status").json()
            break
        except httpx.TransportError:
            time.sleep(1)
    else:
        raise SystemExit(f"Vault não responde em {VAULT}")
    if not st["initialized"]:
        ini = v(cli, "PUT", "sys/init", json={"secret_shares": 1, "secret_threshold": 1})
        arq.write_text(json.dumps(ini))
        os.chmod(arq, 0o600)
        print("Vault inicializado")
    dados = json.loads(arq.read_text())
    if cli.get("/v1/sys/seal-status").json()["sealed"]:
        v(cli, "PUT", "sys/unseal", json={"key": dados["keys_base64"][0]})
        print("Vault aberto")
    return dados["root_token"]


def configurar(cli: httpx.Client):
    montados = v(cli, "GET", "sys/mounts")
    montados = montados.get("data", montados)
    if "transit/" not in montados:
        v(cli, "POST", "sys/mounts/transit", json={"type": "transit"})
    if "pki/" not in montados:
        v(cli, "POST", "sys/mounts/pki", json={"type": "pki", "config": {"max_lease_ttl": "87600h"}})
    for nome, tipo in CHAVES.items():
        if cli.get(f"/v1/transit/keys/{nome}").status_code == 404:
            v(cli, "POST", f"transit/keys/{nome}", json=tipo)
            print(f"chave {nome} criada")
    for nome, hcl in POLITICAS.items():
        v(cli, "PUT", f"sys/policies/acl/{nome}", json={"policy": hcl})
    # AC raiz dos certificados mTLS e o papel que os emite
    if cli.get("/v1/pki/cert/ca").json().get("data", {}).get("certificate", "") == "":
        v(cli, "POST", "pki/root/generate/internal", json={"common_name": "kc-auditor AC local", "ttl": "87600h"})
        print("AC mTLS criada")
    v(cli, "POST", "pki/roles/servicos", json={"allowed_domains": DOMINIO, "allow_subdomains": True,
                                                "allow_localhost": True, "allow_ip_sans": True,
                                                "max_ttl": "720h", "key_type": "ec", "key_bits": 256})


def tokens(cli: httpx.Client):
    for nome in POLITICAS:
        arq = DIR_VAULT / f"{nome}.token"
        if arq.exists():
            r = httpx.get(f"{VAULT}/v1/auth/token/lookup-self", headers={"X-Vault-Token": arq.read_text().strip()})
            if r.status_code == 200:
                continue
        t = v(cli, "POST", "auth/token/create", json={"policies": [nome], "period": "768h", "no_default_policy": False,
                                                       "display_name": nome, "renewable": True})
        arq.write_text(t["auth"]["client_token"])
        os.chmod(arq, 0o600)
        print(f"token {nome} emitido")


def certificados(cli: httpx.Client, validade: str = "168h"):
    DIR_CERT.mkdir(parents=True, exist_ok=True)
    ca = v(cli, "GET", "pki/cert/ca")["data"]["certificate"]
    (DIR_CERT / "ca.crt").write_text(ca + "\n")
    for nome in ("chaveiro",) + CLIENTES:
        corpo = {"common_name": f"{nome}.{DOMINIO}", "ttl": validade}
        if nome == "chaveiro":
            corpo |= {"alt_names": "localhost", "ip_sans": "127.0.0.1"}
        c = v(cli, "POST", "pki/issue/servicos", json=corpo)["data"]
        (DIR_CERT / f"{nome}.crt").write_text(c["certificate"] + "\n")
        chave = DIR_CERT / f"{nome}.key"
        chave.write_text(c["private_key"] + "\n")
        os.chmod(chave, 0o600)
    print(f"certificados mTLS emitidos (validade {validade}) em {DIR_CERT.relative_to(RAIZ)}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--certificados", action="store_true", help="só reemite os certificados mTLS")
    ap.add_argument("--validade", default="168h")
    a = ap.parse_args()
    with httpx.Client(base_url=VAULT, timeout=10, trust_env=False) as cli:
        raiz = abrir_cofre(cli)
        cli.headers["X-Vault-Token"] = raiz
        if not a.certificados:
            configurar(cli)
            tokens(cli)
        certificados(cli, a.validade)
    print("\nPara o modo vault:\n"
          "  export AUDITOR_MODO=vault AUDITOR_CHAVEIRO=https://127.0.0.1:8443\n"
          "  CHAVEIRO_DSN=<papel kc_chaveiro> python -m auditor chaveiro      # em outro terminal")


if __name__ == "__main__":
    sys.exit(main())

"""Faz logins REAIS (grant password no client app-teste) para conferir que o auditor lê eventos produzidos
pelo próprio Keycloak, além dos gerados em massa. Inclui falhas de senha.

  python infra/logins_reais.py --url http://localhost:8080 --instancia kc26 --n 200
"""
from __future__ import annotations

import argparse
import json
import random
import sys
from pathlib import Path

import httpx

RAIZ = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(RAIZ))
from infra.semear import SENHA_TESTE  # noqa: E402
from tools.cenario import REALMS  # noqa: E402


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", required=True)
    ap.add_argument("--instancia", required=True)
    ap.add_argument("--n", type=int, default=200)
    a = ap.parse_args()
    dados = json.loads((RAIZ / "dados/pessoas.json").read_text())
    alvo = [c for c in dados["contas"] if c["instancia"] == a.instancia and c["marca"] == "ALVO"
            and REALMS[a.instancia][c["realm"]]["events_enabled"]]
    h = httpx.Client(base_url=a.url.rstrip("/"), timeout=30, trust_env=False)
    ok = erro = 0
    for i in range(a.n):
        c = random.choice(alvo)
        senha = SENHA_TESTE if random.random() > 0.15 else "senha-errada"
        r = h.post(f"/realms/{c['realm']}/protocol/openid-connect/token",
                   data={"grant_type": "password", "client_id": "app-teste", "username": c["username"],
                         "password": senha, "scope": "openid"})
        ok += r.status_code == 200
        erro += r.status_code != 200
    print(f"logins reais: {ok} sucesso, {erro} falha (esperadas ~15%)")


if __name__ == "__main__":
    main()

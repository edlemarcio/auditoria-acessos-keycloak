"""Prepara uma instância Keycloak REAL pela Admin REST API: realms, eventos, User Profile, clients,
usuários aleatórios (CPF/Título válidos) e o service account somente leitura do auditor.

Funciona no Keycloak 26.x (sem /auth) e no 18.x legado / RH-SSO 7.6 (com /auth).

  python infra/semear.py --url http://localhost:8080 --instancia kc26
  python infra/semear.py --url http://localhost:8081/auth --instancia kc18
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import httpx

RAIZ = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(RAIZ))
from tools.cenario import REALMS, SERVICE_ACCOUNT, SONDA  # noqa: E402

ROLES = ["view-events", "view-users", "query-users", "view-realm"]
SENHA_TESTE = "Senha@Teste1"


class Admin:
    def __init__(self, url, usuario, senha):
        self.h = httpx.Client(base_url=url.rstrip("/"), timeout=120, trust_env=False)
        self.u, self.s = usuario, senha
        self.login()

    def login(self):
        r = self.h.post("/realms/master/protocol/openid-connect/token",
                        data={"grant_type": "password", "client_id": "admin-cli", "username": self.u,
                              "password": self.s})
        r.raise_for_status()
        self.h.headers["Authorization"] = "Bearer " + r.json()["access_token"]

    def req(self, metodo, caminho, ok=(200, 201, 204), **kw):
        r = self.h.request(metodo, "/admin" + caminho, **kw)
        if r.status_code == 401:
            self.login()
            r = self.h.request(metodo, "/admin" + caminho, **kw)
        if r.status_code not in ok:
            raise RuntimeError(f"{metodo} {caminho}: {r.status_code} {r.text[:300]}")
        return r.json() if r.content and r.headers.get("content-type", "").startswith("application/json") else None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", required=True)
    ap.add_argument("--instancia", required=True, choices=list(REALMS))
    ap.add_argument("--admin", default="admin")
    ap.add_argument("--senha", default="admin")
    ap.add_argument("--pessoas", default=str(RAIZ / "dados/pessoas.json"))
    ap.add_argument("--com-senha", type=int, default=50, help="usuários com senha, para logins reais de conferência")
    a = ap.parse_args()
    dados = json.loads(Path(a.pessoas).read_text())
    k = Admin(a.url, a.admin, a.senha)
    cfg = REALMS[a.instancia]

    for realm, rc in cfg.items():
        k.req("POST", "/realms", ok=(201, 409), json={"realm": realm, "enabled": True})
        k.req("PUT", f"/realms/{realm}/events/config", json={
            "eventsEnabled": rc["events_enabled"], "eventsExpiration": rc["expiration"],
            "enabledEventTypes": rc["types"], "eventsListeners": ["jboss-logging"],
            "adminEventsEnabled": True, "adminEventsDetailsEnabled": True})
        if a.instancia == "kc26":   # User Profile declarativo (24+): declara cpf e tituloEleitor
            up = k.req("GET", f"/realms/{realm}/users/profile")
            nomes = {x["name"] for x in up["attributes"]}
            for nome in ("cpf", "tituloEleitor"):
                if nome not in nomes:
                    up["attributes"].append({"name": nome, "displayName": nome, "multivalued": False,
                                             "permissions": {"view": ["admin"], "edit": ["admin"]}})
            k.req("PUT", f"/realms/{realm}/users/profile", json=up)
        for c in dados["clientes"].get(realm, ["app-homologacao"]) + ["app-teste"]:
            k.req("POST", f"/realms/{realm}/clients", ok=(201, 409), json={
                "clientId": c, "enabled": True, "publicClient": c == "app-teste", "directAccessGrantsEnabled": True,
                "redirectUris": [f"https://{c}.exemplo.gov.br/*"], "standardFlowEnabled": True})
        usuarios = []
        for i, c in enumerate(x for x in dados["contas"] if x["instancia"] == a.instancia and x["realm"] == realm
                                and x["marca"] != "EXCLUIDA"):
            u = {"id": c["id"], "username": c["username"], "email": c["email"], "firstName": c["nome"],
                 "lastName": c["sobrenome"], "enabled": True, "emailVerified": True,
                 "attributes": {"cpf": [c["cpf_attr"]], "tituloEleitor": [c["titulo_attr"]]}}
            if i < a.com_senha or c["marca"] == "ALVO":
                u["credentials"] = [{"type": "password", "value": SENHA_TESTE, "temporary": False}]
            usuarios.append(u)
        if rc.get("homologacao"):
            usuarios.append({"username": SONDA["username"], "email": "sonda@exemplo.gov.br", "firstName": "Usuário",
                             "lastName": "Sonda", "enabled": True,
                             "attributes": {"cpf": [SONDA["cpf"]], "tituloEleitor": [SONDA["titulo"]]}})
        for i in range(0, len(usuarios), 500):
            k.req("POST", f"/realms/{realm}/partialImport",
                  json={"ifResourceExists": "SKIP", "users": usuarios[i:i + 500]})
        print(f"{realm}: {len(usuarios)} usuários")

    # service account do auditor no master, somente leitura, roles por realm
    k.req("POST", "/realms/master/clients", ok=(201, 409), json={
        "clientId": SERVICE_ACCOUNT["client_id"], "secret": SERVICE_ACCOUNT["secret"], "enabled": True,
        "publicClient": False, "serviceAccountsEnabled": True, "standardFlowEnabled": False,
        "directAccessGrantsEnabled": False})
    cid = k.req("GET", "/realms/master/clients", params={"clientId": SERVICE_ACCOUNT["client_id"]})[0]["id"]
    sa = k.req("GET", f"/realms/master/clients/{cid}/service-account-user")["id"]
    for realm, rc in cfg.items():
        if rc.get("sem_roles"):
            continue
        rcid = k.req("GET", "/realms/master/clients", params={"clientId": f"{realm}-realm"})[0]["id"]
        roles = [k.req("GET", f"/realms/master/clients/{rcid}/roles/{r}") for r in ROLES]
        k.req("POST", f"/realms/master/users/{sa}/role-mappings/clients/{rcid}", json=roles)
    print(f"service account '{SERVICE_ACCOUNT['client_id']}' com {', '.join(ROLES)} em "
          f"{[r for r, c in cfg.items() if not c.get('sem_roles')]}")


if __name__ == "__main__":
    main()

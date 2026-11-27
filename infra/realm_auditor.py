"""Realm dedicado aos usuários do auditor (W1, PROPOSTA_WEB §4.1 e §8.9), no Keycloak 26 da stack. Idempotente.

  python infra/realm_auditor.py [--kc http://localhost:8090] [--api http://localhost:8000] [--origem-dev URL ...]

Cria:
  * realm `auditor`, separado dos realms auditados, com MFA obrigatório por nível de autenticação (LoA): nível 1 =
    senha, nível 2 = OTP; `acr` = "mfa" no token; o nível 2 vale 5 min (step-up: ações sensíveis pedem OTP de novo
    depois disso);
  * papéis: solicitante, investigador, aprovador, auditor_interno, admin_tecnico, gestor_acesso;
  * clientes: kc-auditor-bff (confidencial, código + PKCE), kc-auditor-cli (público, device flow); os dois emitem
    tokens com audiência kc-auditor-api e kc-auditor-chaveiro;
  * usuários de teste, um ou mais por perfil, inclusive um com papéis conflitantes e o operador do Vault (sem papel).
    Senha: "senha-<usuario>". O OTP é configurado no primeiro login (tests/navegador_kc.py faz isso sozinho).

Grava chaves/realm_auditor.json (segredo do BFF), fora do git.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

import httpx

RAIZ = Path(__file__).resolve().parents[1]
REALM = "auditor"
PAPEIS = ["solicitante", "investigador", "aprovador", "auditor_interno", "admin_tecnico", "gestor_acesso"]
USUARIOS = {
    "solicitante1": (["solicitante"], "Unidade A"), "solicitante2": (["solicitante"], "Unidade B"),
    "investigador1": (["investigador"], "Corregedoria"), "investigador2": (["investigador"], "Corregedoria"),
    "aprovador1": (["aprovador"], "Coordenação"), "aprovador2": (["aprovador"], "Coordenação"),
    "aprovinvest1": (["aprovador", "investigador"], "Corregedoria"),   # permitido em geral, nunca na mesma inv.
    "auditor1": (["auditor_interno"], "Controle interno"),
    "admin1": (["admin_tecnico"], "Infraestrutura"),
    "gestor1": (["gestor_acesso"], "Segurança da informação"),
    "operadorvault1": ([], "Infraestrutura de chaves"),
    "conflito1": (["admin_tecnico", "investigador"], "Infraestrutura"),   # bloqueado no login
}


class KC:
    def __init__(self, url: str):
        self.h = httpx.Client(base_url=url, timeout=30, trust_env=False)
        t = self.h.post("/realms/master/protocol/openid-connect/token",
                        data={"grant_type": "password", "client_id": "admin-cli", "username": "admin",
                              "password": os.environ.get("KC_ADMIN_SENHA", "admin")}).json()["access_token"]
        self.h.headers.update({"Authorization": f"Bearer {t}", "Accept": "application/json"})

    def r(self, metodo, caminho, ok=(200, 201, 204, 409), **kw):
        x = self.h.request(metodo, f"/admin/realms{caminho}", **kw)
        if x.status_code not in ok:
            raise SystemExit(f"{metodo} {caminho}: HTTP {x.status_code} {x.text[:300]}")
        return x.json() if x.content and x.headers.get("content-type", "").startswith("application/json") else None


def fluxo_mfa(kc: KC):
    """Fluxo de navegador com step-up (guia do Keycloak): nível 1 senha, nível 2 OTP com validade de 5 min."""
    nome = "navegador-mfa"
    if nome in {f["alias"] for f in kc.r("GET", f"/{REALM}/authentication/flows")}:
        return nome
    kc.r("POST", f"/{REALM}/authentication/flows/browser/copy", json={"newName": nome})
    forms = f"{nome} forms"
    for e in kc.r("GET", f"/{REALM}/authentication/flows/{forms}/executions"):
        if e["level"] == 0:   # senha e 2FA condicional saem; entram os dois níveis
            kc.r("DELETE", f"/{REALM}/authentication/executions/{e['id']}")
    for nivel, autenticador, idade in ((1, "auth-username-password-form", "36000"), (2, "auth-otp-form", "300")):
        alias = f"nivel-{nivel}"
        kc.r("POST", f"/{REALM}/authentication/flows/{forms}/executions/flow",
             json={"alias": alias, "type": "basic-flow", "description": f"Nível {nivel}",
                   "provider": "registration-page-form"})
        for prov in ("conditional-level-of-authentication", autenticador):
            kc.r("POST", f"/{REALM}/authentication/flows/{alias}/executions/execution", json={"provider": prov})
        for e in kc.r("GET", f"/{REALM}/authentication/flows/{forms}/executions"):
            if e["level"] == 0 and e.get("displayName") == alias:
                kc.r("PUT", f"/{REALM}/authentication/flows/{forms}/executions", json={**e, "requirement": "CONDITIONAL"})
        for e in kc.r("GET", f"/{REALM}/authentication/flows/{alias}/executions"):
            kc.r("PUT", f"/{REALM}/authentication/flows/{alias}/executions", json={**e, "requirement": "REQUIRED"})
            if e.get("providerId") == "conditional-level-of-authentication":
                kc.r("POST", f"/{REALM}/authentication/executions/{e['id']}/config",
                     json={"alias": f"loa-{nivel}", "config": {"loa-condition-level": str(nivel),
                                                               "loa-max-age": idade}})
    return nome


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--kc", default="http://localhost:8090")
    ap.add_argument("--api", default="http://localhost:8000")
    ap.add_argument("--origem-dev", action="append", default=[],
                    help="origem extra aceita no retorno do login (desenvolvimento; ex.: http://localhost:8100)")
    a = ap.parse_args()
    origens = [a.api] + [o.rstrip("/") for o in a.origem_dev]
    kc = KC(a.kc)
    kc.r("POST", "", json={"realm": REALM, "enabled": True, "displayName": "kc-auditor",
                           "loginWithEmailAllowed": False, "bruteForceProtected": True,
                           "ssoSessionIdleTimeout": 1800, "ssoSessionMaxLifespan": 28800,
                           "accessTokenLifespan": 300, "eventsEnabled": True, "adminEventsEnabled": True,
                           "adminEventsDetailsEnabled": True})
    fluxo = fluxo_mfa(kc)
    kc.r("PUT", f"/{REALM}", json={"browserFlow": fluxo, "eventsEnabled": True, "adminEventsEnabled": True,
                                   "adminEventsDetailsEnabled": True,
                                   "attributes": {"acr.loa.map": json.dumps({"senha": 1, "mfa": 2})}})
    # atributo "unidade" no token
    up = kc.r("GET", f"/{REALM}/users/profile")
    if up.get("unmanagedAttributePolicy") != "ENABLED":
        kc.r("PUT", f"/{REALM}/users/profile", json={**up, "unmanagedAttributePolicy": "ENABLED"})
    for p in PAPEIS:
        kc.r("POST", f"/{REALM}/roles", json={"name": p})
    # audiência da API e do chaveiro, e a unidade, num escopo padrão dos dois clientes
    escopos = {s["name"]: s for s in kc.r("GET", f"/{REALM}/client-scopes")}
    if "kc-auditor" not in escopos:
        kc.r("POST", f"/{REALM}/client-scopes", json={
            "name": "kc-auditor", "protocol": "openid-connect", "attributes": {"include.in.token.scope": "false"},
            "protocolMappers": [
                {"name": f"aud-{c}", "protocol": "openid-connect", "protocolMapper": "oidc-audience-mapper",
                 "config": {"included.custom.audience": c, "access.token.claim": "true", "id.token.claim": "false"}}
                for c in ("kc-auditor-api", "kc-auditor-chaveiro")] + [
                {"name": "unidade", "protocol": "openid-connect", "protocolMapper": "oidc-usermodel-attribute-mapper",
                 "config": {"user.attribute": "unidade", "claim.name": "unidade", "jsonType.label": "String",
                            "access.token.claim": "true", "id.token.claim": "true", "userinfo.token.claim": "true"}}]})
        escopos = {s["name"]: s for s in kc.r("GET", f"/{REALM}/client-scopes")}
    acr = {"default.acr.values": "mfa", "minimum.acr.value": "mfa", "pkce.code.challenge.method": "S256",
           "post.logout.redirect.uris": "##".join(f"{o}/*" for o in origens)}
    clientes = {
        "kc-auditor-bff": {"publicClient": False, "standardFlowEnabled": True, "directAccessGrantsEnabled": False,
                           "redirectUris": [f"{o}/auth/retorno" for o in origens], "webOrigins": origens,
                           "frontchannelLogout": False,
                           "attributes": {**acr, "backchannel.logout.url": f"{a.api}/auth/logout-canal",
                                          "backchannel.logout.session.required": "true"}},
        "kc-auditor-cli": {"publicClient": True, "standardFlowEnabled": False, "directAccessGrantsEnabled": False,
                           "attributes": {**acr, "oauth2.device.authorization.grant.enabled": "true",
                                          "oauth2.device.code.lifespan": "300"}},
    }
    for cid, rep in clientes.items():
        exist = kc.r("GET", f"/{REALM}/clients", params={"clientId": cid})
        if not exist:
            kc.r("POST", f"/{REALM}/clients", json={"clientId": cid, "protocol": "openid-connect", **rep})
            exist = kc.r("GET", f"/{REALM}/clients", params={"clientId": cid})
        else:
            kc.r("PUT", f"/{REALM}/clients/{exist[0]['id']}", json={**exist[0], **rep,
                                                                   "attributes": {**exist[0].get("attributes", {}),
                                                                                  **rep["attributes"]}})
        kc.r("PUT", f"/{REALM}/clients/{exist[0]['id']}/default-client-scopes/{escopos['kc-auditor']['id']}")
    bff = kc.r("GET", f"/{REALM}/clients", params={"clientId": "kc-auditor-bff"})[0]
    segredo = kc.r("GET", f"/{REALM}/clients/{bff['id']}/client-secret")["value"]
    for u, (papeis, unidade) in USUARIOS.items():
        kc.r("POST", f"/{REALM}/users", json={
            "username": u, "enabled": True, "firstName": u.capitalize(), "lastName": "Teste",
            "email": f"{u}@auditor.invalid", "emailVerified": True, "attributes": {"unidade": [unidade]},
            "credentials": [{"type": "password", "value": f"senha-{u}", "temporary": False}]})
        uid = kc.r("GET", f"/{REALM}/users", params={"username": u, "exact": "true"})[0]["id"]
        reps = [kc.r("GET", f"/{REALM}/roles/{p}") for p in papeis]
        if reps:
            kc.r("POST", f"/{REALM}/users/{uid}/role-mappings/realm", json=reps)
    destino = RAIZ / "chaves" / "realm_auditor.json"
    destino.parent.mkdir(exist_ok=True)
    destino.write_text(json.dumps({"emissor": f"{a.kc}/realms/{REALM}", "bff_id": "kc-auditor-bff",
                                   "bff_segredo": segredo, "cli_id": "kc-auditor-cli"}, indent=1))
    os.chmod(destino, 0o600)
    print(f"realm '{REALM}' pronto em {a.kc}; segredo do BFF em {destino.relative_to(RAIZ)}")
    print(f"  export AUDITOR_OIDC_EMISSOR={a.kc}/realms/{REALM}")


if __name__ == "__main__":
    main()

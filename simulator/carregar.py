"""Carrega realms, clients, usuários e service account no banco do simulador (esquema do Keycloak)."""
from __future__ import annotations

import argparse
import json
import sys
import time
import uuid
from pathlib import Path

import psycopg

RAIZ = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(RAIZ))
from tools.cenario import REALMS, SERVICE_ACCOUNT, SONDA  # noqa: E402

UP_CONFIG = {"unmanagedAttributePolicy": "ADMIN_VIEW", "attributes": [
    {"name": "username"}, {"name": "email"}, {"name": "firstName"}, {"name": "lastName"},
    {"name": "cpf", "permissions": {"view": ["admin"], "edit": ["admin"]}},
    {"name": "tituloEleitor", "permissions": {"view": ["admin"], "edit": ["admin"]}},
]}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dsn", required=True)
    ap.add_argument("--instancia", required=True, choices=list(REALMS))
    ap.add_argument("--pessoas", default=str(RAIZ / "dados/pessoas.json"))
    a = ap.parse_args()
    dados = json.loads(Path(a.pessoas).read_text())
    cfg = REALMS[a.instancia]
    agora = int(time.time() * 1000)
    with psycopg.connect(a.dsn, autocommit=False) as cx, cx.cursor() as cur:
        cur.execute((RAIZ / "simulator/schema.sql").read_text())
        cur.execute("TRUNCATE event_entity, admin_event_entity, user_attribute, user_entity, client, "
                    "realm_enabled_event_types, sim.user_profile, sim.component, sim.service_account CASCADE")
        cur.execute("DELETE FROM realm")
        ids = {"master": "master"}
        cur.execute("INSERT INTO realm(id,name) VALUES ('master','master')")
        for nome, rc in cfg.items():
            rid = str(uuid.uuid5(uuid.NAMESPACE_DNS, f"{a.instancia}.{nome}"))
            ids[nome] = rid
            cur.execute("INSERT INTO realm(id,name,events_enabled,events_expiration,admin_events_enabled,"
                        "admin_events_details_enabled) VALUES (%s,%s,%s,%s,true,true)",
                        (rid, nome, rc["events_enabled"], rc["expiration"]))
            for t in rc["types"]:
                cur.execute("INSERT INTO realm_enabled_event_types VALUES (%s,%s)", (rid, t))
            if a.instancia == "kc26":
                cur.execute("INSERT INTO sim.user_profile VALUES (%s,%s)", (rid, json.dumps(UP_CONFIG)))
            if rc.get("ldap"):
                cur.execute("INSERT INTO sim.component VALUES (%s,%s,'ldap','ldap',"
                            "'org.keycloak.storage.UserStorageProvider',%s)",
                            (str(uuid.uuid4()), rid, json.dumps({
                                "enabled": ["true"], "importEnabled": ["true"], "editMode": ["READ_ONLY"],
                                "fullSyncPeriod": ["86400"], "changedSyncPeriod": ["3600"],
                                "connectionUrl": ["ldaps://ldap.exemplo:636"], "bindDn": ["cn=svc"],
                                "bindCredential": ["**********"]})))
            for c in dados["clientes"].get(nome, ["app-homologacao"]):
                cur.execute("INSERT INTO client VALUES (%s,%s,%s)", (str(uuid.uuid4()), c, rid))
        visiveis = [n for n, rc in cfg.items() if not rc.get("sem_roles")]
        cur.execute("INSERT INTO sim.service_account VALUES (%s,%s,%s)",
                    (SERVICE_ACCOUNT["client_id"], SERVICE_ACCOUNT["secret"], visiveis))

        # Usuários: a conta EXCLUIDA não é criada (equivale a ter sido removida; os eventos dela continuam).
        users, attrs = [], []
        for c in dados["contas"]:
            if c["instancia"] != a.instancia or c["marca"] == "EXCLUIDA":
                continue
            users.append((c["id"], c["email"], True, True, None, c["nome"], c["sobrenome"],
                          ids[c["realm"]], c["username"],
                          agora - 400 * 86400000, None))
            attrs.append(("cpf", c["cpf_attr"], c["id"], str(uuid.uuid4())))
            attrs.append(("tituloEleitor", c["titulo_attr"], c["id"], str(uuid.uuid4())))
        sid = str(uuid.uuid5(uuid.NAMESPACE_DNS, f"{a.instancia}.sonda"))
        users.append((sid, "sonda@exemplo.gov.br", True, True, None, "Usuário", "Sonda", ids["homologacao"],
                      SONDA["username"], agora - 400 * 86400000, None))
        attrs.append(("cpf", SONDA["cpf"], sid, str(uuid.uuid4())))
        attrs.append(("tituloEleitor", SONDA["titulo"], sid, str(uuid.uuid4())))
        with cur.copy("COPY user_entity (id,email,email_verified,enabled,federation_link,first_name,last_name,"
                      "realm_id,username,created_timestamp,service_account_client_link) FROM STDIN") as cp:
            for u in users:
                cp.write_row(u)
        with cur.copy("COPY user_attribute (name,value,user_id,id) FROM STDIN") as cp:
            for r in attrs:
                cp.write_row(r)
        # Índice criado na 26.4.0 (só existe na instância 26.x)
        if a.instancia == "kc26":
            cur.execute("CREATE INDEX IF NOT EXISTS idx_event_entity_user_id_type "
                        "ON event_entity (user_id, type, event_time)")
        cx.commit()
    print(f"{a.instancia}: realms={len(cfg)} usuarios={len(users)}")


if __name__ == "__main__":
    main()

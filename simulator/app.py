"""Simulador da Admin REST API do Keycloak, para testes sem acesso às imagens oficiais.

Reproduz, sobre as tabelas do Keycloak no PostgreSQL, o comportamento do código-fonte de duas versões:

  SIM_PERFIL=kc26  Keycloak 26.8.2 (RealmAdminResource / DateUtil / JpaEventQuery da tag 26.8.2)
     - dateFrom/dateTo: 'yyyy-MM-dd' em UTC (início/fim do dia) ou epoch ms
     - direction=asc|desc (padrão desc); ordenação só por EVENT_TIME, sem desempate
     - q=atributo:valor com exact (padrão true; false = contém)
  SIM_PERFIL=kc18  Keycloak 18.0.2 legado (base do RH-SSO 7.6)
     - dateFrom/dateTo: só 'yyyy-MM-dd' (SimpleDateFormat no fuso da JVM, SIM_TZ); epoch -> 400
     - dateTo = meia-noite do dia informado (o 18.0.2 não leva ao fim do dia)
     - sem parâmetro direction (ignorado): sempre decrescente
     - q=atributo:valor: igualdade sem diferenciar maiúsculas
     - caminho com prefixo /auth

Não é o Keycloak: o objetivo é exercitar o coletor com volume real. A validação final é contra a stack real.
"""
from __future__ import annotations

import os
import re
import secrets
import threading
import time
from datetime import date, datetime, time as dtime
from zoneinfo import ZoneInfo

from fastapi import APIRouter, Depends, FastAPI, Form, Header, HTTPException, Query, Request
from fastapi.responses import JSONResponse
from psycopg.rows import dict_row
from psycopg_pool import ConnectionPool

PERFIL = os.environ.get("SIM_PERFIL", "kc26")
DSN = os.environ["SIM_DSN"]
TZ = ZoneInfo(os.environ.get("SIM_TZ", "UTC"))
TOKEN_TTL = int(os.environ.get("SIM_TOKEN_TTL", "60"))
PURGA_INTERVALO = int(os.environ.get("SIM_PURGA_INTERVALO", "0"))
BASE = "/auth" if PERFIL == "kc18" else ""
DEFAULT_MAX = 100
# Variantes para testar as sondas (comportamentos de versões específicas)
BUG_DATETO = os.environ.get("SIM_BUG_DATETO") == "1"        # 26.2.0: filtro dateTo retorna vazio
SEM_DIRECTION = os.environ.get("SIM_SEM_DIRECTION") == "1"  # versões sem o parâmetro direction
EXACT_CURINGA = os.environ.get("SIM_EXACT_CURINGA") == "1"  # 26.0.7: busca por atributo curinga por padrão

pool = ConnectionPool(DSN, min_size=2, max_size=int(os.environ.get("SIM_POOL", "8")), kwargs={"row_factory": dict_row})
app = FastAPI(title=f"Keycloak Admin API simulada ({PERFIL})")
r = APIRouter(prefix=BASE)
TOKENS: dict[str, tuple[float, set[str]]] = {}
STATS = {"requisicoes": 0}


@app.middleware("http")
async def contar(request: Request, call_next):
    STATS["requisicoes"] += 1
    return await call_next(request)


def q(sql, args=()):
    with pool.connection() as cx:
        return cx.execute(sql, args).fetchall()


# ------------------------------------------------------------------ autenticação
@r.post("/realms/{realm}/protocol/openid-connect/token")
def token(realm: str, grant_type: str = Form(...), client_id: str = Form(...), client_secret: str = Form("")):
    if realm != "master" or grant_type != "client_credentials":
        raise HTTPException(400, {"error": "unsupported_grant_type"})
    rows = q("SELECT secret, realms FROM sim.service_account WHERE client_id=%s", (client_id,))
    if not rows or rows[0]["secret"] != client_secret:
        return JSONResponse({"error": "unauthorized_client"}, 401)
    tok = secrets.token_urlsafe(32)
    TOKENS[tok] = (time.time() + TOKEN_TTL, set(rows[0]["realms"]))
    return {"access_token": tok, "expires_in": TOKEN_TTL, "token_type": "Bearer", "scope": "profile email"}


def auth(authorization: str = Header(None)) -> set[str]:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(401)
    t = TOKENS.get(authorization[7:])
    if not t or t[0] < time.time():
        raise HTTPException(401)
    return t[1]


def realm_visivel(nome: str, realms: set[str]) -> dict:
    rows = q("SELECT * FROM realm WHERE name=%s", (nome,))
    if not rows:
        raise HTTPException(404, {"error": "Realm not found."})
    if nome not in realms:
        raise HTTPException(403, {"error": "HTTP 403 Forbidden"})
    return rows[0]


# ------------------------------------------------------------------ realms e configuração
@r.get("/admin/serverinfo")
def serverinfo(realms=Depends(auth)):
    return {"systemInfo": {"version": None, "serverTime": datetime.now().isoformat()}}


@r.get("/admin/realms")
def listar_realms(briefRepresentation: bool = False, realms=Depends(auth)):
    rows = q("SELECT id, name, enabled FROM realm ORDER BY name")
    return [{"id": x["id"], "realm": x["name"], "enabled": x["enabled"]} for x in rows if x["name"] in realms]


@r.get("/admin/realms/{realm}/events/config")
def events_config(realm: str, realms=Depends(auth)):
    rm = realm_visivel(realm, realms)
    tipos = [x["value"] for x in q("SELECT value FROM realm_enabled_event_types WHERE realm_id=%s ORDER BY value",
                                   (rm["id"],))]
    return {"eventsEnabled": rm["events_enabled"], "eventsExpiration": rm["events_expiration"],
            "eventsListeners": ["jboss-logging"], "enabledEventTypes": tipos,
            "adminEventsEnabled": rm["admin_events_enabled"],
            "adminEventsDetailsEnabled": rm["admin_events_details_enabled"]}


@r.get("/admin/realms/{realm}/users/profile")
def user_profile(realm: str, realms=Depends(auth)):
    if PERFIL == "kc18":
        raise HTTPException(404)
    rm = realm_visivel(realm, realms)
    rows = q("SELECT config FROM sim.user_profile WHERE realm_id=%s", (rm["id"],))
    return rows[0]["config"] if rows else {"attributes": []}


@r.get("/admin/realms/{realm}/components")
def components(realm: str, type: str | None = None, realms=Depends(auth)):
    rm = realm_visivel(realm, realms)
    rows = q("SELECT * FROM sim.component WHERE realm_id=%s AND (%s::text IS NULL OR provider_type=%s)",
             (rm["id"], type, type))
    return [{"id": x["id"], "name": x["name"], "providerId": x["provider_id"], "providerType": x["provider_type"],
             "parentId": rm["id"], "config": x["config"]} for x in rows]


# ------------------------------------------------------------------ usuários
# Mesmo padrão do SearchQueryUtils (18.0.2 e atual): chave:valor, com aspas para valores com espaço.
QUERY_RE = re.compile(r'\s*(?:(?P<name>[^"][^: ]+)|"(?P<nameEsc>(?:\\.|[^\\"])+)"):'
                      r'(?:(?P<value>[^"][^ ]*)|"(?P<valueEsc>(?:\\.|[^\\"])+)")\s*')


def parse_q(s: str) -> dict[str, str]:
    out, pos = {}, 0
    while pos < len(s):
        m = QUERY_RE.match(s, pos)
        if not m or m.end() == pos:
            raise HTTPException(400, {"error": "invalid query"})
        k = m.group("name") or re.sub(r"\\(.)", r"\1", m.group("nameEsc"))
        v = m.group("value") or re.sub(r"\\(.)", r"\1", m.group("valueEsc"))
        out[k] = v
        pos = m.end()
    return out


def rep_usuario(u: dict, brief: bool) -> dict:
    d = {"id": u["id"], "username": u["username"], "email": u["email"], "firstName": u["first_name"],
         "lastName": u["last_name"], "enabled": u["enabled"], "createdTimestamp": u["created_timestamp"],
         "federationLink": u["federation_link"]}
    if not brief:
        attrs = {}
        for a in q("SELECT name, value FROM user_attribute WHERE user_id=%s", (u["id"],)):
            attrs.setdefault(a["name"], []).append(a["value"])
        d["attributes"] = attrs
    return d


@r.get("/admin/realms/{realm}/users")
def usuarios(realm: str, search: str | None = None, username: str | None = None, q_: str | None = Query(None, alias="q"),
             exact: bool | None = None, first: int = 0, max: int = DEFAULT_MAX,
             briefRepresentation: bool = False, realms=Depends(auth)):
    rm = realm_visivel(realm, realms)
    where, args = ["u.realm_id=%s", "u.service_account_client_link IS NULL"], [rm["id"]]
    if username is not None:
        if exact:
            where.append("u.username = lower(%s)"); args.append(username)
        else:
            where.append("u.username LIKE %s"); args.append(f"%{username.lower()}%")
    if search is not None:
        s = search.strip('"').lower()
        where.append("(u.username LIKE %s OR lower(u.email) LIKE %s OR lower(u.first_name) LIKE %s "
                     "OR lower(u.last_name) LIKE %s)")
        args += [f"%{s}%"] * 4
    if q_:
        for k, v in parse_q(q_).items():
            if PERFIL == "kc18":
                cond = "lower(a.name)=lower(%s) AND lower(a.value)=lower(%s)"; val = v
            elif (exact is None and not EXACT_CURINGA) or exact:
                cond = "a.name=%s AND lower(a.value)=lower(%s)"; val = v
            else:
                cond = "a.name=%s AND lower(a.value) LIKE %s"; val = f"%{v.lower()}%"
            where.append(f"EXISTS (SELECT 1 FROM user_attribute a WHERE a.user_id=u.id AND {cond})")
            args += [k, val]
    rows = q(f"SELECT u.* FROM user_entity u WHERE {' AND '.join(where)} ORDER BY u.username OFFSET %s LIMIT %s",
             (*args, first, max))
    return [rep_usuario(u, briefRepresentation) for u in rows]


@r.get("/admin/realms/{realm}/users/{uid}/sessions")
def sessoes(realm: str, uid: str, realms=Depends(auth)):
    realm_visivel(realm, realms)
    return []


# ------------------------------------------------------------------ eventos
def _data_kc26(s: str, fim: bool) -> int:
    if "-" in s:
        d = date.fromisoformat(s)
        t = dtime.max if fim else dtime.min
        return int(datetime.combine(d, t, tzinfo=ZoneInfo("UTC")).timestamp() * 1000) - (0 if not fim else 0)
    return int(s)


def _data_kc18(s: str) -> int:
    m = re.fullmatch(r"(\d{1,4})-(\d{1,2})-(\d{1,2}).*", s)  # SimpleDateFormat leniente ignora o resto
    if not m:
        raise HTTPException(400, {"error": "Invalid value for 'Date(From)', expected format is yyyy-MM-dd"})
    d = datetime(int(m.group(1)), int(m.group(2)), int(m.group(3)), tzinfo=TZ)
    return int(d.timestamp() * 1000)


def _fim_dia_kc26(s: str) -> int:
    if "-" in s:
        d = date.fromisoformat(s)
        return int(datetime.combine(d, dtime(23, 59, 59, 999000), tzinfo=ZoneInfo("UTC")).timestamp() * 1000)
    return int(s)


@r.get("/admin/realms/{realm}/events")
def eventos(realm: str, request: Request, client: str | None = None, user: str | None = None,
            dateFrom: str | None = None, dateTo: str | None = None, ipAddress: str | None = None,
            first: int | None = None, max: int | None = None, realms=Depends(auth)):
    rm = realm_visivel(realm, realms)
    tipos = request.query_params.getlist("type")
    where, args = ["realm_id=%s"], [rm["id"]]
    if client:
        where.append("client_id=%s"); args.append(client)
    if tipos:
        where.append("type = ANY(%s)"); args.append(tipos)
    if user:
        where.append("user_id=%s"); args.append(user)
    if PERFIL == "kc26":
        try:
            if dateFrom:
                where.append("event_time >= %s"); args.append(_data_kc26(dateFrom, False))
            if dateTo:
                where.append("event_time <= %s"); args.append(_fim_dia_kc26(dateTo))
        except ValueError:
            raise HTTPException(400, {"error": "Invalid value for 'dateFrom', expected format is yyyy-MM-dd "
                                               "or an Epoch timestamp"})
        if BUG_DATETO and dateTo:
            return []
        direction = None if SEM_DIRECTION else request.query_params.get("direction")
        if direction not in (None, "asc", "desc"):
            raise HTTPException(400, {"error": "Invalid value for sortDirection, expected value is asc or desc"})
        ordem = "ASC" if direction == "asc" else "DESC"
    else:
        if dateFrom:
            where.append("event_time >= %s"); args.append(_data_kc18(dateFrom))
        if dateTo:
            where.append("event_time <= %s"); args.append(_data_kc18(dateTo))
        ordem = "DESC"
    if ipAddress:
        where.append("ip_address=%s"); args.append(ipAddress)
    sql = (f"SELECT id, event_time, type, realm_id, client_id, user_id, session_id, ip_address, error, details_json "
           f"FROM event_entity WHERE {' AND '.join(where)} ORDER BY event_time {ordem} "
           f"OFFSET %s LIMIT %s")
    rows = q(sql, (*args, first or 0, max if max is not None else DEFAULT_MAX))
    import json as _j
    out = []
    for e in rows:
        d = {"id": e["id"], "time": e["event_time"], "type": e["type"], "realmId": e["realm_id"],
             "clientId": e["client_id"], "userId": e["user_id"], "sessionId": e["session_id"],
             "ipAddress": e["ip_address"]}
        if e["error"]:
            d["error"] = e["error"]
        if e["details_json"]:
            d["details"] = _j.loads(e["details_json"])
        out.append({k: v for k, v in d.items() if v is not None})
    return out


@r.get("/admin/realms/{realm}/admin-events")
def admin_eventos(realm: str, request: Request, resourcePath: str | None = None, dateFrom: str | None = None,
                  dateTo: str | None = None, first: int = 0, max: int = DEFAULT_MAX, realms=Depends(auth)):
    rm = realm_visivel(realm, realms)
    where, args = ["realm_id=%s"], [rm["id"]]
    ops = request.query_params.getlist("operationTypes")
    if ops:
        where.append("operation_type = ANY(%s)"); args.append(ops)
    if resourcePath:
        where.append("resource_path LIKE %s"); args.append(resourcePath.replace("*", "%"))
    if dateFrom:
        where.append("admin_event_time >= %s")
        args.append(_data_kc26(dateFrom, False) if PERFIL == "kc26" else _data_kc18(dateFrom))
    if dateTo:
        where.append("admin_event_time <= %s")
        args.append(_fim_dia_kc26(dateTo) if PERFIL == "kc26" else _data_kc18(dateTo))
    rows = q(f"SELECT * FROM admin_event_entity WHERE {' AND '.join(where)} ORDER BY admin_event_time DESC "
             f"OFFSET %s LIMIT %s", (*args, first, max))
    return [{"id": x["id"], "time": x["admin_event_time"], "realmId": x["realm_id"],
             "operationType": x["operation_type"], "resourceType": x["resource_type"],
             "resourcePath": x["resource_path"], "representation": x["representation"],
             "authDetails": {"realmId": x["auth_realm_id"], "userId": x["auth_user_id"],
                             "ipAddress": x["ip_address"]}} for x in rows]


app.include_router(r)


@app.get("/_sim/stats")
def stats():
    return {"perfil": PERFIL, **STATS}


# ------------------------------------------------------------------ expurgo (ClearExpiredEvents)
def purgar_uma_vez() -> int:
    agora = int(time.time() * 1000)
    total = 0
    with pool.connection() as cx:
        for rm in cx.execute("SELECT id, events_expiration FROM realm WHERE events_expiration > 0").fetchall():
            cur = cx.execute("DELETE FROM event_entity WHERE realm_id=%s AND event_time < %s",
                             (rm["id"], agora - rm["events_expiration"] * 1000))
            total += cur.rowcount
    return total


@app.post("/_sim/purgar")
def purgar():
    return {"removidos": purgar_uma_vez()}


def _laco_purga():
    while True:
        time.sleep(PURGA_INTERVALO)
        try:
            purgar_uma_vez()
        except Exception:  # noqa: BLE001
            pass


if PURGA_INTERVALO > 0:
    threading.Thread(target=_laco_purga, daemon=True).start()

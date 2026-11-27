"""Descoberta de realms, snapshot da configuração de eventos e localização das contas."""
from __future__ import annotations

from psycopg.types.json import Jsonb

from . import sondas
from .identificador import so_digitos, variantes
from .kc import ClienteKC, ErroKC, SemPermissao

TIPOS_SALVOS_POR_PADRAO = {"LOGIN", "LOGIN_ERROR", "LOGOUT", "LOGOUT_ERROR", "CODE_TO_TOKEN",
                           "CODE_TO_TOKEN_ERROR", "UPDATE_PASSWORD", "RESET_PASSWORD", "IDENTITY_PROVIDER_LOGIN",
                           "IDENTITY_PROVIDER_LOGIN_ERROR", "TOKEN_EXCHANGE", "CLIENT_LOGIN"}


def tipos_gravados(config: dict) -> set[str]:
    t = config.get("enabledEventTypes") or []
    return set(t) if t else set(TIPOS_SALVOS_POR_PADRAO)


def avaliar_realm(config: dict | None, s5: dict, atributo: str) -> tuple[str, str | None, str | None]:
    """Status do realm independente do período: (status, detalhe, ação corretiva)."""
    if config is None:
        return "sem_permissao", "Sem permissão para ler eventos", \
            "Conceder view-events ao service account no client {realm}-realm"
    if not config.get("eventsEnabled"):
        return "eventos_nao_gravados", "Eventos de usuário não são gravados", \
            "Realm settings › Events › User events settings › Save events = ON"
    tipos = tipos_gravados(config)
    if not ({"LOGIN", "IDENTITY_PROVIDER_LOGIN"} & tipos):
        return "tipo_nao_gravado", "Login não está entre os tipos gravados", "Incluir LOGIN nos tipos salvos"
    if "LOGIN_ERROR" not in tipos:
        return "falhas_nao_gravadas", "Falhas de login (LOGIN_ERROR) não são gravadas", \
            "Incluir LOGIN_ERROR nos tipos salvos"
    if s5.get("user_profile") == "ausente":
        return "atributo_nao_pesquisavel", f"Atributo {atributo} não declarado no User Profile", \
            f"Declarar {atributo} no User Profile com leitura para admin"
    fed = s5.get("federacao")
    if isinstance(fed, list) and any(f.get("enabled") == "true" and f.get("importEnabled") == "false" for f in fed):
        return "federacao_sem_importacao", "Federação sem importação: busca por atributo pode falhar", \
            "Validar busca de reserva por username"
    return "ok", None, None


def descobrir(cx, inst: dict, cli: ClienteKC) -> list[dict]:
    visiveis = {r["realm"] for r in cli.realms()}
    atributo = inst["mapeamento"].get("cpf", "cpf")
    saida = []
    for realm in sorted(visiveis | set(inst["realms_esperados"])):
        if realm == "master" or realm == inst.get("realm_homologacao"):
            continue
        if realm not in visiveis:
            snap = {"realm": realm, "visivel": False, "config": None, "s5": {}, "status": "esperado_invisivel",
                    "detalhe": "Realm esperado não aparece para o service account",
                    "acao": "Conceder as roles de leitura no client " + realm + "-realm"}
        else:
            try:
                config = cli.get(f"/admin/realms/{realm}/events/config")
            except SemPermissao:
                config = None
            s5 = sondas.s5_realm(cli, realm, atributo)
            st, det, acao = avaliar_realm(config, s5, atributo)
            snap = {"realm": realm, "visivel": True, "config": config, "s5": s5, "status": st, "detalhe": det,
                    "acao": acao}
        cx.execute("INSERT INTO realm_snapshot (instancia_id, realm, visivel, config, user_profile, federacao, "
                   "status, detalhe, acao) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)",
                   (inst["id"], realm, snap["visivel"], Jsonb(snap["config"]),
                    Jsonb(snap["s5"].get("user_profile")), Jsonb(snap["s5"].get("federacao")),
                    snap["status"], snap["detalhe"], snap["acao"]))
        saida.append(snap)
    return saida


def localizar(cli: ClienteKC, inst: dict, realms: list[dict], tipo: str, digitos: str) -> tuple[list[dict], list]:
    """Busca o identificador em cada realm visível. Retorna (contas, erros)."""
    attr = inst["mapeamento"].get(tipo)
    contas, erros = {}, []
    for snap in realms:
        if not snap["visivel"] or snap["status"] == "sem_permissao":
            continue
        realm = snap["realm"]
        try:
            for v in variantes(tipo, digitos):
                qv = f'"{v}"' if " " in v else v
                for u in cli.get(f"/admin/realms/{realm}/users",
                                 {"q": f"{attr}:{qv}", "exact": "true", "briefRepresentation": "false",
                                  "max": "100"}):
                    vals = (u.get("attributes") or {}).get(attr, [])
                    if any(so_digitos(x) == digitos for x in vals):  # igualdade local (sonda S4)
                        contas[(realm, u["id"])] = {**u, "realm": realm, "via": "atributo"}
                if inst["buscar_username"]:
                    for u in cli.get(f"/admin/realms/{realm}/users",
                                     {"username": v, "exact": "true", "briefRepresentation": "false"}):
                        if so_digitos(u["username"]) == digitos and u["username"] in variantes(tipo, digitos):
                            contas.setdefault((realm, u["id"]), {**u, "realm": realm, "via": "username"})
        except ErroKC as e:
            erros.append((realm, str(e)))
    return list(contas.values()), erros

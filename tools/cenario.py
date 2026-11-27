"""Cenário de teste compartilhado pelo seed real (Admin API), pelo simulador e pelo gerador de eventos."""

DIA = 86400

# enabled_event_types vazio = o Keycloak grava só os tipos "salvar por padrão"
# (REFRESH_TOKEN e REFRESH_TOKEN_ERROR ficam de fora).
TIPOS_COMPLETOS = ["LOGIN", "LOGIN_ERROR", "LOGOUT", "LOGOUT_ERROR", "CODE_TO_TOKEN", "CODE_TO_TOKEN_ERROR",
                   "REFRESH_TOKEN", "REFRESH_TOKEN_ERROR", "UPDATE_PASSWORD", "RESET_PASSWORD"]

REALMS = {
    "kc26": {
        "portal-cidadao": {"events_enabled": True, "expiration": None, "types": []},
        "intranet": {"events_enabled": True, "expiration": 365 * DIA, "types": TIPOS_COMPLETOS},
        "servicos": {"events_enabled": True, "expiration": 90 * DIA, "types": TIPOS_COMPLETOS},
        # realm sem roles para o service account: deve aparecer como "esperado e invisível"
        "parceiros": {"events_enabled": True, "expiration": None, "types": TIPOS_COMPLETOS, "sem_roles": True},
        "homologacao": {"events_enabled": True, "expiration": None, "types": TIPOS_COMPLETOS, "homologacao": True},
    },
    "kc18": {
        "portal-cidadao": {"events_enabled": True, "expiration": None, "types": TIPOS_COMPLETOS},
        # sem LOGIN_ERROR gravado: cobertura parcial ("falhas de login não gravadas")
        "legado": {"events_enabled": True, "expiration": None,
                   "types": ["LOGIN", "LOGOUT", "CODE_TO_TOKEN", "REFRESH_TOKEN"], "ldap": True},
        # eventos desligados: cobertura "sem dados"
        "rh": {"events_enabled": False, "expiration": None, "types": []},
        "homologacao": {"events_enabled": True, "expiration": None, "types": TIPOS_COMPLETOS, "homologacao": True},
    },
}

SERVICE_ACCOUNT = {"client_id": "kc-auditor", "secret": "troque-este-segredo"}
SONDA = {"username": "sonda", "cpf": "52998224725", "titulo": "004356870906"}
PERIODO_DIAS = 180

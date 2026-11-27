"""Quem é o usuário e o que ele pode (W1, PROPOSTA_WEB §4.1 e §4.2). Usado pelos casos de uso (auditor/casos.py), que
são a única porta da API e da CLI de produção: as regras valem igual nas duas.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field

PAPEIS = ("solicitante", "investigador", "aprovador", "auditor_interno", "admin_tecnico", "gestor_acesso")
EXCLUSIVOS = ("gestor_acesso", "admin_tecnico")   # não acumulam nenhum outro papel do auditor
STEP_UP_S = 300


class Negado(PermissionError):
    def __init__(self, codigo: str, texto: str, status: int = 403):
        super().__init__(texto)
        self.codigo, self.status = codigo, status


class StepUpExigido(Negado):
    def __init__(self):
        super().__init__("step_up", "Esta ação exige autenticação recente (MFA nos últimos 5 minutos)", 401)


@dataclass(frozen=True)
class Ator:
    sub: str
    username: str
    papeis: frozenset
    auth_time: int
    porta: str                      # web | cli
    nome: str | None = None
    unidade: str | None = None
    token: str | None = field(default=None, repr=False)   # access token, repassado ao chaveiro (modo vault)

    @classmethod
    def de_claims(cls, c: dict, porta: str, token: str | None = None) -> "Ator":
        from .oidc import papeis
        return cls(sub=c["sub"], username=c.get("preferred_username", c["sub"]),
                   papeis=frozenset(papeis(c) & set(PAPEIS)), auth_time=int(c.get("auth_time") or 0), porta=porta,
                   nome=c.get("name"), unidade=c.get("unidade"), token=token)

    def tem(self, *papeis: str) -> bool:
        return bool(self.papeis & set(papeis))

    def exigir(self, *papeis: str):
        if not self.papeis:
            raise Negado("sem_perfil", "Usuário sem perfil no auditor")
        if not self.tem(*papeis):
            raise Negado("perfil", f"Exige o perfil {' ou '.join(papeis)}")

    def exigir_recente(self):
        if time.time() - self.auth_time > STEP_UP_S:
            raise StepUpExigido()


def conferir_papeis(papeis) -> None:
    """Login recusado com papéis conflitantes, mesmo que o realm os tenha concedido (§4.1)."""
    p = set(papeis) & set(PAPEIS)
    for x in EXCLUSIVOS:
        if x in p and len(p) > 1:
            raise Negado("papeis_conflitantes", f"O perfil {x} não acumula outros perfis: login recusado")


def funcoes(cx, inv_id: int, sub: str) -> set[str]:
    return {r["funcao"] for r in cx.execute("SELECT funcao FROM designacao WHERE investigacao_id=%s AND sub=%s",
                                            (inv_id, sub))}

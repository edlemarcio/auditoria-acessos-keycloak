"""Perfis do auditor no realm dedicado (W2, PROPOSTA_WEB §4.2 e §4.3): Keycloak Admin do realm `auditor` pela conta
de serviço própria `kc-auditor-gestao` (só manage-users/view-users daquele realm), recertificação e vigia de papéis.

A regra (quem pode conceder, combinações proibidas, step-up) fica em auditor/casos.py; aqui só a mecânica. O vigia
compara os papéis do realm com os últimos vistos (tabela papel_visto) e alerta o auditor interno de qualquer mudança,
inclusive a feita direto no console do Keycloak.

  AUDITOR_OIDC_EMISSOR (realm), chaves/realm_auditor.json (gestao_id, gestao_segredo) ou AUDITOR_GESTAO_SEGREDO
"""
from __future__ import annotations

import json
import os
import threading
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import httpx

from . import siem
from .acesso import PAPEIS
from .db import trilha

GESTAO_ID = "kc-auditor-gestao"
RECERT_PRAZO = timedelta(days=30)
_tok: dict = {}
_lock = threading.Lock()


def _cfg() -> dict:
    p = Path(os.environ.get("AUDITOR_REALM_CFG", "chaves/realm_auditor.json"))
    c = json.loads(p.read_text()) if p.exists() else {}
    em = os.environ.get("AUDITOR_OIDC_EMISSOR", "").rstrip("/")
    base, _, realm = em.partition("/realms/")
    return {"id": c.get("gestao_id", GESTAO_ID), "segredo": os.environ.get("AUDITOR_GESTAO_SEGREDO") or
            c.get("gestao_segredo"), "base": base, "realm": realm, "emissor": em}


def configurado() -> bool:
    c = _cfg()
    return bool(c["segredo"] and c["realm"])


class IndisponivelKC(RuntimeError):
    pass


class Admin:
    """Admin REST do realm dedicado com o token de client credentials da conta de serviço (renovado sozinho)."""

    def __init__(self):
        self.c = _cfg()
        if not self.c["segredo"]:
            raise IndisponivelKC("conta de serviço kc-auditor-gestao sem segredo (rode infra/realm_auditor.py)")
        self.h = httpx.Client(base_url=f"{self.c['base']}/admin/realms/{self.c['realm']}", timeout=20,
                              trust_env=False)

    def _token(self) -> str:
        with _lock:
            if _tok.get("v") and _tok["exp"] > time.time() + 30:
                return _tok["v"]
            r = httpx.post(f"{self.c['emissor']}/protocol/openid-connect/token", timeout=20, trust_env=False,
                           data={"grant_type": "client_credentials", "client_id": self.c["id"],
                                 "client_secret": self.c["segredo"]})
            if r.status_code != 200:
                raise IndisponivelKC(f"token da conta de serviço recusado: HTTP {r.status_code}")
            _tok.update(v=r.json()["access_token"], exp=time.time() + r.json().get("expires_in", 60))
            return _tok["v"]

    def r(self, metodo: str, caminho: str, **kw):
        try:
            x = self.h.request(metodo, caminho, headers={"Authorization": f"Bearer {self._token()}"}, **kw)
        except httpx.TransportError as e:
            raise IndisponivelKC(f"Keycloak indisponível: {type(e).__name__}") from e
        if x.status_code >= 400:
            raise IndisponivelKC(f"Keycloak: {metodo} {caminho.split('/')[1] if '/' in caminho else caminho} "
                                 f"HTTP {x.status_code}")
        return x.json() if x.content else None

    def fechar(self):
        self.h.close()

    # ---- usuários
    def usuarios(self) -> list[dict]:
        out = []
        for u in self.r("GET", "/users", params={"max": 2000, "briefRepresentation": "false"}):
            out.append(self._usuario(u))
        return out

    def usuario(self, username: str) -> dict | None:
        us = self.r("GET", "/users", params={"username": username, "exact": "true", "briefRepresentation": "false"})
        return self._usuario(us[0]) if us else None

    def _usuario(self, u: dict) -> dict:
        a = u.get("attributes") or {}
        papeis = sorted({p["name"] for p in self.r("GET", f"/users/{u['id']}/role-mappings/realm") or []}
                        & set(PAPEIS))
        return {"sub": u["id"], "username": u["username"],
                "nome": " ".join(x for x in (u.get("firstName"), u.get("lastName")) if x) or None,
                "unidade": (a.get("unidade") or [None])[0], "papeis": papeis, "habilitado": u.get("enabled", True),
                "coordenador": (a.get("coordenador") or ["false"])[0].lower() == "true"}

    def mudar_papeis(self, sub: str, conceder: list[str], revogar: list[str]):
        if conceder:
            disp = {p["name"]: p for p in self.r("GET", f"/users/{sub}/role-mappings/realm/available") or []}
            faltam = [p for p in conceder if p not in disp]
            reps = [disp[p] for p in conceder if p in disp]
            if reps:
                self.r("POST", f"/users/{sub}/role-mappings/realm", json=reps)
            if faltam:   # já concedido (não aparece entre os disponíveis): nada a fazer
                pass
        if revogar:
            atuais = {p["name"]: p for p in self.r("GET", f"/users/{sub}/role-mappings/realm") or []}
            reps = [atuais[p] for p in revogar if p in atuais]
            if reps:
                self.r("DELETE", f"/users/{sub}/role-mappings/realm", json=reps)


# ------------------------------------------------------------------ alerta e vigia
def alertar(cx, sub: str, username: str, concedidos, revogados, origem: str, por: str | None = None,
            motivo: str | None = None):
    """Toda concessão/revogação: trilha global, SIEM (whitelist) e notificação ao auditor interno."""
    from .gestao import com_papel, notificar
    concedidos, revogados = sorted(concedidos), sorted(revogados)
    trilha(cx, por or "realm-auditor", "mudanca_de_papel", None, usuario=sub, concedidos=concedidos,
           revogados=revogados, origem=origem, motivo=motivo)
    siem.enviar("mudanca_de_papel", "alerta", ator=por or "realm-auditor", motivo_codigo=origem,
                quantidade=len(concedidos) + len(revogados))
    rotulo = {"api": "pelo gestor de acesso", "console": "direto no Keycloak", "recertificacao": "na recertificação",
              "recertificacao_vencida": "por recertificação vencida"}.get(origem, origem)
    txt = f"Perfis de {username} alterados ({rotulo})" + \
          (f": +{', +'.join(concedidos)}" if concedidos else "") + (f" -{', -'.join(revogados)}" if revogados else "")
    notificar(cx, com_papel(cx, "auditor_interno"), "papel_alterado", txt)


def registrar_visto(cx, u: dict):
    cx.execute("INSERT INTO papel_visto (sub, username, papeis, coordenador) VALUES (%s,%s,%s,%s) "
               "ON CONFLICT (sub) DO UPDATE SET username=EXCLUDED.username, papeis=EXCLUDED.papeis, "
               "coordenador=EXCLUDED.coordenador, visto_em=now()", (u["sub"], u["username"], u["papeis"],
                                                                   u["coordenador"]))


def vigiar(cx, adm: Admin | None = None) -> list[dict]:
    """Compara os papéis do realm com os vistos; a primeira passada só grava a referência."""
    adm = adm or Admin()
    try:
        us = adm.usuarios()
    finally:
        adm.fechar()
    vistos = {r["sub"]: r for r in cx.execute("SELECT * FROM papel_visto")}
    primeira = not vistos
    mudancas = []
    for u in us:
        antes = vistos.pop(u["sub"], None)
        a = set(antes["papeis"]) if antes else set()
        b = set(u["papeis"])
        if (antes is None and b and not primeira) or (antes is not None and a != b):
            mudancas.append({"usuario": u["username"], "concedidos": sorted(b - a), "revogados": sorted(a - b)})
            alertar(cx, u["sub"], u["username"], b - a, a - b, "console")
        if antes is None or a != b or antes["coordenador"] != u["coordenador"] or antes["username"] != u["username"]:
            registrar_visto(cx, u)
    for sub, antes in vistos.items():   # usuário excluído do realm
        if antes["papeis"]:
            mudancas.append({"usuario": antes["username"], "concedidos": [], "revogados": sorted(antes["papeis"])})
            alertar(cx, sub, antes["username"], set(), set(antes["papeis"]), "console")
        cx.execute("DELETE FROM papel_visto WHERE sub=%s", (sub,))
    return mudancas


def vencer_recertificacoes(cx, agora: datetime | None = None) -> list[int]:
    """Recertificação vencida: o que não foi confirmado é revogado (§4.3)."""
    agora = agora or datetime.now(timezone.utc)
    feitas = []
    for rc in cx.execute("SELECT * FROM recertificacao WHERE encerrada_em IS NULL AND prazo <= %s",
                         (agora,)).fetchall():
        adm = Admin()
        try:
            for it in cx.execute("SELECT * FROM recertificacao_item WHERE recertificacao_id=%s AND manter IS NULL",
                                 (rc["id"],)).fetchall():
                revogar(cx, adm, it["sub"], it["username"], "sistema", "recertificacao_vencida")
                cx.execute("UPDATE recertificacao_item SET manter=false, decidido_por='sistema', decidido_em=now() "
                           "WHERE recertificacao_id=%s AND sub=%s", (rc["id"], it["sub"]))
        finally:
            adm.fechar()
        cx.execute("UPDATE recertificacao SET encerrada_em=now() WHERE id=%s", (rc["id"],))
        trilha(cx, "sistema", "encerrar_recertificacao", None, recertificacao=rc["id"], vencida=True)
        feitas.append(rc["id"])
    return feitas


def revogar(cx, adm: Admin, sub: str, username: str, por: str, origem: str) -> list[str]:
    """Revoga todos os papéis do auditor de um usuário (recertificação não confirmada)."""
    atuais = [p for p in (adm.usuario(username) or {}).get("papeis", [])]
    if atuais:
        adm.mudar_papeis(sub, [], atuais)
        alertar(cx, sub, username, set(), set(atuais), origem, por)
    u = adm.usuario(username)
    if u:
        registrar_visto(cx, u)
    return atuais

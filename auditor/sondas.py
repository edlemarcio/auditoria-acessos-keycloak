"""Sondas de comportamento (S1-S4, S6, S7) no realm de homologação, e S5 por realm (somente leitura).

O resultado define o modo de coleta da instância:
  epoch_asc   epoch ms aceito e direction=asc funciona            (Keycloak 26.x)
  epoch_desc  epoch ms aceito, mas só ordem decrescente
  dia         só 'yyyy-MM-dd' (Keycloak 18 / RH-SSO 7.6); fuso do servidor medido pela S6
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from .identificador import so_digitos
from .kc import ClienteKC, ErroKC, NaoEncontrado, RequisicaoInvalida

MEIA_HORA = 1800_000


def _ids(evs):
    return {e["id"] for e in evs}


def executar(cli: ClienteKC, realm: str, usuario_sonda: str, atributo_cpf: str = "cpf") -> dict:
    res: dict = {"realm": realm, "executado_em": datetime.now(timezone.utc).isoformat()}
    us = cli.get(f"/admin/realms/{realm}/users", {"username": usuario_sonda, "exact": "true",
                                                    "briefRepresentation": "false"})
    us = [u for u in us if u["username"] == usuario_sonda]
    if not us:
        return {**res, "inconclusiva": "usuário de sonda não encontrado", "modo": "dia"}
    sonda = us[0]
    uid = sonda["id"]
    todos = cli.eventos(realm, [("user", uid), ("max", "1000")])
    if len(todos) < 4:
        return {**res, "inconclusiva": "menos de 4 eventos no usuário de sonda", "modo": "dia"}
    tempos = sorted({e["time"] for e in todos})

    # S1 epoch ms: evento T aparece com dateFrom=dateTo=T e não aparece com dateFrom=T+1
    T = tempos[len(tempos) // 2]
    try:
        a = cli.eventos(realm, [("user", uid), ("dateFrom", str(T)), ("dateTo", str(T)), ("max", "1000")])
        b = cli.eventos(realm, [("user", uid), ("dateFrom", str(T + 1)), ("max", "1000")])
        com_t = {e["id"] for e in todos if e["time"] == T}
        res["S2_dateTo"] = com_t <= _ids(a)
        sem_dt = cli.eventos(realm, [("user", uid), ("dateFrom", str(T)), ("max", "1000")])
        res["S1_epoch"] = bool(com_t & _ids(sem_dt)) and not (com_t & _ids(b))
    except RequisicaoInvalida:
        res["S1_epoch"], res["S2_dateTo"] = False, None

    # S3 direction: asc e desc em ordens invertidas
    try:
        asc = cli.eventos(realm, [("user", uid), ("direction", "asc"), ("max", "1000")])
        desc = cli.eventos(realm, [("user", uid), ("direction", "desc"), ("max", "1000")])
        ta, td = [e["time"] for e in asc], [e["time"] for e in desc]
        res["S3_direction"] = ta == sorted(ta) and td == sorted(td, reverse=True) and ta[0] < ta[-1]
    except RequisicaoInvalida:
        res["S3_direction"] = False

    # S4 exact: prefixo do valor conhecido com exact=true deve retornar zero
    valor = (sonda.get("attributes") or {}).get(atributo_cpf, [None])[0]
    if valor:
        p = so_digitos(valor)[:6]
        r = cli.get(f"/admin/realms/{realm}/users", {"q": f"{atributo_cpf}:{p}", "exact": "true", "max": "5"})
        res["S4_exact"] = len(r) == 0
    else:
        res["S4_exact"] = None

    # S6 fuso do formato 'yyyy-MM-dd' e S7 semântica de dateTo, numa grade de eventos a cada 30 min
    res.update(_sonda_fuso(cli, realm, uid, todos))

    if res.get("S1_epoch") and res.get("S3_direction"):
        res["modo"] = "epoch_asc"
    elif res.get("S1_epoch"):
        res["modo"] = "epoch_desc"
    else:
        res["modo"] = "dia"
    res["sem_dateTo"] = res.get("S1_epoch") and res.get("S2_dateTo") is False
    return res


def _sonda_fuso(cli, realm, uid, todos) -> dict:
    """Mede o deslocamento entre a meia-noite UTC e o início do dia aplicado pelo servidor."""
    tempos = sorted(e["time"] for e in todos)
    # procura uma meia-noite UTC com eventos a no máximo 30 min de distância em ±12 h
    for t in tempos:
        meia = datetime.fromtimestamp(t / 1000, timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)
        for dia in (meia, meia + timedelta(days=1)):
            m = int(dia.timestamp() * 1000)
            janela = [x for x in tempos if m - 12 * 3600_000 <= x <= m + 12 * 3600_000]
            if len(janela) < 40:
                continue
            gaps = max(b - a for a, b in zip(janela, janela[1:]))
            if gaps > MEIA_HORA:
                continue
            d = dia.strftime("%Y-%m-%d")
            try:
                inc = cli.eventos(realm, [("user", uid), ("dateFrom", d), ("max", "1000")])
                ate = cli.eventos(realm, [("user", uid), ("dateTo", d), ("max", "1000")])
            except ErroKC:
                return {"S6_fuso": None}
            tinc = [e["time"] for e in inc if m - 12 * 3600_000 <= e["time"] <= m + 12 * 3600_000]
            texc = [x for x in janela if x not in set(tinc)]
            if not tinc:
                return {"S6_fuso": None}
            borda_min = max(texc) if texc else m - 12 * 3600_000   # último excluído
            borda_max = min(tinc)                                     # primeiro incluído
            # início do dia no servidor está em (borda_min, borda_max]; deslocamento = m - início
            desloc_h = round((m - borda_max) / 3600_000 * 2) / 2
            tate = max(e["time"] for e in ate) if ate else None
            # S7: dateTo=d inclui o dia inteiro (fim do dia) ou para na meia-noite (início do dia)?
            s7 = None
            if tate is not None:
                s7 = "fim_do_dia" if tate > borda_max + 6 * 3600_000 else "inicio_do_dia"
            return {"S6_fuso": {"deslocamento_horas": desloc_h, "intervalo_ms": [borda_min, borda_max],
                                "dia_referencia": d}, "S7_dateTo": s7}
    return {"S6_fuso": None, "S7_dateTo": None}


def s5_realm(cli: ClienteKC, realm: str, atributo: str) -> dict:
    """User Profile e federação (somente leitura; guarda só campos não sensíveis)."""
    out: dict = {}
    try:
        up = cli.get(f"/admin/realms/{realm}/users/profile")
        attr = next((a for a in up.get("attributes", []) if a.get("name") == atributo), None)
        out["user_profile"] = "declarado" if attr and "admin" in (attr.get("permissions", {}).get("view", [])) \
            else ("nao_gerenciado_visivel" if up.get("unmanagedAttributePolicy") in ("ADMIN_VIEW", "ADMIN_EDIT",
                                                                                   "ENABLED") else "ausente")
    except NaoEncontrado:
        out["user_profile"] = "sem_user_profile"   # versões antigas: atributos livres
    except ErroKC as e:
        out["user_profile"] = f"erro: {e}"
    try:
        comps = cli.get(f"/admin/realms/{realm}/components",
                        {"type": "org.keycloak.storage.UserStorageProvider"})
        out["federacao"] = [{"providerId": c.get("providerId"),
                             **{k: (c.get("config", {}).get(k) or [None])[0]
                                for k in ("enabled", "importEnabled", "editMode", "fullSyncPeriod",
                                          "changedSyncPeriod")}} for c in comps]
    except ErroKC as e:
        out["federacao"] = f"erro: {e}"
    return out

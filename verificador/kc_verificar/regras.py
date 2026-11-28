"""Regras publicadas (FORMATO_PACOTE.md §9) para `kc-verificar --recalcular`.

Reimplementação independente das regras de consolidação: categorias, filtro do período, KPIs, consolidado por janela,
fora do expediente, rajadas de falhas, IP novo e frações de cobertura. Se o pacote declarar regras diferentes destas
(`resultados.json` → `regras`), o verificador acusa: as regras do pacote não são aceitas como dadas.
"""
from __future__ import annotations

from datetime import datetime, timedelta
from zoneinfo import ZoneInfo

CATEGORIA = {
    "LOGIN": "Acesso", "IDENTITY_PROVIDER_LOGIN": "Acesso", "LOGIN_ERROR": "Acesso",
    "IDENTITY_PROVIDER_LOGIN_ERROR": "Acesso", "LOGOUT": "Acesso", "LOGOUT_ERROR": "Acesso",
    "CODE_TO_TOKEN": "Técnico", "CODE_TO_TOKEN_ERROR": "Técnico", "REFRESH_TOKEN": "Técnico",
    "REFRESH_TOKEN_ERROR": "Técnico", "TOKEN_EXCHANGE": "Técnico", "TOKEN_EXCHANGE_ERROR": "Técnico",
    "UPDATE_PASSWORD": "Conta", "RESET_PASSWORD": "Conta", "UPDATE_TOTP": "Conta", "REMOVE_TOTP": "Conta",
    "UPDATE_PROFILE": "Conta", "UPDATE_EMAIL": "Conta",
}
LOGINS = {"LOGIN", "IDENTITY_PROVIDER_LOGIN"}
FALHAS = {"LOGIN_ERROR", "IDENTITY_PROVIDER_LOGIN_ERROR"}
CATEGORIAS_PADRAO = ["Acesso", "Conta"]
EXPEDIENTE = (7, 19)              # segunda a sexta, horas locais [7, 19)
RAJADA = {"minimo": 5, "janela_ms": 600_000}


def categoria(t: str) -> str:
    return CATEGORIA.get(t, "Outro")


def truncar(ms: int, tz: ZoneInfo, gran: str) -> datetime:
    """Início da janela em hora local, sem fuso (como date_trunc sobre `timestamp AT TIME ZONE fuso`)."""
    d = datetime.fromtimestamp(ms / 1000, tz).replace(tzinfo=None)
    if gran == "hora":
        return d.replace(minute=0, second=0, microsecond=0)
    d = d.replace(hour=0, minute=0, second=0, microsecond=0)
    if gran == "dia":
        return d
    if gran == "semana":
        return d - timedelta(days=d.weekday())
    if gran == "mes":
        return d.replace(day=1)
    raise ValueError(f"granularidade desconhecida: {gran}")


def fora_expediente(ms: int, tz: ZoneInfo) -> bool:
    d = datetime.fromtimestamp(ms / 1000, tz)
    return d.isoweekday() >= 6 or not (EXPEDIENTE[0] <= d.hour < EXPEDIENTE[1])


class Recalculo:
    """Acumula os eventos (já normalizados: t, instancia, realm, conta, tipo, cliente, ip) e calcula os resultados.

    Memória: contadores por janela e por IP, as falhas (para as rajadas) e os horários dos destaques; não os eventos.
    """

    def __init__(self, inicio_ms: int, fim_ms: int, fuso: str, gran: str, base_dias: int,
                 categorias: list[str] | None = None):
        self.ini, self.fim, self.tz, self.gran = inicio_ms, fim_ms, ZoneInfo(fuso), gran
        self.base = bool(base_dias)
        self.cats = set(categorias or CATEGORIAS_PADRAO)
        self.logins = self.falhas_n = self.eventos = 0
        self.apps: set = set()
        self.ips: set = set()
        self.primeiro = self.ultimo = None
        self.janelas: dict = {}
        self.fora: list = []
        self.falhas: dict = {}
        self.base_ips: set = set()
        self.periodo: list = []       # (t, ip) dos eventos do período, para o IP novo (base pode vir depois)

    def adicionar(self, t: int, instancia: str, realm: str, conta, tipo: str, cliente, ip):
        ip = ip or None
        if t < self.ini:
            if ip:
                self.base_ips.add(ip)
            return
        if t >= self.fim or categoria(tipo) not in self.cats:
            return
        self.eventos += 1
        if tipo in LOGINS:
            self.logins += 1
            if cliente is not None:
                self.apps.add(cliente)
            self.primeiro = t if self.primeiro is None else min(self.primeiro, t)
            self.ultimo = t if self.ultimo is None else max(self.ultimo, t)
            if fora_expediente(t, self.tz):
                self.fora.append([t, instancia, realm])
        elif tipo in FALHAS:
            self.falhas_n += 1
            self.falhas.setdefault((instancia, realm, conta), []).append(t)
        if ip and (tipo in LOGINS or tipo in FALHAS):
            self.ips.add(ip)
        k = (truncar(t, self.tz, self.gran).isoformat(), instancia, realm, cliente, tipo)
        j = self.janelas.get(k)
        if j is None:
            j = self.janelas[k] = [0, set()]
        j[0] += 1
        if ip:
            j[1].add(ip)
        if self.base and ip:
            self.periodo.append((t, ip))

    def _rajadas(self) -> list:
        out = []
        for (inst, realm, conta), ts in self.falhas.items():
            ts.sort()
            i, atual = 0, None
            for j in range(len(ts)):
                while ts[j] - ts[i] > RAJADA["janela_ms"]:
                    i += 1
                if j - i + 1 >= RAJADA["minimo"]:
                    if atual and ts[i] <= atual[4]:
                        atual[4] = ts[j]
                        atual[5] = j - atual[6] + 1
                    else:
                        atual = [inst, realm, conta, ts[i], ts[j], j - i + 1, i]
                        out.append(atual)
        return sorted(r[:6] for r in out)

    def resultados(self) -> dict:
        ip_novo = None
        if self.base:
            vistos, ip_novo = set(), []
            for t, ip in sorted(self.periodo, key=lambda x: x[0]):
                if ip not in self.base_ips and ip not in vistos:
                    vistos.add(ip)
                    ip_novo.append(t)
            ip_novo.sort()
        janelas = sorted(([k[0], k[1], k[2], k[3], k[4], v[0], len(v[1])] for k, v in self.janelas.items()),
                         key=lambda x: (x[0], x[1], x[2], x[3] or "", x[4]))
        return {"kpis": {"logins": self.logins, "falhas": self.falhas_n, "aplicacoes": len(self.apps),
                         "ips": len(self.ips), "eventos": self.eventos, "primeiro_ms": self.primeiro,
                         "ultimo_ms": self.ultimo},
                "janelas": janelas,
                "destaques": {"fora_expediente": sorted(self.fora), "rajadas": self._rajadas(), "ip_novo": ip_novo}}


def fracoes(inicio_ms: int, fim_ms: int, cob: list[dict]) -> dict:
    """Realms: pares cobertos ÷ pesquisados. Tempo: dias com dados em todas as contas com eventos, menos os dias
    marcados como divergentes ou expirados no detalhe."""
    total = len(cob)
    cobertos = sum(1 for c in cob if c["classe"] == "coberto")
    dias_periodo = max(1, round((fim_ms - inicio_ms) / 86400_000))
    com_conta = [c for c in cob if c.get("conta_id") is not None and c["classe"] != "sem_dados"]
    if com_conta:
        desde = max((c.get("desde_ms") or inicio_ms) for c in com_conta)
        dias_ok = max(0, round((fim_ms - max(desde, inicio_ms)) / 86400_000))
        perdidos = set()
        for c in com_conta:
            for parte in (c.get("detalhe") or "").split("; "):
                if ":" in parte and ("divergente" in parte or "expirado" in parte):
                    perdidos |= {d.strip() for d in parte.split(":", 1)[1].split(",")}
        dias_ok = max(0, dias_ok - len(perdidos))
    else:
        dias_ok = dias_periodo if total and cobertos == total else 0
    return {"realms": [cobertos, total], "tempo": [min(dias_ok, dias_periodo), dias_periodo],
            "completa": cobertos == total and dias_ok >= dias_periodo}

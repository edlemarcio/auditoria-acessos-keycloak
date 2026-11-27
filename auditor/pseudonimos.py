"""Rótulos dos pseudônimos e a visão mascarada ou sem máscara dos dados (W0b, PROPOSTA_WEB §5.2 e §5.4).

Numeração determinística e imutável: no fechamento, cada item ganha o próximo número da sua classe, por ordem do
primeiro `time_ms` em que aparece (empate pelo HMAC). Item novo recebe o próximo número; nada é renumerado.
"""
from __future__ import annotations

from .sigilo import Cofre, abrir_extra

CHAVE_PSEUDO = 0x6B70   # advisory lock da numeração por investigação
NOMES = {"conta": "Conta", "ip": "IP", "sessao": "Sessão"}


def atribuir(cx, cf: Cofre) -> int:
    """Atribui rótulos aos pseudônimos ainda sem número. Idempotente; devolve quantos foram criados."""
    inv = cf.inv
    with cx.transaction():
        cx.execute("SELECT pg_advisory_xact_lock(%s, %s)", (CHAVE_PSEUDO, inv))
        itens: dict[str, dict[str, int | None]] = {c: {} for c in NOMES}
        for classe, col in (("conta", "ps_conta"), ("ip", "ps_ip"), ("sessao", "ps_sessao")):
            for r in cx.execute(f"SELECT {col} AS h, min(time_ms) AS p FROM evento WHERE investigacao_id=%s "
                                f"AND {col} IS NOT NULL GROUP BY 1", (inv,)):
                itens[classe][r["h"]] = r["p"]
        for r in cx.execute("SELECT ps_conta AS h FROM conta WHERE investigacao_id=%s AND ps_conta IS NOT NULL",
                            (inv,)):
            itens["conta"].setdefault(r["h"], None)
        # IPs que só aparecem nas sessões ativas fotografadas no fechamento
        for x in cx.execute("SELECT * FROM conta_extra WHERE investigacao_id=%s AND tipo='sessao'", (inv,)):
            d = abrir_extra(cf, x)["dados"] or {}
            h = cf.ps("ip", d.get("ipAddress"))
            if h:
                vals = [v for v in (itens["ip"].get(h), d.get("start")) if v is not None]
                itens["ip"][h] = min(vals) if vals else None
        novos = 0
        for classe, hs in itens.items():
            ja = {r["hmac"] for r in cx.execute("SELECT hmac FROM pseudonimo WHERE investigacao_id=%s AND classe=%s",
                                                (inv, classe))}
            prox = cx.execute("SELECT coalesce(max(rotulo), 0) AS m FROM pseudonimo WHERE investigacao_id=%s AND "
                              "classe=%s", (inv, classe)).fetchone()["m"]
            for h, p in sorted(((h, p) for h, p in hs.items() if h not in ja),
                               key=lambda x: (x[1] is None, x[1] or 0, x[0])):
                prox += 1
                novos += 1
                cx.execute("INSERT INTO pseudonimo (investigacao_id, classe, hmac, rotulo, primeiro_ms) "
                           "VALUES (%s,%s,%s,%s,%s)", (inv, classe, h, prox, p))
    return novos


def rotulos(cx, inv_id: int) -> dict[tuple[str, str], str]:
    return {(r["classe"], r["hmac"]): f"{NOMES[r['classe']]} {r['rotulo']}" for r in cx.execute(
        "SELECT classe, hmac, rotulo FROM pseudonimo WHERE investigacao_id=%s", (inv_id,))}


class Visao:
    """O que aparece na planilha, no dashboard e no pacote. Mascarada: pseudônimos no lugar de conta, IP e sessão,
    identificador do alvo mascarado nos textos e valores pessoais conhecidos trocados pelo pseudônimo."""

    def __init__(self, sem_mascara: bool, msk_alvo, rot: dict, cf: Cofre):
        self.sem_mascara, self.msk_alvo, self.rot, self.cf = sem_mascara, msk_alvo, rot, cf
        self._troca: dict[str, str] = {}

    def conhecer(self, contas: list[dict], eventos: list[dict]):
        """Valores pessoais conhecidos (para trocar dentro de textos livres pelo pseudônimo correspondente)."""
        for c in contas:
            r = self.rot.get(("conta", c.get("ps_conta")))
            if r:
                for v in (c.get("user_id"), c.get("username"), c.get("email")):
                    if v and len(v) >= 3:
                        self._troca[v] = r
        for e in eventos:
            for classe, ps, v in (("ip", e.get("ps_ip"), e.get("ip")), ("sessao", e.get("ps_sessao"),
                                                                       e.get("session_id"))):
                r = self.rot.get((classe, ps))
                if r and v:
                    self._troca[v] = r

    def _rotulo(self, classe, ps, valor, vazio="—"):
        if not valor and not ps:
            return vazio
        return self.rot.get((classe, ps)) or f"{NOMES[classe]} (numeração no fechamento)"

    def conta(self, c: dict) -> str:
        if self.sem_mascara:
            return c.get("username") or c.get("user_id") or "—"
        if c.get("via") == "varredura":
            return "Tentativas com o identificador"
        if c.get("via") == "realm":
            return "(realm inteiro)"
        return self._rotulo("conta", c.get("ps_conta"), c.get("user_id"))

    def user_id(self, c: dict) -> str | None:
        return c.get("user_id") if self.sem_mascara else (self.conta(c) if c.get("user_id") else None)

    def ip(self, ps, valor) -> str:
        return (valor or "—") if self.sem_mascara else self._rotulo("ip", ps, valor)

    def ip_valor(self, valor) -> str:
        return self.ip(self.cf.ps("ip", valor), valor)

    def sessao(self, ps, valor) -> str:
        return (valor or "—") if self.sem_mascara else self._rotulo("sessao", ps, valor)

    def texto(self, s):
        if s is None or self.sem_mascara:
            return s
        s = str(s)
        for v in sorted(self._troca, key=len, reverse=True):
            if v in s:
                s = s.replace(v, self._troca[v])
        return self.msk_alvo(s)

    def json(self, obj):
        """Estruturas (eventos administrativos, sessões): textos tratados; `representation` (a conta inteira
        serializada) sai do mascarado."""
        if self.sem_mascara:
            return obj
        if isinstance(obj, dict):
            return {k: ("[redigido]" if k == "representation" else
                        self.ip_valor(v) if k == "ipAddress" and isinstance(v, str) else self.json(v))
                    for k, v in obj.items()}
        if isinstance(obj, list):
            return [self.json(v) for v in obj]
        return self.texto(obj) if isinstance(obj, str) else obj

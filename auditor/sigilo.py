"""Cifra das colunas pessoais com a DEK da investigação e pseudônimos (W0b, PROPOSTA_WEB §5.1, §5.3 e §5.4).

`Cofre` concentra o uso da DEK: cifrar e decifrar uma célula (AAD = investigação | tabela | coluna | linha | classe)
e calcular pseudônimos (HMAC-SHA-256 completo com K_pseudo, derivada da DEK por classe). As linhas de banco
"abertas" ganham de volta os campos em claro só em memória.
"""
from __future__ import annotations

import hashlib
import hmac
import json

from . import chaves, cripto


class Cofre:
    def __init__(self, inv_id: int, finalidade: str, classe: str = "principal"):
        self.inv, self.finalidade, self.classe = inv_id, finalidade, classe
        self.dek = chaves.dek(inv_id, finalidade, classe)
        self._kps: dict[str, bytes] = {}

    # ---- pseudônimos
    def ps(self, classe: str, valor) -> str | None:
        if valor is None or valor == "":
            return None
        k = self._kps.get(classe)
        if k is None:
            k = self._kps[classe] = cripto.chave_pseudo(self.dek, self.inv, classe)
        return hmac.new(k, str(valor).encode(), hashlib.sha256).hexdigest()

    # ---- células
    def _aad(self, tabela, coluna, linha) -> bytes:
        return cripto.aad(self.inv, tabela, coluna, linha, self.classe)

    def cifrar(self, tabela: str, coluna: str, linha, obj) -> bytes:
        return cripto.cifrar_dek(self.dek, json.dumps(obj, ensure_ascii=False, separators=(",", ":")),
                                 self._aad(tabela, coluna, linha))

    def decifrar(self, tabela: str, coluna: str, linha, blob):
        return json.loads(cripto.decifrar_dek(self.dek, bytes(blob), self._aad(tabela, coluna, linha)))

    def cifrar_bytes(self, tabela: str, coluna: str, linha, dados: bytes) -> bytes:
        return cripto.cifrar_dek(self.dek, dados, self._aad(tabela, coluna, linha))

    def decifrar_bytes(self, tabela: str, coluna: str, linha, blob) -> bytes:
        return cripto.decifrar_dek(self.dek, bytes(blob), self._aad(tabela, coluna, linha))


# ------------------------------------------------------------------ eventos
def id_gravado(cf: Cofre, id_evento: str) -> str:
    """O id sintético do Keycloak <= 21 é o hash do evento inteiro: confirmaria um palpite. Vira HMAC (§5.1)."""
    return "h:" + cf.ps("evento", id_evento) if id_evento.startswith("sha256:") else id_evento


def linha_evento(r: dict) -> str:
    return f"{r['instancia_id']}|{r['realm']}|{r['id']}"


def cifrar_evento(cf: Cofre, inst_id: int, realm: str, idg: str, bruto: dict, **extra) -> bytes:
    return cf.cifrar("evento", "cifrado", f"{inst_id}|{realm}|{idg}", {"bruto": bruto, **extra})


def abrir_evento(cf: Cofre, r: dict) -> dict:
    """Devolve a linha com user_id, session_id, ip, details e bruto em claro (em memória)."""
    if r.get("cifrado") is None:
        return r
    d = cf.decifrar("evento", "cifrado", linha_evento(r), r["cifrado"])
    b = d["bruto"]
    return {**r, "user_id": b.get("userId"), "session_id": b.get("sessionId"), "ip": b.get("ipAddress"),
            "details": b.get("details"), "bruto": b, "sal": d.get("sal")}


# ------------------------------------------------------------------ contas
def inserir_conta(cx, cf: Cofre, instancia_id: int, realm: str, user_id: str | None, username: str | None,
                  email: str | None = None, criado_ms=None, habilitada=None, origem=None, via: str = "atributo") -> int:
    cid = cx.execute("SELECT nextval('conta_id_seq') AS n").fetchone()["n"]
    r = cx.execute("INSERT INTO conta (id, investigacao_id, instancia_id, realm, ps_conta, cifrado, criado_ms, "
                   "habilitada, origem, via) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s) ON CONFLICT DO NOTHING "
                   "RETURNING id",
                   (cid, cf.inv, instancia_id, realm, cf.ps("conta", user_id),
                    cf.cifrar("conta", "cifrado", cid, {"user_id": user_id, "username": username, "email": email}),
                    criado_ms, habilitada, origem, via)).fetchone()
    return r["id"] if r else 0


def abrir_conta(cf: Cofre, c: dict) -> dict:
    if c.get("cifrado") is None:
        return c
    return {**c, **cf.decifrar("conta", "cifrado", c["id"], c["cifrado"])}


def contas(cx, cf: Cofre, onde: str = "", args: tuple = ()) -> list[dict]:
    return [abrir_conta(cf, c) for c in cx.execute(
        "SELECT c.*, i.nome AS instancia FROM conta c JOIN instancia i ON i.id=c.instancia_id "
        f"WHERE c.investigacao_id=%s {onde} ORDER BY i.nome, c.realm, c.id", (cf.inv, *args)).fetchall()]


# ------------------------------------------------------------------ outros
def justificativa(cf: Cofre, inv: dict) -> str:
    if inv.get("justificativa_cifrada") is None:
        return inv["justificativa"]
    return cf.decifrar("investigacao", "justificativa", inv["id"], inv["justificativa_cifrada"])


def abrir_extra(cf: Cofre, x: dict) -> dict:
    if x.get("cifrado") is None:
        return x
    return {**x, "dados": cf.decifrar("conta_extra", "dados", x["id"], x["cifrado"])}

"""Cliente da Admin REST API: token, orçamento de carga, novas tentativas e registro de evidência."""
from __future__ import annotations

import hashlib
import json
import random
import threading
import time
from datetime import datetime, timezone

import httpx
from psycopg.types.json import Jsonb

from . import __version__
from . import chaves
from .db import conectar


class ErroKC(Exception):
    status: int | None = None


class SemPermissao(ErroKC):
    status = 403


class NaoEncontrado(ErroKC):
    status = 404


class RequisicaoInvalida(ErroKC):
    status = 400


class FalhaTemporaria(ErroKC):
    pass


class Orcamento:
    """Limite por instância, compartilhado entre **todos os processos** que usam o mesmo banco do auditor
    (workers, API, CLI): requisições simultâneas e requisições por segundo.

    * Taxa: `orcamento_instancia.proximo` guarda o horário da próxima vaga. Quem vai enviar trava a linha, dorme até
      o horário (sem consultar em laço) e grava a vaga seguinte a partir do horário real de envio.
    * Concorrência: N advisory locks de sessão por instância; cada thread usa uma conexão dedicada, fora de
      qualquer pool, e o lock é liberado ao fim da requisição ou com a queda da conexão.
    """

    CHAVE = 0x6B63   # namespace dos advisory locks ("kc")

    def __init__(self, instancia_id: int, concorrencia: int, req_por_s: float):
        self.inst_id = instancia_id
        self.concorrencia = concorrencia
        # 3% de folga: cobre a variação entre a liberação da vaga e o envio de fato, em processos diferentes
        self.intervalo = 1.03 / req_por_s
        self._local = threading.local()
        with conectar() as cx:
            cx.execute("INSERT INTO orcamento_instancia (instancia_id) VALUES (%s) ON CONFLICT DO NOTHING",
                       (instancia_id,))

    def _cx(self):
        cx = getattr(self._local, "cx", None)
        if cx is None or cx.closed:
            cx = self._local.cx = conectar()
        return cx

    def __enter__(self):
        cx = self._cx()
        while True:   # vaga de concorrência
            for slot in range(self.concorrencia):
                if cx.execute("SELECT pg_try_advisory_lock(%s, %s) AS ok",
                              (self.CHAVE, self.inst_id * 1024 + slot)).fetchone()["ok"]:
                    self._local.slot = slot
                    break
            else:
                time.sleep(0.05)
                continue
            break
        # o lock da linha fica com quem vai enviar até o horário de envio; a vaga seguinte é calculada a partir do
        # horário real (e não do reservado), para que um processo que acordou atrasado não encurte o intervalo
        with cx.transaction():
            espera = cx.execute("SELECT extract(epoch FROM proximo - clock_timestamp())::float AS espera "
                                "FROM orcamento_instancia WHERE instancia_id=%s FOR UPDATE",
                                (self.inst_id,)).fetchone()["espera"]
            if espera > 0:
                time.sleep(espera)
            cx.execute("UPDATE orcamento_instancia SET proximo = clock_timestamp() + make_interval(secs => %s) "
                       "WHERE instancia_id=%s", (self.intervalo, self.inst_id))
        return self

    def __exit__(self, *exc):
        self._cx().execute("SELECT pg_advisory_unlock(%s, %s)", (self.CHAVE, self.inst_id * 1024 + self._local.slot))


_ORCAMENTOS: dict[int, Orcamento] = {}
_ORC_LOCK = threading.Lock()


class ClienteKC:
    TENTATIVAS = 6

    def __init__(self, instancia: dict, investigacao_id: int | None = None, registrar: bool = True,
                 finalidade: str | None = None):
        self.inst = instancia
        self.investigacao_id = investigacao_id
        self.registrar = registrar
        self.segredo = chaves.segredo(instancia, finalidade or ("coleta" if investigacao_id else "sondas"))
        verify = instancia.get("ca_path") or True
        self.http = httpx.Client(base_url=instancia["url"].rstrip("/"), timeout=30.0, verify=verify,
                                 trust_env=False)
        self._token = None
        self._expira = 0.0
        self._tlock = threading.Lock()
        with _ORC_LOCK:
            if instancia["id"] not in _ORCAMENTOS:
                _ORCAMENTOS[instancia["id"]] = Orcamento(instancia["id"], instancia["concorrencia"],
                                                         instancia["req_por_s"])
            self.orc = _ORCAMENTOS[instancia["id"]]
        self._log_cx = conectar() if registrar else None
        self._log_lock = threading.Lock()
        self.relogio_diferenca_s: float | None = None

    # ------------------------------------------------------------ token
    def _renovar(self):
        r = self.http.post(f"/realms/{self.inst['realm_auth']}/protocol/openid-connect/token",
                           data={"grant_type": "client_credentials", "client_id": self.inst["client_id"],
                                 "client_secret": self.segredo})
        if r.status_code != 200:
            raise ErroKC(f"falha ao obter token: HTTP {r.status_code}")
        d = r.json()
        self._token = d["access_token"]
        # renova a 70% da validade informada pelo servidor
        self._expira = time.monotonic() + 0.7 * float(d.get("expires_in", 60))

    def token(self, forcar: bool = False) -> str:
        with self._tlock:
            if forcar or not self._token or time.monotonic() >= self._expira:
                self._renovar()
            return self._token

    # ------------------------------------------------------------ requisição
    def get(self, caminho: str, params: list[tuple[str, str]] | dict | None = None):
        tentativa, renovou = 0, False
        while True:
            tentativa += 1
            status, corpo, erro = None, b"", None
            ini, t0 = datetime.now(timezone.utc), time.monotonic()
            try:
                with self.orc:
                    # horário registrado = envio de fato (depois da espera do orçamento)
                    ini, t0 = datetime.now(timezone.utc), time.monotonic()
                    r = self.http.get(caminho, params=params, headers={"Authorization": f"Bearer {self.token()}"})
                status, corpo = r.status_code, r.content
                if self.relogio_diferenca_s is None and "date" in r.headers:
                    from email.utils import parsedate_to_datetime
                    self.relogio_diferenca_s = (parsedate_to_datetime(r.headers["date"]) - ini).total_seconds()
            except (httpx.TimeoutException, httpx.TransportError) as e:
                erro = e
            ms = (time.monotonic() - t0) * 1000
            self._registrar(caminho, params, status, ini, ms, corpo)

            if status == 200:
                return json.loads(corpo)
            if status == 401 and not renovou:
                renovou = True
                self.token(forcar=True)
                continue
            if status == 403:
                raise SemPermissao(caminho)
            if status == 404:
                raise NaoEncontrado(caminho)
            if status == 400:
                raise RequisicaoInvalida(corpo.decode(errors="replace")[:300])
            if tentativa >= self.TENTATIVAS:
                raise FalhaTemporaria(f"{caminho}: {status or erro}")
            # 429, 5xx, timeout: espera exponencial com variação aleatória
            time.sleep(min(30.0, 0.5 * 2 ** (tentativa - 1)) * random.uniform(0.5, 1.5))

    def _registrar(self, caminho, params, status, ini, ms, corpo):
        if not self.registrar:
            return
        p = params if isinstance(params, dict) else (
            {k: [v for kk, v in params if kk == k] if sum(1 for kk, _ in params if kk == k) > 1 else v
             for k, v in params} if params else None)
        with self._log_lock:
            self._log_cx.execute(
                "INSERT INTO requisicao (investigacao_id, instancia_id, metodo, caminho, params, status, inicio, ms,"
                " sha256, bytes, coletor) VALUES (%s,%s,'GET',%s,%s,%s,%s,%s,%s,%s,%s)",
                (self.investigacao_id, self.inst["id"], caminho, Jsonb(p) if p else None, status, ini, ms,
                 hashlib.sha256(corpo).hexdigest() if corpo else None, len(corpo), __version__))

    def fechar(self):
        self.http.close()
        if self._log_cx:
            self._log_cx.close()

    # ------------------------------------------------------------ atalhos
    def realms(self):
        return self.get("/admin/realms", {"briefRepresentation": "true"})

    def eventos(self, realm: str, params: list[tuple[str, str]]):
        evs = self.get(f"/admin/realms/{realm}/events", params)
        # Keycloak <= 21 / RH-SSO 7.x não expõe o id do evento: id sintético pelo conteúdo + nº da ocorrência
        # na resposta (eventos idênticos no mesmo ms são distintos; o modo dia lê o dia numa página só)
        vistos: dict[str, int] = {}
        for e in evs:
            if "id" not in e:
                h = hashlib.sha256(json.dumps(e, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
                vistos[h] = vistos.get(h, 0) + 1
                e["id"] = f"sha256:{h}:{vistos[h]}"
        return evs

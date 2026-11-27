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
from .cripto import decifrar
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
    """Limite compartilhado por instância: requisições simultâneas e requisições por segundo."""

    def __init__(self, concorrencia: int, req_por_s: float):
        self.sem = threading.BoundedSemaphore(concorrencia)
        # 1% de folga: a resolução do relógio não deixa 6 envios caberem em 1 s com orçamento de 5
        self.intervalo = 1.01 / req_por_s
        self.proximo = time.monotonic()
        self.lock = threading.Lock()

    def __enter__(self):
        self.sem.acquire()
        with self.lock:
            agora = time.monotonic()
            espera = self.proximo - agora
            self.proximo = max(agora, self.proximo) + self.intervalo
        if espera > 0:
            time.sleep(espera)
        return self

    def __exit__(self, *exc):
        self.sem.release()


_ORCAMENTOS: dict[int, Orcamento] = {}
_ORC_LOCK = threading.Lock()


class ClienteKC:
    TENTATIVAS = 6

    def __init__(self, instancia: dict, investigacao_id: int | None = None, registrar: bool = True):
        self.inst = instancia
        self.investigacao_id = investigacao_id
        self.registrar = registrar
        self.segredo = decifrar(instancia["segredo_cifrado"])
        verify = instancia.get("ca_path") or True
        self.http = httpx.Client(base_url=instancia["url"].rstrip("/"), timeout=30.0, verify=verify,
                                 trust_env=False)
        self._token = None
        self._expira = 0.0
        self._tlock = threading.Lock()
        with _ORC_LOCK:
            self.orc = _ORCAMENTOS.setdefault(instancia["id"], Orcamento(instancia["concorrencia"],
                                                                         instancia["req_por_s"]))
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
        return self.get(f"/admin/realms/{realm}/events", params)

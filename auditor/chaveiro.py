"""`chaveiro`: porteiro das chaves (W0b, PROPOSTA_WEB §5.3). Único serviço com `transit/decrypt` da KEK.

Cada serviço pede a DEK por mTLS dizendo a investigação e a finalidade. O chaveiro lê no banco o estado da
investigação (papel kc_chaveiro: só estado, jobs e DEKs envolvidas), aplica a regra da identidade do certificado e
só então desembrulha a DEK no Vault. Cada entrega e cada recusa vão para a trilha e para o SIEM; volume fora do padrão
gera alerta. Não guarda DEK desembrulhada.

  CHAVEIRO_DSN=postgresql://kc_chaveiro:...@localhost:5435/auditor \\
  CHAVEIRO_VAULT_TOKEN_FILE=chaves/vault/chaveiro.token python -m auditor chaveiro [--porta 8443]

Identidades (CN do certificado, emitido pelo Vault PKI):
  worker    coleta (investigação em 'coletando'), preparar e fechar (job do tipo em execução)
  pacotes   exportar (investigação concluída ou parcial)
  operador  criar as DEKs de uma investigação em abertura; HMAC do alvo; segredos (cadastro e sondas)
  api       recusado até a W1, que exige o token OIDC do usuário designado
"""
from __future__ import annotations

import base64
import json
import os
import ssl
import threading
import time
from collections import deque
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import httpx
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb
from psycopg_pool import ConnectionPool

from . import siem

DOMINIO = ".kc-auditor.local"
KEK = "kc-auditor-kek"
EXPORTAVEIS = ("concluida", "concluida_com_lacunas", "parcial")
LIMITE_POR_MINUTO = int(os.environ.get("CHAVEIRO_LIMITE_POR_MINUTO", "120"))


class Negado(Exception):
    def __init__(self, codigo: str, texto: str):
        super().__init__(texto)
        self.codigo = codigo


def _b64(b: bytes) -> str:
    return base64.b64encode(b).decode()


class Chaveiro:
    def __init__(self, dsn: str, vault: str, token: str):
        self.pool = ConnectionPool(dsn, min_size=1, max_size=8, kwargs={"autocommit": True, "row_factory": dict_row},
                                   open=True)
        self.vault = httpx.Client(base_url=vault, headers={"X-Vault-Token": token}, timeout=10, trust_env=False)
        self._volume: dict[str, deque] = {}
        self._vlock = threading.Lock()

    # ---------------------------------------------------------------- Vault
    def _v(self, caminho: str, **corpo) -> dict:
        r = self.vault.post(f"/v1/{caminho}", json=corpo)
        if r.status_code != 200:
            raise RuntimeError(f"Vault {caminho}: HTTP {r.status_code}")
        return r.json()["data"]

    @staticmethod
    def _ctx(inv_id: int, classe: str) -> str:
        return _b64(f"kc-auditor/kek|{inv_id}|{classe}".encode())

    # ---------------------------------------------------------------- registro
    def _registrar(self, cn: str, acao: str, inv_id: int | None, ok: bool, **det):
        with self.pool.connection() as cx:
            cx.execute("INSERT INTO trilha_auditoria (operador, acao, investigacao_id, detalhe) VALUES (%s,%s,%s,%s)",
                       (f"chaveiro:{cn}", acao, inv_id, Jsonb(det)))
        siem.enviar(acao, "info" if ok else "alerta", servico=cn, investigacao=inv_id,
                    finalidade=det.get("finalidade"), classe=det.get("classe"), motivo_codigo=det.get("motivo"))
        if ok:
            self._medir(cn)

    def _medir(self, cn: str):
        agora = time.monotonic()
        with self._vlock:
            q = self._volume.setdefault(cn, deque())
            q.append(agora)
            while q and q[0] < agora - 60:
                q.popleft()
            n = len(q)
        if n == LIMITE_POR_MINUTO + 1:
            siem.enviar("volume_anormal_de_chaves", "alerta", servico=cn, quantidade=n, janela_s=60)

    # ---------------------------------------------------------------- regras
    def _estado(self, cx, inv_id: int) -> str:
        r = cx.execute("SELECT status FROM investigacao WHERE id=%s", (inv_id,)).fetchone()
        if not r:
            raise Negado("inexistente", f"investigação {inv_id} inexistente")
        return r["status"]

    def _autorizar(self, cx, cn: str, inv_id: int, finalidade: str):
        st = self._estado(cx, inv_id)

        def job_ativo(tipo):
            return cx.execute("SELECT 1 FROM job WHERE investigacao_id=%s AND tipo=%s AND status='executando'",
                              (inv_id, tipo)).fetchone() is not None
        regras = {
            ("worker", "coleta"): (lambda: st == "coletando", "fora_de_coleta"),
            ("worker", "preparar"): (lambda: job_ativo("preparar"), "sem_job_preparar"),
            ("worker", "fechar"): (lambda: job_ativo("fechar"), "sem_job_fechar"),
            ("pacotes", "exportar"): (lambda: st in EXPORTAVEIS, "nao_exportavel"),
        }
        if cn == "api":
            raise Negado("exige_oidc", "a API recebe DEKs só com o token OIDC do usuário designado (W1)")
        regra = regras.get((cn, finalidade))
        if not regra:
            raise Negado("finalidade_nao_permitida", f"'{cn}' não recebe DEK para '{finalidade}'")
        if not regra[0]():
            raise Negado(regra[1], f"'{finalidade}' recusada: investigação {inv_id} está '{st}'")

    # ---------------------------------------------------------------- operações
    def criar(self, cn: str, inv_id: int) -> dict:
        if cn not in ("operador", "api"):
            raise Negado("finalidade_nao_permitida", f"'{cn}' não cria investigações")
        with self.pool.connection() as cx:
            if self._estado(cx, inv_id) != "abrindo":
                raise Negado("fora_de_abertura", f"investigação {inv_id} não está em abertura")
            with cx.transaction():
                # a chave primária barra a criação dupla concorrente
                if cx.execute("SELECT 1 FROM chave_investigacao WHERE investigacao_id=%s", (inv_id,)).fetchone():
                    raise Negado("ja_tem_chave", f"investigação {inv_id} já tem DEK")
                principal = None
                for classe in ("principal", "terceiros"):
                    d = self._v(f"transit/datakey/plaintext/{KEK}", context=self._ctx(inv_id, classe), bits=256)
                    cx.execute("INSERT INTO chave_investigacao (investigacao_id, classe, envelope, key_id, versao) "
                               "VALUES (%s,%s,%s,%s,%s)", (inv_id, classe, d["ciphertext"].encode(), KEK,
                                                           int(d["ciphertext"].split(":")[1][1:])))
                    if classe == "principal":
                        principal = d["plaintext"]
        self._registrar(cn, "criar_dek", inv_id, True, finalidade="abrir", classe="principal")
        return {"dek": principal}

    def entregar(self, cn: str, inv_id: int, finalidade: str, classe: str) -> dict:
        with self.pool.connection() as cx:
            self._autorizar(cx, cn, inv_id, finalidade)
            r = cx.execute("SELECT envelope FROM chave_investigacao WHERE investigacao_id=%s AND classe=%s AND "
                           "destruida_em IS NULL", (inv_id, classe)).fetchone()
        if not r:
            raise Negado("sem_chave", f"investigação {inv_id} sem DEK '{classe}'")
        env = bytes(r["envelope"]).decode()
        if not env.startswith("vault:"):
            raise Negado("chave_local", f"DEK da investigação {inv_id} envolvida no modo local")
        d = self._v(f"transit/decrypt/{KEK}", ciphertext=env, context=self._ctx(inv_id, classe))
        self._registrar(cn, "entregar_dek", inv_id, True, finalidade=finalidade, classe=classe)
        return {"dek": d["plaintext"]}

    def hmac_alvo(self, cn: str, tipo: str, digitos: str) -> dict:
        if cn not in ("operador", "api"):
            raise Negado("finalidade_nao_permitida", f"'{cn}' não calcula HMAC do alvo")
        d = self._v("transit/hmac/kc-auditor-alvo/sha2-256", input=_b64(f"{tipo}:{digitos}".encode()))
        siem.enviar("hmac_alvo", servico=cn)
        return {"hmac": d["hmac"]}

    def cifrar_segredo(self, cn: str, instancia: str, segredo: str) -> dict:
        if cn != "operador":
            raise Negado("finalidade_nao_permitida", f"'{cn}' não cadastra instâncias")
        d = self._v("transit/encrypt/kc-auditor-segredos", plaintext=_b64(segredo.encode()),
                    context=_b64(f"instancia|{instancia}".encode()))
        siem.enviar("cifrar_segredo", servico=cn, instancia=instancia)
        return {"cifrado": d["ciphertext"]}

    def segredo(self, cn: str, instancia_id: int, finalidade: str) -> dict:
        if cn not in ("worker", "operador"):
            raise Negado("finalidade_nao_permitida", f"'{cn}' não fala com os Keycloaks auditados")
        with self.pool.connection() as cx:
            i = cx.execute("SELECT nome, segredo_cifrado FROM instancia WHERE id=%s", (instancia_id,)).fetchone()
        if not i:
            raise Negado("inexistente", f"instância {instancia_id} inexistente")
        d = self._v("transit/decrypt/kc-auditor-segredos", ciphertext=bytes(i["segredo_cifrado"]).decode(),
                    context=_b64(f"instancia|{i['nome']}".encode()))
        siem.enviar("entregar_segredo", servico=cn, instancia=i["nome"], finalidade=finalidade)
        return {"segredo": base64.b64decode(d["plaintext"]).decode()}


def _cn(sock) -> str | None:
    cert = sock.getpeercert()
    for rdn in (cert or {}).get("subject", ()):
        for k, v in rdn:
            if k == "commonName" and v.endswith(DOMINIO):
                return v[: -len(DOMINIO)]
    return None


def servir(porta: int = 8443, certs: Path = Path("chaves/servicos")):
    token_arq = os.environ.get("CHAVEIRO_VAULT_TOKEN_FILE", "chaves/vault/chaveiro.token")
    ch = Chaveiro(os.environ["CHAVEIRO_DSN"], os.environ.get("VAULT_ADDR", "http://127.0.0.1:8200"),
                  Path(token_arq).read_text().strip())

    class H(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def setup(self):
            self.request.settimeout(15)
            self.request.do_handshake()      # sem certificado válido da AC dos serviços, falha aqui
            super().setup()

        def log_message(self, *a):   # nada de corpo nem DEK em log
            pass

        def _responder(self, codigo: int, corpo: dict):
            b = json.dumps(corpo).encode()
            self.send_response(codigo)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(b)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(b)

        def do_GET(self):
            self._responder(200 if self.path == "/v1/saude" else 404, {"ok": self.path == "/v1/saude"})

        def do_POST(self):
            cn = _cn(self.connection)
            if not cn:
                return self._responder(403, {"motivo": "certificado sem identidade de serviço"})
            try:
                c = json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0))) or b"{}")
                rotas = {
                    "/v1/dek/criar": lambda: ch.criar(cn, int(c["investigacao"])),
                    "/v1/dek": lambda: ch.entregar(cn, int(c["investigacao"]), c["finalidade"],
                                                   c.get("classe", "principal")),
                    "/v1/hmac/alvo": lambda: ch.hmac_alvo(cn, c["tipo"], c["digitos"]),
                    "/v1/segredo/cifrar": lambda: ch.cifrar_segredo(cn, c["instancia"], c["segredo"]),
                    "/v1/segredo": lambda: ch.segredo(cn, int(c["instancia_id"]), c.get("finalidade", "")),
                }
                if self.path not in rotas:
                    return self._responder(404, {"motivo": "rota inexistente"})
                self._responder(200, rotas[self.path]())
            except Negado as e:
                inv = c.get("investigacao") if isinstance(c, dict) else None
                ch._registrar(cn, "recusar_dek" if "dek" in self.path else "recusar_chave", inv, False,
                              finalidade=c.get("finalidade"), classe=c.get("classe"), motivo=e.codigo)
                self._responder(403, {"motivo": str(e), "codigo": e.codigo})
            except (KeyError, ValueError) as e:
                self._responder(400, {"motivo": f"pedido inválido: {type(e).__name__}"})
            except Exception as e:  # noqa: BLE001
                siem.enviar("erro_chaveiro", "alerta", servico=cn)
                self._responder(500, {"motivo": type(e).__name__})

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.load_cert_chain(certs / "chaveiro.crt", certs / "chaveiro.key")
    ctx.load_verify_locations(certs / "ca.crt")
    ctx.verify_mode = ssl.CERT_REQUIRED

    class Servidor(ThreadingHTTPServer):
        daemon_threads = True

        def get_request(self):
            # o aperto de mão TLS é feito na thread da conexão (Handler.setup), não no laço que aceita conexões
            sock, end = self.socket.accept()
            return ctx.wrap_socket(sock, server_side=True, do_handshake_on_connect=False), end

        def handle_error(self, request, client_address):
            siem.enviar("conexao_recusada_tls", "alerta", servico="desconhecido")

    srv = Servidor(("127.0.0.1", porta), H)
    print(f"chaveiro em https://127.0.0.1:{porta} (mTLS)", flush=True)
    siem.enviar("chaveiro_iniciado", servico="chaveiro")
    srv.serve_forever()

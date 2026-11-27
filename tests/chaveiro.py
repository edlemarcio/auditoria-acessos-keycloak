"""Critérios de aceite do chaveiro e do envelope de chaves (docs/PROPOSTA_WEB.md §5.3, etapa W0b), contra a stack
real no modo vault. Usa um banco próprio (não mexe nas investigações do modo local).

  docker compose -f infra/docker-compose.yml --profile vault up -d vault && python infra/vault_setup.py
  psql ... -c "CREATE DATABASE auditor_w0b"; AUDITOR_DSN=<dono>/auditor_w0b AUDITOR_MODO=vault python -m auditor init
  psql <dono>/auditor_w0b -v senha_app=... -v senha_chaveiro=... -f infra/papeis.sql
  AUDITOR_DSN=<kc_auditor_app>/auditor_w0b CHAVEIRO_DSN=<kc_chaveiro>/auditor_w0b KC_DSN_kc26=... KC_DSN_kc18=... \\
    python tests/chaveiro.py [dias]

1. Segredos dos service accounts e DEKs só envolvidos pelo Vault; nenhuma chave no processo (AUDITOR_CHAVE ausente).
2. O worker pedindo a DEK de investigação fora de coleta é recusado, vai para a trilha e gera alerta no SIEM.
3. Identidade sem a finalidade (operador pedindo coleta, pacotes antes da conclusão, api sem OIDC) é recusada.
4. Serviço sem certificado, ou com certificado de outra AC, não conecta.
5. Fluxo completo pelo worker (preparar, coletar, fechar) e exportação pela identidade `pacotes`; contagem id a id.
6. Falha fechado: sem chaveiro não há recurso ao modo local; modo local recusado com AUDITOR_AMBIENTE=producao.
7. SIEM sem DEK, sem segredo e sem o identificador do alvo.
"""
from __future__ import annotations

import base64
import datetime as dt
import json
import os
import ssl
import socket
import subprocess
import sys
import time
from pathlib import Path

RAIZ = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(RAIZ))
os.environ["AUDITOR_MODO"] = "vault"
os.environ.pop("AUDITOR_CHAVE", None)          # 1: o processo não tem chave nenhuma
SIEM = RAIZ / "logs" / "siem_teste_chaveiro.jsonl"
os.environ["AUDITOR_SIEM"] = str(SIEM)
from auditor import chaves  # noqa: E402
from auditor.db import conectar  # noqa: E402

PORTA = 8443
falhas: list[str] = []


def checar(ok: bool, nome: str, detalhe: str = ""):
    print(f"{'OK   ' if ok else 'FALHA'} {nome}{(' — ' + detalhe) if detalhe else ''}", flush=True)
    if not ok:
        falhas.append(nome)


def auditor(*args, identidade=None, **kw) -> subprocess.CompletedProcess:
    env = dict(os.environ)
    if identidade:
        env["AUDITOR_IDENTIDADE"] = identidade
    return subprocess.run([sys.executable, "-m", "auditor", *args], cwd=RAIZ, env=env, capture_output=True,
                          text=True, **kw)


def como(identidade: str):
    """Troca a identidade mTLS deste processo (o cliente do chaveiro é recriado)."""
    os.environ["AUDITOR_IDENTIDADE"] = identidade
    chaves._cli = None
    chaves.esquecer()


def recusado(f) -> tuple[bool, str]:
    try:
        f()
        return False, "entregue"
    except chaves.Recusado as e:
        return True, str(e)


def subir_chaveiro() -> subprocess.Popen:
    p = subprocess.Popen([sys.executable, "-m", "auditor", "chaveiro", "--porta", str(PORTA)], cwd=RAIZ,
                         env=dict(os.environ), stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    for _ in range(50):
        try:
            socket.create_connection(("127.0.0.1", PORTA), 0.2).close()
            return p
        except OSError:
            time.sleep(0.2)
    raise SystemExit("chaveiro não subiu: " + (p.stdout.read() if p.stdout else ""))


def main(dias: int = 10):
    SIEM.unlink(missing_ok=True)
    ch = subir_chaveiro()
    try:
        # ---- 1. cadastro das instâncias com o segredo cifrado pelo Vault
        with conectar() as cx:
            existentes = {r["nome"] for r in cx.execute("SELECT nome FROM instancia")}
        cad = {"kc26": ["--url", os.environ.get("KC26_URL", "http://localhost:8090"), "--versao", "26.8.2",
                        "--realms-esperados", "portal-cidadao,intranet,servicos,parceiros"],
               "rhsso": ["--url", "http://localhost:8081/auth", "--versao", "18.0.2 legado (base RH-SSO 7.6)",
                         "--realms-esperados", "portal-cidadao,legado,rh"]}
        for nome, extra in cad.items():
            if nome not in existentes:
                r = auditor("instancia-add", "--nome", nome, "--client-id", "kc-auditor", "--segredo",
                            os.environ.get("KC_SEGREDO", "troque-este-segredo"), "--homologacao", "homologacao",
                            "--sonda", "sonda", *extra, identidade="operador", timeout=300)
                checar(r.returncode == 0, f"1 cadastro da instância {nome} no modo vault", r.stderr.strip()[-200:])
        with conectar() as cx:
            segs = [bytes(r["segredo_cifrado"]) for r in cx.execute("SELECT segredo_cifrado FROM instancia")]
        checar(segs and all(s.startswith(b"vault:v") for s in segs), "1 segredos dos service accounts cifrados "
               "pelo Vault (Transit, contexto por instância)")

        # ---- abrir pela identidade operador (cria as DEKs pelo chaveiro)
        alvo = json.loads((RAIZ / "dados/pessoas.json").read_text())["casos"]["ALVO"]["cpf"]
        ate = dt.date.today() - dt.timedelta(days=1)
        r = auditor("investigar", "--cpf", alvo, "--de", (ate - dt.timedelta(days=dias)).isoformat(), "--ate",
                    ate.isoformat(), "--operador", "teste-chaveiro", "--justificativa", "Teste do chaveiro W0b",
                    "--varredura", identidade="operador", timeout=120)
        checar(r.returncode == 0 and "na fila do worker" in r.stdout, "5 investigar no modo vault vai direto para a "
               "fila", r.stdout.strip().replace("\n", " | ") + r.stderr[-300:])
        inv = int(r.stdout.split("investigação ")[1].split()[0])
        with conectar() as cx:
            ks = cx.execute("SELECT classe, envelope, key_id FROM chave_investigacao WHERE investigacao_id=%s",
                            (inv,)).fetchall()
            i = cx.execute("SELECT * FROM investigacao WHERE id=%s", (inv,)).fetchone()
        checar(len(ks) == 2 and all(bytes(k["envelope"]).startswith(b"vault:v") and k["key_id"] == "kc-auditor-kek"
                                    for k in ks), "1 DEK principal e de terceiros envolvidas pela KEK do Vault")
        checar(i["alvo_hmac"].startswith("vault:v") and bytes(i["alvo_cifrado"])[:1] == b"\x03",
               "1 HMAC do alvo pelo Vault e alvo cifrado com a DEK (v3)")

        # ---- 2. worker pedindo DEK fora de coleta (status na_fila)
        como("worker")
        ok, msg = recusado(lambda: chaves.dek(inv, "coleta"))
        checar(ok, "2 worker pedindo DEK de investigação fora de coleta é recusado", msg)
        with conectar() as cx:
            t = cx.execute("SELECT count(*) n FROM trilha_auditoria WHERE investigacao_id=%s AND acao='recusar_dek' "
                           "AND operador='chaveiro:worker'", (inv,)).fetchone()["n"]
        alertas = [json.loads(l) for l in SIEM.read_text().splitlines()] if SIEM.exists() else []
        checar(t >= 1 and any(a["acao"] == "recusar_dek" and a["severidade"] == "alerta" and a.get("investigacao")
                              == inv for a in alertas), "2 recusa registrada na trilha e alerta no SIEM")

        # ---- 3. identidades sem a finalidade
        for ident, fin, nome in (("operador", "coleta", "operador pedindo DEK de coleta"),
                                 ("pacotes", "exportar", "pacotes antes da conclusão"),
                                 ("api", "exportar", "api sem token OIDC (W1)"),
                                 ("worker", "exportar", "worker pedindo DEK de exportação")):
            como(ident)
            ok, msg = recusado(lambda: chaves.dek(inv, fin))
            checar(ok, f"3 {nome} é recusado", msg)
        como("worker")
        ok, msg = recusado(lambda: chaves.pedir("/v1/hmac/alvo", tipo="cpf", digitos="00000000000"))
        checar(ok, "3 worker não calcula HMAC de alvo (não abre investigações)", msg)

        # ---- 4. mTLS
        ctx = ssl.create_default_context(cafile=str(RAIZ / "chaves/servicos/ca.crt"))
        try:
            with socket.create_connection(("127.0.0.1", PORTA), 3) as s, ctx.wrap_socket(s, server_hostname="localhost") as t:
                t.sendall(b"POST /v1/dek HTTP/1.1\r\nHost: x\r\nContent-Length: 2\r\n\r\n{}")
                sem = t.recv(100)
            checar(not sem, "4 sem certificado de cliente não recebe nada", repr(sem[:60]))
        except (ssl.SSLError, ConnectionError, OSError) as e:
            checar(True, "4 sem certificado de cliente a conexão é recusada", type(e).__name__)
        checar(_outra_ac(ctx), "4 certificado de outra AC é recusado")

        # ---- 5. fluxo completo pelo worker e exportação
        w = auditor("worker", "--threads", "3", "--ocioso", "15", identidade="worker", timeout=1800)
        with conectar() as cx:
            st = cx.execute("SELECT status FROM investigacao WHERE id=%s", (inv,)).fetchone()["status"]
            entregas = cx.execute("SELECT detalhe->>'finalidade' f, count(*) n FROM trilha_auditoria WHERE "
                                  "investigacao_id=%s AND acao='entregar_dek' GROUP BY 1", (inv,)).fetchall()
        checar(st in ("concluida", "concluida_com_lacunas"), "5 worker prepara, coleta e fecha no modo vault",
               f"status={st} {w.stderr.strip()[-300:]}")
        checar({e["f"] for e in entregas} >= {"preparar", "coleta"}, "5 DEKs entregues ao worker por finalidade",
               str({e["f"]: e["n"] for e in entregas}))
        como("pacotes")
        ok, msg = recusado(lambda: chaves.dek(inv, "exportar"))
        checar(ok, "3 pacotes sem pacote pedido é recusado, mesmo com a investigação concluída", msg)
        with conectar() as cx:   # o pedido de pacote (na W1, feito pela API)
            cx.execute("INSERT INTO pacote (investigacao_id, sem_mascara, pedido_por) VALUES (%s,false,'teste')", (inv,))
        r = subprocess.run([sys.executable, "tests/contagem_real.py", str(inv)], cwd=RAIZ, capture_output=True,
                           text=True, env={**os.environ, "AUDITOR_IDENTIDADE": "pacotes"})
        checar(r.returncode == 0, "5 contagem id a id", r.stdout.strip().replace("\n", " | ")[-300:])
        saida = RAIZ / "saida" / "teste_chaveiro"
        e = auditor("exportar", "--id", str(inv), "--saida", str(saida), identidade="pacotes", timeout=600)
        checar(e.returncode == 0 and "pacote" in e.stdout, "5 exportação pela identidade pacotes",
               (e.stdout + e.stderr).strip()[-300:])
        como("operador")
        ok, msg = recusado(lambda: chaves.dek(inv, "exportar"))
        checar(ok, "5 operador não recebe a DEK de exportação nem depois da conclusão", msg)

        # ---- 7. SIEM
        txt = SIEM.read_text()
        como("pacotes")
        d = chaves.dek(inv, "exportar")
        checar(base64.b64encode(d).decode() not in txt and alvo not in txt and "".join(filter(str.isdigit, alvo))
               not in txt and "troque-este-segredo" not in txt, "7 SIEM sem DEK, sem segredo e sem o alvo",
               f"{len(txt.splitlines())} linhas")
    finally:
        ch.terminate()
        ch.wait(10)

    # ---- 6. falha fechado (chaveiro parado)
    como("worker")
    os.environ["AUDITOR_CHAVE"] = base64.b64encode(os.urandom(32)).decode()   # mesmo com chave local disponível
    try:
        chaves.dek(inv, "coleta")
        checar(False, "6 sem chaveiro, nada de recurso ao modo local")
    except chaves.ChaveiroIndisponivel as e:
        checar(True, "6 sem chaveiro, nada de recurso ao modo local", str(e))
    os.environ["AUDITOR_MODO"], os.environ["AUDITOR_AMBIENTE"] = "local", "producao"
    try:
        chaves.modo()
        checar(False, "6 modo local recusado em produção")
    except RuntimeError as e:
        checar("producao" in str(e), "6 modo local recusado em produção", str(e)[:80])

    print(f"\n{'APROVADO' if not falhas else 'REPROVADO'}: {len(falhas)} falha(s)")
    sys.exit(1 if falhas else 0)


def _outra_ac(ctx_servidor_ca) -> bool:
    """Certificado autoassinado com o CN de um serviço legítimo: o chaveiro não pode aceitar."""
    import tempfile
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID
    k = ec.generate_private_key(ec.SECP256R1())
    nome = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "worker.kc-auditor.local")])
    agora = dt.datetime.now(dt.timezone.utc)
    c = (x509.CertificateBuilder().subject_name(nome).issuer_name(nome).public_key(k.public_key())
         .serial_number(x509.random_serial_number()).not_valid_before(agora - dt.timedelta(minutes=1))
         .not_valid_after(agora + dt.timedelta(hours=1)).sign(k, hashes.SHA256()))
    with tempfile.TemporaryDirectory() as d:
        (Path(d) / "c.crt").write_bytes(c.public_bytes(serialization.Encoding.PEM))
        (Path(d) / "c.key").write_bytes(k.private_bytes(serialization.Encoding.PEM,
                                                        serialization.PrivateFormat.PKCS8,
                                                        serialization.NoEncryption()))
        ctx_servidor_ca.load_cert_chain(Path(d) / "c.crt", Path(d) / "c.key")
        try:
            with socket.create_connection(("127.0.0.1", PORTA), 3) as s, \
                    ctx_servidor_ca.wrap_socket(s, server_hostname="localhost") as t:
                corpo = b'{"investigacao": 1, "finalidade": "coleta"}'
                t.sendall(b"POST /v1/dek HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\nContent-Length: "
                          + str(len(corpo)).encode() + b"\r\n\r\n" + corpo)
                return not t.recv(200).startswith(b"HTTP/1.1 200")
        except (ssl.SSLError, ConnectionError, OSError):
            return True


if __name__ == "__main__":
    main(*(int(x) for x in sys.argv[1:2]))

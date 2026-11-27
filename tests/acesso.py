"""Critérios de aceite da W1 (docs/PROPOSTA_WEB.md §11): acesso, pelas duas portas, contra a stack real.

  python infra/realm_auditor.py
  AUDITOR_DSN=<kc_auditor_app> AUDITOR_CHAVE=... AUDITOR_CHAVE_ED25519=... KC_DSN_kc26=... KC_DSN_kc18=... \\
    python tests/acesso.py

Sobe a API e um worker (modo local) e faz login de cada usuário de teste pela web (BFF, código + PKCE, MFA) e pela
CLI de produção (device flow, MFA, processo sem nenhuma credencial).

1. Matriz de permissões dos perfis (solicitante, investigador, aprovador, auditor interno, administrador técnico,
   gestor de acesso, operador do Vault), pela web e pela CLI: o que cada um pode, funciona; o que não pode, é recusado.
2. Segregação e quatro olhos: quem pede não aprova; o aprovador não se designa; no pedido externo quem registra pode
   investigar; o pacote sem máscara exige outra pessoa; papéis conflitantes recusados no login.
3. Step-up: ação sensível com autenticação de mais de 5 min é recusada.
4. Nenhuma rota sem autorização; POST com cookie sem o cabeçalho anti-CSRF recusado.
5. CLI de produção sem credencial de banco nem de Vault: recusa iniciar se houver uma no ambiente.
6. Modo local que falha fechado: sem AUDITOR_MODO, contra destino de produção ou em host de produção.
7. Trilha no SIEM sem texto livre.
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import threading
import time
from datetime import date, timedelta
from pathlib import Path

import httpx

RAIZ = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(RAIZ))
sys.path.insert(0, str(RAIZ / "tests"))
from navegador_kc import aprovar_dispositivo, cliente, logar  # noqa: E402

API = "http://localhost:8000"
EMISSOR = os.environ.setdefault("AUDITOR_OIDC_EMISSOR", "http://localhost:8090/realms/auditor")
SIEM = RAIZ / "logs" / "siem_teste_acesso.jsonl"
falhas: list[str] = []
web: dict[str, httpx.Client] = {}
LOGIN_CLI: dict[str, float] = {}


def checar(ok: bool, nome: str, detalhe="") -> None:
    detalhe = str(detalhe)
    print(f"{'OK   ' if ok else 'FALHA'} {nome}{(' — ' + detalhe) if detalhe else ''}", flush=True)
    if not ok:
        falhas.append(nome)


# ------------------------------------------------------------------ portas
def entrar_web(u: str) -> httpx.Response | httpx.Client:
    c = cliente()
    volta = logar(f"{API}/auth/entrar", u, c, retorno=f"{API}/auth/retorno")
    r = c.get(volta)
    if r.status_code not in (302, 307):
        return r
    c.headers["X-Requisicao"] = "kc-auditor"
    return c


def env_cli(u: str, **extra) -> dict:
    """Ambiente da CLI de produção: só endereço da API, do SSO e o arquivo do token. Nenhuma credencial."""
    return {"PATH": os.environ["PATH"], "HOME": os.environ.get("HOME", "/tmp"), "AUDITOR_MODO": "producao",
            "AUDITOR_API": API, "AUDITOR_OIDC_EMISSOR": EMISSOR,
            "AUDITOR_SESSAO_CLI": str(RAIZ / "chaves" / f"cli_{u}.json"), **extra}


def cli(u: str, *args, **extra) -> subprocess.CompletedProcess:
    return subprocess.run([sys.executable, "-m", "auditor", *map(str, args)], cwd=RAIZ, env=env_cli(u, **extra),
                          capture_output=True, text=True, timeout=900)


def entrar_cli(u: str) -> subprocess.CompletedProcess:
    p = subprocess.Popen([sys.executable, "-m", "auditor", "login"], cwd=RAIZ, env=env_cli(u),
                         stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    url = p.stdout.readline().split("Abra ", 1)[1].strip()
    aprovar_dispositivo(url, u)
    out, err = p.communicate(timeout=120)
    LOGIN_CLI[u] = time.time()
    return subprocess.CompletedProcess(p.args, p.returncode, out, err)


def _codigo_cli(r: subprocess.CompletedProcess) -> int | None:
    m = re.search(r"\[(\d{3}) ", r.stderr + r.stdout)
    return int(m.group(1)) if m else (0 if r.returncode == 0 else None)


def pelas_duas(u: str, metodo: str, caminho: str, corpo: dict | None, cli_args: list, permitido: bool, nome: str):
    """A mesma ação pela web e pela CLI; confere que as duas portas dão a mesma resposta."""
    r = web[u].request(metodo, f"{API}{caminho}", json=corpo)
    c = cli(u, *cli_args)
    ok_w = (r.status_code < 300) if permitido else r.status_code in (401, 403, 404)
    cc = _codigo_cli(c)
    ok_c = (c.returncode == 0) if permitido else (c.returncode != 0 and cc in (401, 403, 404))
    checar(ok_w and ok_c, f"1 {nome}: {u} {'pode' if permitido else 'não pode'} (web e CLI)",
           f"web {r.status_code}, cli {cc if cc is not None else c.returncode}"
           + ("" if ok_w and ok_c else f" {(r.text[:90] if not ok_w else c.stderr[-120:])}"))
    return r


# ------------------------------------------------------------------ processos
MODO = os.environ.get("AUDITOR_MODO", "local")


def subir(nome: str, *args) -> subprocess.Popen:
    env = {**os.environ, "AUDITOR_MODO": MODO, "AUDITOR_COOKIE_SEGURO": "0", "AUDITOR_SIEM": str(SIEM)}
    p = subprocess.Popen([sys.executable, "-m", "auditor", *args], cwd=RAIZ, env=env,
                         stdout=open(RAIZ / "logs" / f"teste_acesso_{nome}.log", "w"), stderr=subprocess.STDOUT)
    return p


def main():
    SIEM.unlink(missing_ok=True)
    (RAIZ / "logs").mkdir(exist_ok=True)
    if MODO == "vault":   # como em produção: chaveiro, API e workers com identidades próprias, nenhuma chave local
        os.environ.pop("AUDITOR_CHAVE", None)
        procs = [subir("chaveiro", "chaveiro")]
        time.sleep(2)
        procs += [subir("api", "api"), subir("worker", "worker", "--threads", "3", "--papel", "coleta"),
                  subir("pacotes", "worker", "--threads", "1", "--papel", "pacotes")]
    else:
        procs = [subir("api", "api"), subir("worker", "worker", "--threads", "3")]
    try:
        for _ in range(50):
            try:
                httpx.get(f"{API}/saude", timeout=1)
                break
            except httpx.TransportError:
                time.sleep(0.3)
        executar()
    finally:
        for p in procs:
            p.terminate()
            p.wait(15)
    print(f"\n{'APROVADO' if not falhas else 'REPROVADO'}: {len(falhas)} falha(s)")
    sys.exit(1 if falhas else 0)


def executar():
    usuarios = ["solicitante1", "solicitante2", "investigador1", "investigador2", "aprovador1", "aprovador2",
                "aprovinvest1", "auditor1", "admin1", "gestor1", "operadorvault1"]
    # ---- logins pelas duas portas
    for u in usuarios:
        w = entrar_web(u)
        if isinstance(w, httpx.Client):
            web[u] = w
    checar(set(web) == set(usuarios), "login web (código + PKCE, MFA) de todos os perfis", f"{len(web)} sessões")
    falhou_cli = [u for u in usuarios if entrar_cli(u).returncode != 0]
    checar(not falhou_cli, "login da CLI de produção (device flow, MFA) de todos os perfis", f"falharam: {falhou_cli}")
    r = entrar_web("conflito1")
    checar(not isinstance(r, httpx.Client) and r.status_code == 403 and "papeis_conflitantes" in r.text,
           "2 papéis conflitantes: login web recusado", getattr(r, "status_code", "sessão criada"))
    c = entrar_cli("conflito1")
    checar(c.returncode != 0 and "papeis_conflitantes" in c.stderr, "2 papéis conflitantes: CLI recusada")
    t0 = time.time()

    # ---- pedir
    alvo = json.loads((RAIZ / "dados/pessoas.json").read_text())["casos"]["ALVO"]["cpf"]
    ate = date.today() - timedelta(days=1)
    de = (ate - timedelta(days=2)).isoformat()
    corpo = {"cpf": alvo, "de": de, "ate": ate.isoformat(), "justificativa": "Processo 77/2026, teste da W1"}
    args = ["pedir", "--cpf", alvo, "--de", de, "--ate", ate.isoformat(), "--justificativa", "Processo 78/2026"]
    for u in ("aprovador1", "auditor1", "admin1", "gestor1", "operadorvault1", "investigador1"):
        pelas_duas(u, "POST", "/api/investigacoes", corpo, args, False, "pedir investigação")
    r = pelas_duas("solicitante1", "POST", "/api/investigacoes", corpo, args, True, "pedir investigação")
    A = r.json()["investigacao"]
    B = A + 1   # a da CLI (Processo 78), usada para devolver, reenviar e recusar

    # ---- ver e listar
    for u, pode in (("solicitante1", True), ("solicitante2", False), ("investigador1", False), ("aprovador1", True),
                    ("auditor1", True), ("admin1", False), ("gestor1", False), ("operadorvault1", False)):
        pelas_duas(u, "GET", f"/api/investigacoes/{A}", None, ["ver", "--id", A], pode, "ver a investigação")
    v = web["auditor1"].get(f"{API}/api/investigacoes/{A}").json()
    checar("alvo" not in v and "justificativa" not in v, "1 auditor interno vê só metadados (sem alvo mascarado)")
    v = web["aprovador1"].get(f"{API}/api/investigacoes/{A}").json()
    checar(v.get("justificativa") == corpo["justificativa"], "1 aprovador vê a justificativa para decidir")
    for u, pode in (("admin1", False), ("gestor1", False), ("operadorvault1", False), ("auditor1", True)):
        pelas_duas(u, "GET", "/api/investigacoes", None, ["pedidos"], pode, "listar investigações")

    # ---- decisão
    ap = {"investigador": "investigador1", "motivo": "Pedido fundamentado"}
    aargs = ["aprovar", "--id", A, "--investigador", "investigador1", "--motivo", "Pedido fundamentado"]
    for u in ("solicitante1", "investigador1", "auditor1", "admin1", "gestor1"):
        pelas_duas(u, "POST", f"/api/investigacoes/{A}/aprovar", ap, aargs, False, "aprovar")
    r = web["aprovinvest1"].post(f"{API}/api/investigacoes/{A}/aprovar",
                                 json={"investigador": "aprovinvest1", "motivo": "Eu mesmo investigo"})
    checar(r.status_code == 403 and "segregacao" in r.text, "2 aprovador não se designa investigador", r.status_code)
    r = web["aprovador1"].post(f"{API}/api/investigacoes/{A}/aprovar", json={"investigador": "solicitante1",
                                                                             "motivo": "Designação inválida"})
    checar(r.status_code == 422, "2 só quem tem o perfil investigador é designado", r.status_code)
    r = web["aprovador1"].post(f"{API}/api/investigacoes/{A}/aprovar", json=ap)
    checar(r.status_code == 200, "1 aprovador1 aprova e designa investigador1 (web)", r.text[:80])
    c = cli("aprovador2", "devolver", "--id", B, "--motivo", "Falta o número do processo")
    checar(c.returncode == 0, "1 aprovador2 devolve pela CLI", c.stderr[-100:])
    c = cli("solicitante1", "reenviar", "--id", B, "--motivo", "Número incluído")
    checar(c.returncode == 0, "1 solicitante reenvia pela CLI", c.stderr[-100:])
    c = cli("solicitante2", "reenviar", "--id", B, "--motivo", "Não é meu")
    checar(c.returncode != 0, "1 outro solicitante não reenvia o pedido alheio")
    r = web["aprovador1"].post(f"{API}/api/investigacoes/{B}/recusar", json={"motivo": "Sem fundamento legal"})
    checar(r.status_code == 200, "1 aprovador recusa (web)", r.text[:80])

    # ---- pedido externo: quem registra pode ser o investigador
    ext = {**corpo, "justificativa": "Ofício 12/2026 da Polícia Federal",
           "origem": {"orgao": "Polícia Federal", "documento": "Ofício 12/2026", "fundamento": "Requisição em IPL",
                      "processo": "IPL 1/2026", "destinatario": "Delegado responsável"}}
    # W2: o pedido externo exige o documento de origem antes do envio (rascunho → documento → enviar)
    r = web["investigador2"].post(f"{API}/api/investigacoes", json={**ext, "rascunho": True})
    E = r.json().get("investigacao")
    rd = web["investigador2"].post(f"{API}/api/investigacoes/{E}/documento",
                                   files={"arquivo": ("oficio.pdf", b"%PDF-1.4 oficio 12/2026")})
    re_ = web["investigador2"].post(f"{API}/api/investigacoes/{E}/enviar")
    checar(r.status_code == 201 and rd.status_code == 201 and re_.status_code == 200,
           "2 investigador registra pedido externo (ofício)", f"{r.text[:60]} {rd.status_code} {re_.text[:60]}")
    r = web["investigador2"].post(f"{API}/api/investigacoes", json=corpo)
    checar(r.status_code == 403, "2 investigador não pede investigação sem origem externa", r.status_code)
    r = web["aprovador2"].post(f"{API}/api/investigacoes/{E}/aprovar", json={"investigador": "investigador2",
                                                                             "motivo": "Ofício conferido"})
    checar(r.status_code == 200, "2 pedido externo: quem registrou é designado investigador (aprovador ≠ inv.)",
           r.text[:80])
    v = web["investigador2"].get(f"{API}/api/investigacoes/{E}").json()
    checar((v.get("origem") or {}).get("orgao") == "Polícia Federal", "2 origem do pedido externo cifrada e legível "
           "pelo designado")

    # ---- coleta
    for u in ("investigador2", "aprovador1", "solicitante1", "auditor1"):
        pelas_duas(u, "POST", f"/api/investigacoes/{A}/iniciar", None, ["iniciar", "--id", A], False, "iniciar coleta")
    pelas_duas("investigador1", "POST", f"/api/investigacoes/{A}/iniciar", None, ["progresso", "--id", A], True,
               "iniciar coleta (web) e acompanhar (CLI)")
    for _ in range(300):
        st = web["investigador1"].get(f"{API}/api/investigacoes/{A}/progresso").json()["status"]
        if st in ("concluida", "concluida_com_lacunas"):
            break
        time.sleep(2)
    checar(st in ("concluida", "concluida_com_lacunas"), "1 worker prepara, coleta e fecha a investigação aprovada", st)
    for u in ("investigador2", "solicitante1"):
        pelas_duas(u, "POST", f"/api/investigacoes/{A}/pausar", None, ["pausar", "--id", A], False, "pausar")

    # ---- pacotes
    for u in ("investigador2", "solicitante1", "aprovador1", "auditor1"):
        pelas_duas(u, "POST", f"/api/investigacoes/{A}/pacotes", {"sem_mascara": False},
                   ["exportar", "--id", A, "--saida", "saida/teste_acesso", "--espera", "5"], False, "pedir pacote")
    c = cli("investigador1", "exportar", "--id", A, "--saida", "saida/teste_acesso")
    checar(c.returncode == 0 and "sha256" in c.stdout, "1 investigador gera e baixa o pacote mascarado pela CLI",
           (c.stdout + c.stderr).strip()[-140:])
    pk = web["investigador1"].get(f"{API}/api/investigacoes/{A}/pacotes").json()[-1]["pacote"]
    link = web["investigador1"].post(f"{API}/api/pacotes/{pk}/link").json()["link"]
    r = web["investigador2"].get(f"{API}{link}")
    checar(r.status_code == 404, "1 link de download não serve a outra pessoa", r.status_code)
    r1, r2 = web["investigador1"].get(f"{API}{link}"), web["investigador1"].get(f"{API}{link}")
    checar(r1.status_code == 200 and r2.status_code == 404, "1 link de download é de uso único",
           f"{r1.status_code}, depois {r2.status_code}")
    r = web["investigador1"].post(f"{API}/api/investigacoes/{A}/pacotes",
                                  json={"sem_mascara": True, "destino": "Juntada ao processo 77/2026, sigilo nível 3"})
    checar(r.status_code == 202 and "pedido" in r.json(), "2 pacote sem máscara vira pedido de aprovação", r.text[:80])
    ped = r.json()["pedido"]
    r = web["investigador1"].post(f"{API}/api/aprovacoes/{ped}/decidir", json={"aprovar": True, "motivo": "Eu mesmo"})
    checar(r.status_code == 403, "2 quatro olhos: o investigador não aprova o próprio pacote", r.status_code)
    c = cli("aprovador2", "decidir-pacote", "--pedido", ped, "--aprovar", "--motivo", "Destino conferido")
    checar(c.returncode == 0, "2 outro aprovador aprova o pacote sem máscara (CLI)", c.stderr[-120:])
    c = cli("investigador1", "baixar", "--pacote", json.loads(c.stdout)["pacote"], "--saida", "saida/teste_acesso")
    checar(c.returncode == 0 and "sem_mascara" in c.stdout, "1 investigador baixa o pacote sem máscara aprovado",
           (c.stdout + c.stderr).strip()[-120:])

    # ---- fiscalização, administração, gestão de acesso
    for u, pode in (("auditor1", True), ("investigador1", False), ("aprovador1", False), ("admin1", False),
                    ("gestor1", False)):
        pelas_duas(u, "GET", f"/api/trilha?investigacao={A}", None, ["trilha", "--id", A], pode, "ler a trilha")
    pelas_duas("auditor1", "GET", "/api/trilha/verificar", None, ["verificar-cadeia"], True, "verificar a cadeia")
    v = web["auditor1"].get(f"{API}/api/trilha/verificar").json()
    checar(v["cadeias"] == v["integras"], "1 todas as cadeias íntegras", f"{v['integras']}/{v['cadeias']}")
    for u, pode in (("admin1", True), ("auditor1", False), ("investigador1", False), ("gestor1", False),
                    ("operadorvault1", False)):
        pelas_duas(u, "GET", "/api/instancias", None, ["instancias"], pode, "ver instâncias")
    pelas_duas("admin1", "POST", "/api/instancias/kc26/sondas", None, ["sondas", "--nome", "kc26"], True,
               "rodar sondas")
    for u in ("aprovador1", "investigador1"):
        pelas_duas(u, "POST", "/api/instancias/kc26/orcamento", {"concorrencia": 2, "req_por_s": 5},
                   ["orcamento", "--nome", "kc26", "--concorrencia", 2, "--req-por-s", 5], False, "ajustar orçamento")
    for u, pode in (("gestor1", True), ("admin1", False), ("auditor1", False)):
        pelas_duas(u, "GET", "/api/usuarios", None, ["usuarios"], pode, "ver perfis (recertificação)")

    # ---- 3. step-up: CLI com login de mais de 5 min
    espera = 305 - (time.time() - LOGIN_CLI["admin1"])
    if espera > 0:
        print(f"  (aguardando {espera:.0f}s para o login da CLI passar de 5 min)", flush=True)
        time.sleep(espera)
    c = cli("admin1", "orcamento", "--nome", "kc26", "--concorrencia", 2, "--req-por-s", 5)
    checar(c.returncode != 0 and "autenticação recente" in c.stderr, "3 step-up: ação sensível com login antigo "
           "recusada", c.stderr.strip()[-90:])
    entrar_cli("admin1")
    c = cli("admin1", "orcamento", "--nome", "kc26", "--concorrencia", 2, "--req-por-s", 5)
    checar(c.returncode == 0, "3 depois de novo login com MFA, a ação passa", c.stderr[-90:])

    # ---- 4. nenhuma rota sem autorização
    from auditor.api import ROTAS_PUBLICAS, app
    sem, vault_ok = [], []
    for rt in app.routes:
        if not hasattr(rt, "methods") or rt.path in ROTAS_PUBLICAS:
            continue
        caminho = re.sub(r"\{[^}]+\}", "1", rt.path)
        for m in rt.methods - {"HEAD", "OPTIONS"}:
            if httpx.request(m, f"{API}{caminho}", json={}).status_code != 401:
                sem.append(f"{m} {rt.path}")
            if caminho not in ("/api/eu", "/auth/sair") and web["operadorvault1"].request(m, f"{API}{caminho}", json={}).status_code < 300:
                vault_ok.append(f"{m} {rt.path}")
    checar(not sem, "4 nenhuma rota responde sem autenticação", f"{len(app.routes)} rotas; sem: {sem[:3]}")
    checar(not vault_ok, "4 usuário sem perfil (operador do Vault) não usa nenhuma rota", str(vault_ok[:3]))
    sem_csrf = cliente()
    sem_csrf.cookies = web["solicitante1"].cookies
    r = sem_csrf.post(f"{API}/api/investigacoes", json=corpo)
    checar(r.status_code == 403 and "csrf" in r.text, "4 POST com cookie e sem cabeçalho anti-CSRF recusado",
           r.status_code)

    # ---- 5. CLI de produção sem credencial
    for var, val in (("AUDITOR_DSN", os.environ.get("AUDITOR_DSN", "postgresql://x@y/z")),
                     ("AUDITOR_CHAVE", "x"), ("AUDITOR_CERTS", "chaves/servicos")):
        c = cli("solicitante1", "eu", **{var: val})
        checar(c.returncode != 0 and var in (c.stderr + c.stdout), f"5 CLI de produção recusa iniciar com {var}")
    c = cli("solicitante1", "init")
    checar(c.returncode != 0 and "não existe no modo producao" in (c.stderr + c.stdout),
           "5 comandos de servidor não existem na CLI de produção")

    # ---- 6. modo local que falha fechado
    base = {k: v for k, v in os.environ.items() if k not in ("AUDITOR_MODO", "AUDITOR_IDENTIDADE")}
    casos6 = (("sem AUDITOR_MODO", {}),
              ("banco em destino de produção", {"AUDITOR_MODO": "local", "AUDITOR_DESTINOS_PRODUCAO": "localhost:5435"}),
              ("instância em destino de produção", {"AUDITOR_MODO": "local", "AUDITOR_DESTINOS_PRODUCAO": "localhost:8090"}),
              ("host marcado como produção", {"AUDITOR_MODO": "local", "AUDITOR_AMBIENTE": "producao"}))
    for nome, extra in casos6:
        c = subprocess.run([sys.executable, "-m", "auditor", "init"], cwd=RAIZ, capture_output=True, text=True,
                           env={**base, "AUDITOR_SIEM": str(SIEM), **extra})
        checar(c.returncode != 0 and ("recusado" in c.stderr or "AUDITOR_MODO" in c.stderr),
               f"6 modo local recusado: {nome}", c.stderr.strip()[-80:])
    ev = [json.loads(x) for x in SIEM.read_text().splitlines()]
    checar(sum(1 for e in ev if e["acao"] in ("modo_local_contra_producao", "modo_local_em_producao")) >= 3,
           "6 recusas do modo local alertadas no SIEM")

    # ---- 7. trilha no SIEM
    txt = SIEM.read_text()
    regs = {e.get("registro") for e in ev if e["acao"] == "trilha"}
    checar({"pedir_investigacao", "aprovar_investigacao", "baixar_pacote", "login"} <= regs and
           "Processo 77/2026" not in txt and "Ofício 12/2026" not in txt and alvo not in txt,
           "7 trilha copiada para o SIEM sem texto livre nem identificador", f"{len(regs)} tipos de registro")
    print(f"  (duração da matriz: {time.time() - t0:.0f}s)")


if __name__ == "__main__":
    main()

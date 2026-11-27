"""Critérios de aceite do servidor da W2 (docs/W2_CONTRATO.md, PROPOSTA_WEB §11) contra a stack real, pela API como a
web faria (cookie da sessão do BFF + cabeçalho X-Requisicao).

  python infra/realm_auditor.py --origem-dev http://localhost:8300 ...
  AUDITOR_DSN=<kc_auditor_app>/auditor_w2b AUDITOR_CHAVE=... KC_DSN_kc26=... KC_DSN_kc18=... python tests/gestao.py

Sobe a API (porta 8300) e um worker (modo local, laço de limpeza a cada 5 s) e percorre:
 1. investigação de 180 dias em kc26 e kc18: estimativa, rascunho, editar, busca tolerante, enviar, devolver,
    reenviar, aprovar, coletar, pausar, retomar e concluir; `acoes` por perfil; linha do tempo com motivo só para
    quem pode ler;
 2. rascunho descartado (DEK destruída);
 3. pedido externo com documento de origem (cifrado no banco; sha256 na trilha; quem baixa);
 4. preservação urgente: coleta lacrada (409 nas rotas de dados) → escalonamento (relógio simulado) → prorrogação
    única → aprovação libera; outra recusada → DEK destruída; outra sem decisão em 5 dias úteis → DEK destruída;
 5. acompanhamento JSON e SSE (eventos, heartbeat, 4ª conexão 429, Last-Event-ID);
 6. notificações e e-mail sem dado pessoal; pedir-acesso igual para existente e inexistente;
 7. substituto e escalonamento do pedido parado (relógio simulado);
 8. perfis: concessão/revogação pelo Keycloak Admin (conta kc-auditor-gestao), combinação proibida recusada antes,
    alerta ao auditor interno; recertificação (confirmada e vencida); vigia de papel alterado direto no Keycloak;
 9. saúde com filas e workers; teste de conexão de instância; SPA (503 sem web/dist; com web/dist, cache e CSP);
    erro 500 com código de correlação; 422 sem eco do CPF;
10. varredura: nenhum CPF/título/username/e-mail/userId da massa em claro no banco, em logs/ e nas respostas.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import threading
import time
from datetime import date, timedelta
from pathlib import Path

import httpx

RAIZ = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(RAIZ))
sys.path.insert(0, str(RAIZ / "tests"))
from navegador_kc import cliente, logar  # noqa: E402

PORTA = int(os.environ.get("PORTA_TESTE", "8300"))
API = f"http://localhost:{PORTA}"
EMISSOR = os.environ.setdefault("AUDITOR_OIDC_EMISSOR", "http://localhost:8090/realms/auditor")
KC = EMISSOR.split("/realms/")[0]
LOGS = RAIZ / "logs"
SIEM = LOGS / "siem_teste_gestao.jsonl"
EMAIL = LOGS / "email_teste_gestao.jsonl"
ERROS = LOGS / "api_erros_teste_gestao.jsonl"
os.environ.update({"AUDITOR_API_URL": API, "AUDITOR_SIEM": str(SIEM), "AUDITOR_EMAIL": str(EMAIL),
                   "AUDITOR_LOG_ERROS": str(ERROS), "AUDITOR_MODO": os.environ.get("AUDITOR_MODO", "local")})
falhas: list[str] = []
oks = [0]
web: dict[str, httpx.Client] = {}
RESPOSTAS: list[str] = []   # todo corpo recebido, para a varredura final
ALVO = json.loads((RAIZ / "dados/pessoas.json").read_text())["casos"]["ALVO"]["cpf"]
TESTE_U = ("w2teste1", "w2teste2")


def checar(ok: bool, nome: str, detalhe="") -> bool:
    detalhe = str(detalhe)
    print(f"{'OK   ' if ok else 'FALHA'} {nome}{(' — ' + detalhe) if detalhe else ''}", flush=True)
    if ok:
        oks[0] += 1
    else:
        falhas.append(nome)
    return ok


SENSIVEIS = ("/aprovar", "/devolver", "/recusar", "/autorizar-preservacao", "/prorrogar-preservacao", "/papeis",
             "/confirmar", "/orcamento", "/decidir")
LOGIN: dict[str, float] = {}


def req(u: str, metodo: str, caminho: str, **kw) -> httpx.Response:
    if metodo == "POST" and caminho.endswith(SENSIVEIS) and time.time() - LOGIN.get(u, 0) > 240:
        entrar(u)   # step-up: ação sensível exige MFA nos últimos 5 min (como a tela faria após o 401 step_up)
    r = web[u].request(metodo, f"{API}{caminho}", **kw)
    if r.headers.get("content-type", "").startswith(("application/json", "text/plain")):
        RESPOSTAS.append(r.text)
    return r


def j(u, metodo, caminho, **kw):
    r = req(u, metodo, caminho, **kw)
    try:
        return r.status_code, r.json()
    except ValueError:
        return r.status_code, r.text


def entrar(u: str):
    c = cliente()
    volta = logar(f"{API}/auth/entrar", u, c, retorno=f"{API}/auth/retorno")
    r = c.get(volta)
    if r.status_code not in (302, 307):
        raise RuntimeError(f"login de {u}: {r.status_code} {r.text[:100]}")
    c.headers["X-Requisicao"] = "kc-auditor"
    web[u] = c
    LOGIN[u] = time.time()


# ------------------------------------------------------------------ Keycloak (master), banco e processos
class Mestre:
    def __init__(self):
        self.t = 0.0

        def renovar(rq):   # o token do admin do master vale 60 s
            if time.time() - self.t > 30:
                tk = httpx.post(f"{KC}/realms/master/protocol/openid-connect/token", trust_env=False,
                                data={"grant_type": "password", "client_id": "admin-cli", "username": "admin",
                                      "password": os.environ.get("KC_ADMIN_SENHA", "admin")}).json()["access_token"]
                self.h.headers["Authorization"] = f"Bearer {tk}"
                self.t = time.time()
            rq.headers["Authorization"] = self.h.headers["Authorization"]
        self.h = httpx.Client(base_url=f"{KC}/admin/realms/auditor", timeout=20, trust_env=False,
                              event_hooks={"request": [renovar]})

    def uid(self, u):
        r = self.h.get("/users", params={"username": u, "exact": "true"}).json()
        return r[0]["id"] if r else None

    def garantir(self, u):
        if not self.uid(u):
            self.h.post("/users", json={"username": u, "enabled": True, "firstName": "Teste", "lastName": "W2",
                                        "email": f"{u}@auditor.invalid", "emailVerified": True,
                                        "attributes": {"unidade": ["Teste W2"]}})
        return self.uid(u)

    def papeis(self, u):
        return sorted(p["name"] for p in self.h.get(f"/users/{self.uid(u)}/role-mappings/realm").json()
                      if p["name"] in ("solicitante", "investigador", "aprovador", "auditor_interno", "admin_tecnico",
                                       "gestor_acesso"))

    def mudar(self, u, conceder=(), revogar=()):
        uid = self.uid(u)
        for nomes, metodo in ((conceder, "POST"), (revogar, "DELETE")):
            reps = [self.h.get(f"/roles/{p}").json() for p in nomes]
            if reps:
                self.h.request(metodo, f"/users/{uid}/role-mappings/realm", json=reps)


def banco():
    from auditor.db import conectar
    return conectar()


def subir(nome: str, *args, **env) -> subprocess.Popen:
    e = {**os.environ, "AUDITOR_COOKIE_SEGURO": "0", "AUDITOR_FAXINA_S": "5", **env}
    return subprocess.Popen([sys.executable, "-m", "auditor", *args], cwd=RAIZ, env=e,
                            stdout=open(LOGS / f"teste_gestao_{nome}.log", "w"), stderr=subprocess.STDOUT)


def esperar(pred, limite=600, passo=2.0, nome=""):
    fim = time.time() + limite
    while time.time() < fim:
        v = pred()
        if v:
            return v
        time.sleep(passo)
    return None


def st(u, inv):
    return j(u, "GET", f"/api/investigacoes/{inv}")[1]


def acoes(u, inv):
    c, v = j(u, "GET", f"/api/investigacoes/{inv}")
    return v.get("acoes") if c == 200 else c


def notif(u, tipo=None):
    return [n for n in j(u, "GET", "/api/notificacoes?nao_lidas=1")[1] if not tipo or n["tipo"] == tipo]


# ------------------------------------------------------------------ SSE
class Ouvinte(threading.Thread):
    """Lê o stream SSE com o cookie da sessão; guarda (evento, id, dados)."""

    def __init__(self, u, inv, ultimo_id=None, duracao=30.0, ate_heartbeat=False):
        super().__init__(daemon=True)
        self.u, self.inv, self.ultimo, self.duracao, self.ate_hb = u, inv, ultimo_id, duracao, ate_heartbeat
        self.eventos: list[tuple] = []
        self.status = None
        self.aberto = threading.Event()
        self.parar = threading.Event()

    def run(self):
        h = {"Accept": "text/event-stream"}
        if self.ultimo is not None:
            h["Last-Event-ID"] = str(self.ultimo)
        c = httpx.Client(timeout=httpx.Timeout(5, read=self.duracao + 20), trust_env=False, cookies=web[self.u].cookies)
        fim = time.time() + self.duracao
        try:
            with c.stream("GET", f"{API}/api/investigacoes/{self.inv}/acompanhamento/stream", headers=h) as r:
                self.status = r.status_code
                self.aberto.set()
                if r.status_code != 200:
                    return
                ev, id_, dados = None, None, None
                for linha in r.iter_lines():
                    if linha.startswith("event:"):
                        ev = linha[6:].strip()
                    elif linha.startswith("id:"):
                        id_ = int(linha[3:].strip())
                    elif linha.startswith("data:"):
                        dados = json.loads(linha[5:].strip())
                    elif linha == "" and ev:
                        self.eventos.append((ev, id_, dados))
                        if ev == "heartbeat" and self.ate_hb:
                            break
                        ev, id_, dados = None, None, None
                    if time.time() > fim or self.parar.is_set():
                        break
        except httpx.HTTPError:
            pass
        finally:
            self.aberto.set()
            c.close()

    def progresso(self):
        return [e for e in self.eventos if e[0] == "progresso"]


# ------------------------------------------------------------------ roteiro
def main():
    LOGS.mkdir(exist_ok=True)
    for p in (SIEM, EMAIL, ERROS):
        p.unlink(missing_ok=True)
    m = Mestre()
    for u in TESTE_U:   # usuários descartáveis da gestão de perfis (sem papel no início)
        m.garantir(u)
        m.mudar(u, revogar=m.papeis(u))
    subprocess.run(["fuser", "-k", f"{PORTA}/tcp"], capture_output=True)
    procs = [subir("api", "api", "--porta", str(PORTA)), subir("worker", "worker", "--threads", "4")]
    try:
        for _ in range(60):
            try:
                httpx.get(f"{API}/saude", timeout=1)
                break
            except httpx.TransportError:
                time.sleep(0.3)
        executar(m)
    finally:
        for p in procs:
            p.terminate()
            p.wait(15)
        for u in TESTE_U:
            m.mudar(u, revogar=m.papeis(u))
    print(f"\n{'APROVADO' if not falhas else 'REPROVADO'}: {oks[0]} ok, {len(falhas)} falha(s)")
    for f in falhas:
        print(f"  - {f}")
    sys.exit(1 if falhas else 0)


def executar(m: Mestre):
    t0 = time.time()
    for u in ("solicitante1", "solicitante2", "investigador1", "investigador2", "aprovador1", "aprovador2",
              "coordenador1", "auditor1", "admin1", "gestor1"):
        entrar(u)
    checar(len(web) == 10, "login web (BFF, MFA) dos perfis", f"{len(web)} sessões")
    c, eu = j("coordenador1", "GET", "/api/eu")
    checar(eu.get("coordenador") is True, "coordenador1 tem o atributo coordenador no token")
    for nome in ("kc26", "rhsso"):   # coleta rápida no teste (ajuste do orçamento, com step-up)
        c, _ = j("admin1", "POST", f"/api/instancias/{nome}/orcamento", json={"concorrencia": 4, "req_por_s": 20})
    ate = date.today() - timedelta(days=1)
    de180 = (ate - timedelta(days=179)).isoformat()

    # ================================================================ 1. estimativa e rascunho
    c, e = j("solicitante1", "POST", "/api/estimativas", json={"de": de180, "ate": ate.isoformat(),
                                                               "instancias": ["kc26", "rhsso"]})
    exp = {(x["instancia"], x["realm"]): x for x in e.get("expiracao", [])}
    checar(c == 200 and e["tarefas"] > 0 and e["segundos"] > 0 and exp.get(("kc26", "servicos"), {}).get(
        "expira_antes_da_aprovacao") is True and e["preservacao_recomendada"] is True,
           "1 estimativa (180 dias): tarefas, tempo e expiração por realm (servicos guarda 90 dias)",
           f"{e.get('tarefas')} tarefas, {e.get('segundos')} s")
    n_trilha = banco().execute("SELECT count(*) n FROM trilha_auditoria").fetchone()["n"]
    j("solicitante1", "POST", "/api/estimativas", json={"de": de180, "ate": ate.isoformat()})
    checar(banco().execute("SELECT count(*) n FROM trilha_auditoria").fetchone()["n"] == n_trilha,
           "1 estimativa não grava nada na trilha")
    corpo = {"cpf": ALVO, "de": de180, "ate": ate.isoformat(), "instancias": ["kc26", "rhsso"],
             "justificativa": "Apuração disciplinar 12/2026 (teste W2)", "tipo_processo": "apuracao_disciplinar",
             "processo": "0001234-56.2026.6.05.0001", "rascunho": True}
    c, r = j("solicitante1", "POST", "/api/investigacoes", json=corpo)
    A = r.get("investigacao")
    checar(c == 201 and r.get("status") == "rascunho", "1 rascunho gravado sem enviar", r)
    c, v = j("solicitante1", "GET", f"/api/investigacoes/{A}")
    checar(v.get("acoes") == ["enviar", "editar", "descartar"] and v.get("alvo_mascarado", "").startswith("***")
           and v.get("tipo_processo") == "apuracao_disciplinar", "1 rascunho: ações do solicitante (enviar, editar, "
           "descartar) e alvo só mascarado", v.get("acoes"))
    checar(j("aprovador1", "GET", f"/api/investigacoes/{A}")[0] == 404 and
           j("solicitante2", "GET", f"/api/investigacoes/{A}")[0] == 404, "1 rascunho invisível a aprovador e a "
           "outro solicitante (404 sem_acesso)")
    c, r = j("solicitante1", "PUT", f"/api/investigacoes/{A}", json={**corpo, "cpf": None,
                                                                    "justificativa": "Apuração disciplinar 12/2026, "
                                                                                     "corrigida (teste W2)"})
    checar(c == 200, "1 editar o rascunho (PUT, sem reenviar o CPF)", r)
    c, r = j("solicitante2", "PUT", f"/api/investigacoes/{A}", json=corpo)
    checar(c == 404 and r.get("erro") == "sem_acesso", "1 só o solicitante edita (outro: 404 sem_acesso)", c)
    c, inex = j("solicitante1", "GET", "/api/investigacoes/999999")
    checar(c == 404 and inex == {"erro": r.get("erro"), "mensagem": r.get("mensagem")},
           "1 inexistente e sem vínculo: a mesma resposta 404")
    for q in ("0001234-56.2026.6.05.0001", "00012345620266050001", "0001234 56.2026/6 05 0001", str(A)):
        c, l = j("solicitante1", "GET", "/api/investigacoes", params={"q": q})
        if not checar(c == 200 and [i["id"] for i in l["itens"]] == [A], f"1 busca tolerante q={q!r}",
                      f"{l.get('total') if isinstance(l, dict) else l}"):
            break
    cols = {r["column_name"] for r in banco().execute("SELECT column_name FROM information_schema.columns WHERE "
                                                      "table_name='investigacao'")}
    pc = banco().execute("SELECT processo_cifrado, processo_hmac FROM investigacao WHERE id=%s", (A,)).fetchone()
    checar("processo" not in cols and b"0001234" not in bytes(pc["processo_cifrado"]) and len(pc["processo_hmac"]) == 64
           and st("solicitante1", A)["processo"] == corpo["processo"] and st("auditor1", A).get("processo") is None,
           "1 processo cifrado com a DEK (busca pelo HMAC); só quem lê vê o processo")
    checar(j("auditor1", "GET", "/api/investigacoes", params={"q": corpo["processo"]})[1]["total"] == 0,
           "1 auditor interno não busca pelo processo")
    c, d = j("solicitante1", "GET", "/api/instancias/disponiveis")
    checar(c == 200 and {x["nome"] for x in d} == {"kc26", "rhsso"} and "intranet" in next(
        x["realms"] for x in d if x["nome"] == "kc26") and all(set(x) == {"nome", "realms"} for x in d) and
           j("admin1", "GET", "/api/instancias/disponiveis")[0] == 403,
           "1 instâncias disponíveis para o assistente (sem URL, segredo nem orçamento)", d)
    c, l = j("solicitante1", "GET", "/api/investigacoes", params={"q": "99999999"})
    checar(c == 200 and l["total"] == 0 and set(l) == {"itens", "total", "pagina", "por_pagina"},
           "1 lista paginada {itens, total, pagina, por_pagina}")
    c, r = j("solicitante1", "POST", f"/api/investigacoes/{A}/enviar")
    checar(c == 200 and r["status"] == "aguardando_aprovacao", "1 enviar o rascunho", r)
    checar(any(n["investigacao"] == A for n in notif("aprovador1", "pedido_recebido")),
           "1 aprovador notificado do pedido recebido")
    ac = {u: acoes(u, A) for u in ("solicitante1", "aprovador1", "auditor1", "investigador1", "admin1")}
    checar(ac["solicitante1"] == ["cancelar"] and ac["aprovador1"] == ["aprovar", "devolver", "recusar"] and
           ac["auditor1"] == [] and ac["investigador1"] == 404 and ac["admin1"] == 403,
           "1 acoes no aguardando: solicitante cancela; aprovador aprova/devolve/recusa; auditor nada", ac)
    c, l = j("aprovador1", "GET", "/api/investigacoes", params={"visao": "aguardando"})
    checar(A in [i["id"] for i in l["itens"]], "1 visao=aguardando do aprovador")
    c, ini = j("aprovador1", "GET", "/api/inicio")
    checar(c == 200 and any(x["investigacao"] == A and x["tipo"] == "investigacao" for x in
                            ini["aguardando_minha_decisao"]) and ini["nao_lidas"] >= 1,
           "1 início do aprovador: aguardando minha decisão e não lidas", f"{len(ini.get('aguardando_minha_decisao', []))}")
    c, r = j("aprovador2", "POST", f"/api/investigacoes/{A}/devolver", json={"motivo": "Falta o fundamento legal"})
    checar(c == 200 and r["status"] == "devolvida", "1 devolver", r)
    checar(any(n["investigacao"] == A for n in notif("solicitante1", "pedido_devolvido")),
           "1 solicitante notificado da devolução")
    checar(acoes("solicitante1", A) == ["editar", "cancelar", "reenviar"], "1 devolvida: solicitante edita, "
           "reenvia ou cancela", acoes("solicitante1", A))
    lt = st("solicitante1", A)["linha_do_tempo"]
    lta = st("auditor1", A)["linha_do_tempo"]
    dv = [x for x in lt if x["status"] == "devolvida"]
    checar(dv and dv[-1].get("motivo") == "Falta o fundamento legal" and dv[-1]["por"] == "aprovador2" and
           [x["status"] for x in lt][:3] == ["rascunho", "aguardando_aprovacao", "devolvida"] and
           all("motivo" not in x for x in lta), "1 linha do tempo: motivo para o solicitante, nunca para o auditor",
           [x["status"] for x in lt])
    c, ap = j("aprovador1", "GET", "/api/aprovacoes")
    it = next((x for x in ap if x["investigacao"] == A), {}) if c == 200 else {}
    c2, el = j("aprovador1", "GET", f"/api/investigacoes/{A}/investigadores-elegiveis")
    checar(c2 == 404, "1 elegíveis: só para o aprovador que decide (devolvida: 404)", c2)
    c, r = j("solicitante1", "POST", f"/api/investigacoes/{A}/reenviar", json={"motivo": "Fundamento incluído"})
    c, ap = j("aprovador1", "GET", "/api/aprovacoes")
    it = next((x for x in ap if x["investigacao"] == A), {})
    checar(it.get("risco_expiracao") is True and it["realm_critico"]["realm"] == "servicos" and it.get("prazo") and
           it.get("escalonado") is False, "1 aprovações: prazo, escalonado e risco de expiração (realm mais crítico)",
           it.get("realm_critico"))
    c, el = j("aprovador1", "GET", f"/api/investigacoes/{A}/investigadores-elegiveis")
    nomes_el = {x["username"] for x in el} if c == 200 else set()
    checar(c == 200 and {"investigador1", "investigador2"} <= nomes_el and "aprovador1" not in nomes_el and
           "solicitante1" not in nomes_el and set(el[0]) == {"username", "nome", "unidade"} and
           j("solicitante2", "GET", f"/api/investigacoes/{A}/investigadores-elegiveis")[0] == 403,
           "1 investigadores elegíveis (sem o solicitante e o próprio aprovador)", sorted(nomes_el))
    checar(c == 200, "1 reenviar", r)
    c, r = j("aprovador1", "POST", f"/api/investigacoes/{A}/aprovar", json={"investigador": "investigador1",
                                                                           "motivo": "Pedido fundamentado"})
    checar(c == 200 and r["status"] == "aprovada", "1 aprovar (designa investigador1)", r)
    checar(acoes("investigador1", A) == ["iniciar"] and acoes("solicitante1", A) == [] and
           acoes("aprovador1", A) == [], "1 aprovada: só o investigador inicia", acoes("investigador1", A))
    v = st("aprovador1", A)
    checar(v["expiracao"] and v["estimativa"]["tarefas"] > 0 and v["documento"] is None and v["preservacao"] is None,
           "1 detalhe: expiração, estimativa, documento e preservação", v["estimativa"])

    # ================================================================ 1b. coleta 180 dias + SSE
    ouv = Ouvinte("investigador1", A, duracao=600)
    ouv.start()
    ouv.aberto.wait(10)
    c, r = j("investigador1", "POST", f"/api/investigacoes/{A}/iniciar")
    checar(c == 200, "1 iniciar a coleta", r)
    ok = esperar(lambda: (lambda a: a if a["status"] == "coletando" and 5 <= a["progresso_pct"] < 80 else None)(
        j("investigador1", "GET", f"/api/investigacoes/{A}/acompanhamento")[1]), limite=300, passo=1)
    checar(bool(ok), "1 coletando (acompanhamento JSON)", ok and ok["progresso_pct"])
    c, r = j("investigador1", "POST", f"/api/investigacoes/{A}/pausar")
    checar(c == 200 and acoes("investigador1", A) == ["cancelar", "retomar"], "1 pausar (ações: retomar, cancelar)",
           acoes("investigador1", A))
    time.sleep(4)
    a1 = j("investigador1", "GET", f"/api/investigacoes/{A}/acompanhamento")[1]
    time.sleep(5)
    a2 = j("investigador1", "GET", f"/api/investigacoes/{A}/acompanhamento")[1]
    checar(a1["status"] == a2["status"] == "pausada" and a1["progresso_pct"] == a2["progresso_pct"] < 100,
           "1 pausada: a coleta para", f"{a1['progresso_pct']}% e {a2['progresso_pct']}%")
    c, r = j("investigador1", "POST", f"/api/investigacoes/{A}/retomar")
    checar(c == 200, "1 retomar", r)
    fim = esperar(lambda: st("investigador1", A)["status"] in ("concluida", "concluida_com_lacunas") or None,
                  limite=900)
    v = st("investigador1", A)
    checar(bool(fim), "1 investigação de 180 dias concluída só pela API (kc26 e kc18)", v["status"])
    ac = j("investigador1", "GET", f"/api/investigacoes/{A}/acompanhamento")[1]
    insts = {x["nome"]: x for x in ac["instancias"]}
    checar(set(insts) == {"kc26", "rhsso"} and all(x["tarefas"]["concluida"] > 0 for x in insts.values()) and
           ac["progresso_pct"] == 100 and ac["eventos"] > 0, "1 acompanhamento: as duas instâncias, 100%, eventos",
           {k: x["tarefas"] for k, x in insts.items()})
    checar(v["acoes"] == ["gerar_pacote", "pedir_sem_mascara"], "1 concluída: investigador gera pacote", v["acoes"])
    checar(esperar(lambda: any(n["investigacao"] == A for n in notif("solicitante1", "coleta_concluida")) and
                   any(n["investigacao"] == A for n in notif("investigador1", "coleta_concluida")), 20, 1),
           "1 coleta concluída notificada ao solicitante e ao investigador")
    sts = [x["status"] for x in v["linha_do_tempo"]]
    checar(all(s in sts for s in ("aprovada", "preparando", "coletando", "pausada")) and sts[-1] == v["status"],
           "1 linha do tempo até a conclusão", sts)
    time.sleep(2)
    ouv.parar.set()
    ouv.join(30)
    pr = ouv.progresso()
    ids = [e[1] for e in pr]
    checar(ouv.status == 200 and len(pr) >= 3 and ids == sorted(set(ids)) and
           pr[-1][2]["status"] in ("concluida", "concluida_com_lacunas") and
           {"status", "progresso_pct", "eventos", "instancias", "falhas", "retentativas", "termino_estimado"}
           <= set(pr[-1][2]), "5 SSE: eventos de progresso com id crescente até a conclusão",
           f"{len(pr)} eventos, ids {ids[:3]}…{ids[-2:]}")
    # heartbeat, limite de conexões, Last-Event-ID
    hb = Ouvinte("investigador1", A, ultimo_id=1000, duracao=25, ate_heartbeat=True)
    outros = [Ouvinte("investigador1", A, duracao=25, ate_heartbeat=True) for _ in range(2)]
    for o in [hb, *outros]:
        o.start()
        o.aberto.wait(10)
    time.sleep(1)
    quarta = req("investigador1", "GET", f"/api/investigacoes/{A}/acompanhamento/stream")
    checar(quarta.status_code == 429 and quarta.json().get("erro") == "limite_conexoes",
           "5 SSE: a 4ª conexão do mesmo usuário recebe 429", quarta.status_code)
    hb.join(30)
    checar(any(e[0] == "heartbeat" for e in hb.eventos), "5 SSE: heartbeat em 15 s", [e[0] for e in hb.eventos])
    checar(hb.progresso() and hb.progresso()[0][1] > 1000, "5 SSE: reconexão com Last-Event-ID recebe id maior",
           hb.progresso()[0][1] if hb.progresso() else None)
    for o in outros:
        o.join(30)
    checar(req("solicitante2", "GET", f"/api/investigacoes/{A}/acompanhamento/stream").status_code == 404 and
           req("auditor1", "GET", f"/api/investigacoes/{A}/acompanhamento").status_code in (403, 404),
           "5 SSE: designação conferida ao abrir o stream")
    dep = Ouvinte("investigador1", A, duracao=3)   # as 3 conexões foram liberadas
    dep.start()
    dep.join(20)
    checar(dep.status == 200, "5 SSE: conexões liberadas ao fechar", dep.status)

    # ================================================================ 2. rascunho descartado
    c, r = j("solicitante1", "POST", "/api/investigacoes", json={**corpo, "processo": None, "rascunho": True})
    D = r["investigacao"]
    c, r = j("solicitante1", "DELETE", f"/api/investigacoes/{D}")
    k = banco().execute("SELECT count(*) n FROM chave_investigacao WHERE investigacao_id=%s AND destruida_em IS NOT "
                        "NULL AND length(envelope)=0", (D,)).fetchone()["n"]
    checar(c == 200 and j("solicitante1", "GET", f"/api/investigacoes/{D}")[0] == 404 and k == 2,
           "2 descartar o rascunho: some e as DEKs são destruídas", f"{c} {k}")

    # ================================================================ 3. pedido externo e documento
    ext = {**corpo, "rascunho": False, "processo": None, "justificativa": "Ofício 77/2026 da PF (teste W2)",
           "origem": {"orgao": "Polícia Federal", "documento": "Ofício 77/2026", "fundamento": "Requisição em IPL",
                      "processo": "IPL 9/2026", "destinatario": "Delegado"}}
    c, r = j("investigador2", "POST", "/api/investigacoes", json=ext)
    checar(c == 422 and r.get("erro") == "documento", "3 pedido externo sem documento é recusado no envio direto", c)
    c, r = j("investigador2", "POST", "/api/investigacoes", json={**ext, "rascunho": True})
    E = r["investigacao"]
    c, r = j("investigador2", "POST", f"/api/investigacoes/{E}/enviar")
    checar(c == 422 and r.get("erro") == "documento", "3 enviar sem o documento de origem: 422", c)
    marca = f"OFICIO-SIGILOSO-{os.getpid()}".encode()
    pdf = b"%PDF-1.4\n" + marca + b" CPF " + ALVO.encode() + b"\n%%EOF"
    c, r = j("investigador2", "POST", f"/api/investigacoes/{E}/documento",
             files={"arquivo": ("oficio_77-2026.pdf", pdf, "application/pdf")})
    import hashlib
    sha = hashlib.sha256(pdf).hexdigest()
    checar(c == 201 and r.get("sha256") == sha and r.get("tamanho") == len(pdf),
           "3 documento de origem enviado (multipart)", r)
    d = banco().execute("SELECT * FROM documento WHERE investigacao_id=%s", (E,)).fetchone()
    cru = bytes(d["cifrado"]) + bytes(d["meta_cifrado"])
    checar(marca not in cru and ALVO.encode() not in cru and b"%PDF" not in cru and b"oficio_77" not in cru
           and d["sha256"] == sha,
           "3 documento cifrado no banco: os bytes não aparecem em claro (nem o nome)")
    tr = banco().execute("SELECT detalhe FROM trilha_auditoria WHERE cadeia=%s AND acao='anexar_documento'",
                         (E,)).fetchone()
    checar(tr and tr["detalhe"]["sha256"] == sha, "3 SHA-256 do documento na trilha")
    c1 = req("investigador2", "POST", f"/api/investigacoes/{E}/documento",
             files={"arquivo": ("x.txt", b"texto qualquer")}).status_code
    c2 = req("investigador2", "POST", f"/api/investigacoes/{E}/documento",
             files={"arquivo": ("g.pdf", b"%PDF-" + b"0" * (10 * 1024 * 1024 + 10))}).status_code
    checar(c1 == 415 and c2 == 413, "3 documento: só PDF/imagem, até 10 MB", f"{c1} {c2}")
    c, r = j("investigador2", "POST", f"/api/investigacoes/{E}/enviar")
    checar(c == 200, "3 enviar com o documento", r)
    checar("baixar_documento" in acoes("aprovador2", E), "3 acoes do aprovador da fila: baixar_documento")
    r = req("aprovador2", "GET", f"/api/investigacoes/{E}/documento")
    checar(r.status_code == 200 and r.content == pdf and r.headers.get("x-conteudo-sha256") == sha,
           "3 aprovador da fila baixa o documento", r.status_code)
    cs = {u: req(u, "GET", f"/api/investigacoes/{E}/documento").status_code
          for u in ("auditor1", "solicitante2", "investigador1")}
    checar(all(x in (403, 404) for x in cs.values()), "3 auditor interno e não designados não baixam o documento", cs)
    v = st("aprovador2", E)
    checar(v["documento"] and v["documento"]["sha256"] == sha and v["documento"]["nome"] == "oficio_77-2026.pdf"
           and st("auditor1", E).get("documento", {}).get("nome") is None,
           "3 detalhe: documento (nome só para quem decifra)")
    c, r = j("aprovador2", "POST", f"/api/investigacoes/{E}/aprovar", json={"investigador": "investigador2",
                                                                           "motivo": "Ofício conferido"})
    checar(c == 200 and req("investigador2", "GET", f"/api/investigacoes/{E}/documento").status_code == 200,
           "3 investigador designado baixa o documento", c)
    checar(banco().execute("SELECT count(*) n FROM trilha_auditoria WHERE cadeia=%s AND acao='baixar_documento'",
                           (E,)).fetchone()["n"] == 2, "3 cada download do documento vai para a trilha")

    # ================================================================ 4. preservação urgente
    de3 = (ate - timedelta(days=2)).isoformat()
    pu = {**corpo, "de": de3, "instancias": ["kc26"], "rascunho": False, "processo": None,
          "preservacao_urgente": True, "justificativa": "Preservação: eventos expiram (teste W2)"}
    informada = next(c_ for c_ in json.loads((RAIZ / "dados/pessoas.json").read_text())["contas"]
                     if c_["instancia"] == "kc26" and c_["realm"] == "intranet")
    c, r = j("solicitante1", "POST", "/api/investigacoes", json={**pu, "contas_informadas": [
        {"instancia": "kc26", "realm": "intranet", "username": informada["username"]}]})
    P = r["investigacao"]
    checar(st("solicitante1", P).get("contas_informadas") == 1 and informada["username"].encode() not in bytes(
        banco().execute("SELECT contas_cifradas FROM investigacao WHERE id=%s", (P,)).fetchone()["contas_cifradas"]),
           "4 contas informadas no pedido, cifradas com a DEK")
    c, ini = j("aprovador1", "GET", "/api/inicio")
    checar(any(x["investigacao"] == P and x["tipo"] == "preservacao_urgente" for x in ini["aguardando_minha_decisao"]),
           "4 preservação urgente na fila com tipo=preservacao_urgente")
    checar(acoes("aprovador1", P) == ["aprovar", "devolver", "recusar", "autorizar_preservacao"],
           "4 acoes do aprovador: autorizar_preservacao", acoes("aprovador1", P))
    c, r = j("solicitante1", "POST", f"/api/investigacoes/{P}/autorizar-preservacao",
             json={"investigador": "investigador1", "motivo": "Eu mesmo autorizo"})
    checar(c == 403, "4 quem pediu não autoriza a preservação", c)
    c, r = j("aprovador1", "POST", f"/api/investigacoes/{P}/autorizar-preservacao",
             json={"investigador": "investigador1", "motivo": "Eventos expiram em 2 dias"})
    checar(c == 200 and r["status"] == "preservacao_urgente" and r["destroi_em"] > r["escalona_em"],
           "4 autorizar a preservação: coleta lacrada", r)
    v = st("aprovador1", P)
    checar(v["status"] == "preservacao_urgente" and v["preservacao"] and not v["preservacao"]["prorrogada"],
           "4 detalhe: estado preservacao_urgente e prazos", v["preservacao"])
    esperar(lambda: st("investigador1", P)["status_interno"] in ("concluida", "concluida_com_lacunas") or None, 300)
    v = st("investigador1", P)
    checar(v["status"] == "preservacao_urgente" and v["status_interno"] in ("concluida", "concluida_com_lacunas"),
           "4 coleta lacrada roda até o fim e continua lacrada", v["status_interno"])
    lac = {f"{mt} {cam}": req("investigador1", mt, cam, json=b).status_code for mt, cam, b in (
        ("GET", f"/api/investigacoes/{P}/pacotes", None), ("POST", f"/api/investigacoes/{P}/pacotes",
                                                          {"sem_mascara": False}),
        ("POST", f"/api/investigacoes/{P}/pausar", None), ("POST", f"/api/investigacoes/{P}/iniciar", None))}
    r = req("investigador1", "GET", f"/api/investigacoes/{P}/pacotes")
    checar(all(x == 409 for x in lac.values()) and r.json().get("erro") == "lacrada",
           "4 lacrada: rotas de dados e pacote respondem 409 lacrada", lac)
    checar(acoes("investigador1", P) == [] and "prorrogar_preservacao" in acoes("coordenador1", P) and
           "prorrogar_preservacao" not in acoes("aprovador2", P), "4 acoes na lacrada: investigador nada; só a "
           "coordenação prorroga", {u: acoes(u, P) for u in ("investigador1", "coordenador1", "aprovador2")})
    # relógio simulado: 3 dias úteis → escalonamento ao coordenador
    from auditor import gestao
    p = banco().execute("SELECT * FROM preservacao WHERE investigacao_id=%s", (P,)).fetchone()
    with banco() as cx:
        f1 = gestao.vencer_prazos(cx, p["escalona_em"] - timedelta(minutes=1))
        f2 = gestao.vencer_prazos(cx, p["escalona_em"] + timedelta(minutes=1))
    checar(P not in f1["escalonadas"] and P in f2["escalonadas"] and
           any(n["investigacao"] == P for n in notif("coordenador1", "preservacao_expira")),
           "4 prazo (relógio simulado): escalonamento ao coordenador em 3 dias úteis", f2)
    c, r = j("aprovador2", "POST", f"/api/investigacoes/{P}/prorrogar-preservacao", json={"motivo": "Mais prazo"})
    checar(c == 403, "4 só a coordenação prorroga", c)
    c, r = j("coordenador1", "POST", f"/api/investigacoes/{P}/prorrogar-preservacao",
             json={"motivo": "Aguardando o processo"})
    c2, r2 = j("coordenador1", "POST", f"/api/investigacoes/{P}/prorrogar-preservacao",
               json={"motivo": "De novo, por favor"})
    p2 = banco().execute("SELECT * FROM preservacao WHERE investigacao_id=%s", (P,)).fetchone()
    checar(c == 200 and c2 == 409 and p2["destroi_em"] == gestao.somar_dias_uteis(p["destroi_em"], 10),
           "4 prorrogação única (+10 dias úteis)", f"{c} {c2}")
    with banco() as cx:
        f3 = gestao.vencer_prazos(cx, p["destroi_em"] + timedelta(hours=1))
    checar(P not in f3["destruidas"], "4 prorrogada: não destrói no 5º dia útil")
    c, r = j("aprovador2", "POST", f"/api/investigacoes/{P}/aprovar", json={"investigador": "investigador1",
                                                                           "motivo": "Pedido completo conferido"})
    checar(c == 200 and r["status"] in ("concluida", "concluida_com_lacunas"), "4 aprovar o pedido completo libera",
           r)
    checar(req("investigador1", "GET", f"/api/investigacoes/{P}/pacotes").status_code == 200 and
           "gerar_pacote" in acoes("investigador1", P), "4 depois da aprovação, rotas de dados abrem")
    n_inf = banco().execute("SELECT count(*) n FROM conta WHERE investigacao_id=%s AND via='informada'",
                            (P,)).fetchone()["n"]
    checar(n_inf == 1, "4 a conta informada (username) entrou no preparo", n_inf)
    c, r = j("investigador1", "POST", f"/api/investigacoes/{P}/pacotes", json={"sem_mascara": False})
    pk = r.get("pacote")
    pronto = esperar(lambda: any(x["pacote"] == pk and x["status"] == "pronto" for x in
                                 j("investigador1", "GET", f"/api/investigacoes/{P}/pacotes")[1]), 300, 2)
    c, lk = j("investigador1", "POST", f"/api/pacotes/{pk}/link")
    with banco() as cx:
        cx.execute("UPDATE link_download SET expira_em=now() - interval '1 minute' WHERE pacote_id=%s", (pk,))
    r = req("investigador1", "GET", lk.get("link", "/x"))
    checar(bool(pronto) and r.status_code == 410 and r.json().get("erro") == "expirado",
           "4 link expirado responde 410 expirado", r.status_code)
    # recusada → DEK destruída
    c, r = j("solicitante1", "POST", "/api/investigacoes", json={**pu, "justificativa": "Preservação a recusar"})
    R = r["investigacao"]
    j("aprovador1", "POST", f"/api/investigacoes/{R}/autorizar-preservacao",
      json={"investigador": "investigador1", "motivo": "Urgente, autorizo a coleta"})
    c, r = j("aprovador1", "POST", f"/api/investigacoes/{R}/devolver", json={"motivo": "Devolver não cabe"})
    checar(c == 409, "4 lacrada: devolver não cabe (só aprovar ou recusar)", c)
    c, r = j("aprovador2", "POST", f"/api/investigacoes/{R}/recusar", json={"motivo": "Sem fundamento para preservar"})
    k = banco().execute("SELECT count(*) n FROM chave_investigacao WHERE investigacao_id=%s AND destruida_em IS NOT NULL"
                        " AND length(envelope)=0", (R,)).fetchone()["n"]
    tr = banco().execute("SELECT detalhe FROM trilha_auditoria WHERE cadeia=%s AND acao='destruir_dek'",
                         (R,)).fetchone()
    v = st("solicitante1", R)
    checar(c == 200 and k == 2 and tr and tr["detalhe"]["fundamento"].startswith("recusa") and
           v["status"] == "recusada" and "justificativa" not in v, "4 recusar a preservação destrói a DEK (trilha com "
           "o fundamento)", f"{c} {k}")
    # sem decisão em 5 dias úteis → DEK destruída
    c, r = j("solicitante1", "POST", "/api/investigacoes", json={**pu, "justificativa": "Preservação que expira"})
    X = r["investigacao"]
    j("aprovador1", "POST", f"/api/investigacoes/{X}/autorizar-preservacao",
      json={"investigador": "investigador1", "motivo": "Urgente, autorizo a coleta"})
    p = banco().execute("SELECT * FROM preservacao WHERE investigacao_id=%s", (X,)).fetchone()
    with banco() as cx:
        f4 = gestao.vencer_prazos(cx, p["destroi_em"] + timedelta(minutes=1))
    k = banco().execute("SELECT count(*) n FROM chave_investigacao WHERE investigacao_id=%s AND destruida_em IS NOT "
                        "NULL", (X,)).fetchone()["n"]
    ped = banco().execute("SELECT status FROM pedido WHERE investigacao_id=%s", (X,)).fetchone()["status"]
    checar(X in f4["destruidas"] and k == 2 and ped == "expirado" and st("solicitante1", X)["status"] == "recusada",
           "4 sem decisão em 5 dias úteis (relógio simulado): DEK destruída", f"{k} {ped}")

    # ================================================================ 6. notificações e pedir-acesso
    ns = j("solicitante1", "GET", "/api/notificacoes")[1]
    checar(ns and {"id", "tipo", "texto", "investigacao", "quando", "lida"} <= set(ns[0]),
           "6 notificações: forma do contrato", len(ns))
    nid = ns[0]["id"]
    c, _ = j("solicitante1", "POST", f"/api/notificacoes/{nid}/lida")
    checar(c == 200 and all(n["id"] != nid for n in notif("solicitante1")), "6 marcar uma como lida")
    c, _ = j("solicitante1", "POST", "/api/notificacoes/lidas")
    checar(c == 200 and notif("solicitante1") == [] and j("solicitante1", "GET", "/api/inicio")[1]["nao_lidas"] == 0,
           "6 marcar todas como lidas")
    checar(j("solicitante2", "POST", f"/api/notificacoes/{nid}/lida")[0] == 404, "6 notificação de outro: 404")
    em = [json.loads(x) for x in EMAIL.read_text().splitlines()] if EMAIL.exists() else []
    txt = EMAIL.read_text() if EMAIL.exists() else ""
    checar(len(em) > 5 and ALVO not in txt and "***" not in txt and "fundamento" not in txt.lower()
           and "Falta o" not in txt, "6 e-mail só em logs/email.jsonl, sem dado pessoal nem alvo mascarado",
           f"{len(em)} e-mails")
    r1 = req("solicitante2", "POST", f"/api/investigacoes/{A}/pedir-acesso", json={"motivo": "Preciso acompanhar"})
    r2 = req("solicitante2", "POST", "/api/investigacoes/987654/pedir-acesso", json={"motivo": "Preciso acompanhar"})
    n = banco().execute("SELECT count(*) n FROM trilha_auditoria WHERE cadeia=0 AND acao='pedir_acesso'").fetchone()["n"]
    checar(r1.status_code == r2.status_code == 202 and r1.content == r2.content and n >= 2,
           "6 pedir-acesso: 202 igual para existente e inexistente, na trilha global", f"{r1.status_code} {n}")

    # ================================================================ 7. substituto e escalonamento
    c, r = j("aprovador1", "PUT", "/api/substitutos/eu", json={"substituto": "solicitante1"})
    checar(c == 422, "7 substituto precisa ser aprovador", c)
    c, r = j("aprovador1", "PUT", "/api/substitutos/eu", json={"substituto": "aprovador2"})
    c2, l = j("aprovador2", "GET", "/api/substitutos")
    checar(c == 200 and any(x["aprovador"] == "aprovador1" and x["substituto"] == "aprovador2" for x in l) and
           any(x["aprovador"] == "aprovador2" and x["substituto"] is None for x in l),
           "7 aprovador define o substituto; a lista traz todos os aprovadores", l)
    checar(j("solicitante1", "PUT", "/api/substitutos/eu", json={"substituto": "aprovador2"})[0] == 403,
           "7 só aprovador define substituto")
    c, r = j("solicitante1", "POST", "/api/investigacoes", json={**pu, "preservacao_urgente": False,
                                                                 "justificativa": "Pedido que fica parado"})
    S = r["investigacao"]
    ped = banco().execute("SELECT * FROM pedido WHERE investigacao_id=%s", (S,)).fetchone()
    j("aprovador2", "POST", "/api/notificacoes/lidas")
    j("coordenador1", "POST", "/api/notificacoes/lidas")
    with banco() as cx:
        e0 = gestao.vencer_prazos(cx, ped["criado_em"] + timedelta(hours=1))
        e1 = gestao.vencer_prazos(cx, gestao.somar_dias_uteis(ped["criado_em"], 1) + timedelta(minutes=1))
    n_sub = [n for n in notif("aprovador2", "escalonamento") if n["investigacao"] == S]
    checar((ped["id"], 1) not in e0["pedidos"] and (ped["id"], 1) in e1["pedidos"] and n_sub and
           not [n for n in notif("coordenador1", "escalonamento") if n["investigacao"] == S],
           "7 pedido parado há 1 dia útil escalona ao substituto (relógio simulado)", e1["pedidos"])
    with banco() as cx:
        e2 = gestao.vencer_prazos(cx, gestao.somar_dias_uteis(ped["criado_em"], 2) + timedelta(minutes=1))
    checar((ped["id"], 2) in e2["pedidos"] and [n for n in notif("coordenador1", "escalonamento")
                                                if n["investigacao"] == S], "7 depois, ao coordenador", e2["pedidos"])
    c, ini = j("aprovador1", "GET", "/api/inicio")
    checar(any(x["investigacao"] == S and x["escalonado"] for x in ini["aguardando_minha_decisao"]),
           "7 início: pedido marcado como escalonado")
    checar(any(a["tipo"] == "escalonamento" for a in j("aprovador2", "GET", "/api/inicio")[1]["alertas"]),
           "7 início: alerta de escalonamento")
    j("solicitante1", "POST", f"/api/investigacoes/{S}/cancelar", json={"motivo": "Não precisa mais"})

    # ================================================================ 8. perfis, recertificação e vigia
    c, pf = j("gestor1", "GET", "/api/perfis")
    us = {x["username"]: x for x in pf} if c == 200 else {}
    checar(c == 200 and us.get("aprovador1", {}).get("papeis") == ["aprovador"] and us["coordenador1"]["coordenador"]
           and {"username", "nome", "unidade", "papeis", "ultimo_login", "recertificado_em"} <= set(us["aprovador1"]),
           "8 perfis lidos do realm pela conta de serviço kc-auditor-gestao", f"{len(us)} usuários")
    checar(j("aprovador1", "GET", "/api/perfis")[0] == 403 and j("admin1", "GET", "/api/perfis")[0] == 403,
           "8 só o gestor de acesso vê os perfis")
    j("auditor1", "POST", "/api/notificacoes/lidas")
    c, r = j("gestor1", "POST", "/api/perfis/w2teste1/papeis", json={"conceder": ["solicitante"],
                                                                     "motivo": "Novo servidor da unidade"})
    checar(c == 200 and m.papeis("w2teste1") == ["solicitante"], "8 conceder papel pelo Keycloak Admin", r)
    checar(any("w2teste1" in n["texto"] for n in notif("auditor1", "papel_alterado")),
           "8 concessão gera alerta (notificação) ao auditor interno")
    c, r = j("gestor1", "POST", "/api/perfis/w2teste1/papeis", json={"conceder": ["admin_tecnico"],
                                                                     "motivo": "Combinação que não pode"})
    checar(c == 422 and r.get("erro") == "combinacao_proibida" and m.papeis("w2teste1") == ["solicitante"],
           "8 combinação proibida recusada antes de chamar o Keycloak", r.get("erro"))
    c, r = j("gestor1", "POST", "/api/perfis/gestor1/papeis", json={"conceder": ["auditor_interno"],
                                                                    "motivo": "Para mim mesmo"})
    checar(c in (403, 422), "8 gestor não altera os próprios perfis", c)
    checar(j("aprovador1", "POST", "/api/perfis/w2teste1/papeis", json={"revogar": ["solicitante"],
                                                                        "motivo": "Sem perfil"})[0] == 403,
           "8 só o gestor de acesso concede/revoga")
    c, r = j("gestor1", "POST", "/api/perfis/w2teste1/papeis", json={"revogar": ["solicitante"],
                                                                     "motivo": "Saiu da unidade"})
    checar(c == 200 and m.papeis("w2teste1") == [], "8 revogar papel", r)
    siem = [json.loads(x) for x in SIEM.read_text().splitlines()]
    checar(sum(1 for e in siem if e["acao"] == "mudanca_de_papel" and e.get("motivo_codigo") == "api") >= 2,
           "8 concessão/revogação no SIEM (whitelist)")
    # recertificação confirmada (revoga) e vencida (revoga o que não foi confirmado)
    m.mudar("w2teste1", conceder=["solicitante"])
    m.mudar("w2teste2", conceder=["investigador"])
    time.sleep(8)   # o vigia registra (e alerta) a concessão feita direto no Keycloak
    c, r = j("gestor1", "POST", "/api/recertificacoes", json={"usuarios": list(TESTE_U), "prazo_dias": 30})
    rid = r.get("id")
    checar(c == 201 and len(r["itens"]) == 2 and {x["username"] for x in r["pendentes"]} == set(TESTE_U) and
           r.get("criada_em") and r.get("prazo") and r.get("concluida_em") is None, "8 abrir recertificação", r)
    c, r = j("gestor1", "POST", f"/api/recertificacoes/{rid}/confirmar", json={"username": "w2teste1",
                                                                               "manter": False})
    checar(c == 200 and m.papeis("w2teste1") == [], "8 recertificação não confirmada (manter=false) revoga", r)
    from auditor import kc_gestao
    with banco() as cx:
        cx.execute("UPDATE recertificacao SET prazo=now() - interval '1 minute' WHERE id=%s", (rid,))
    with banco() as cx:
        venc = kc_gestao.vencer_recertificacoes(cx)
    lr = j("gestor1", "GET", "/api/recertificacoes")[1]
    checar(rid in venc and m.papeis("w2teste2") == [] and lr[0]["concluida_em"] and not lr[0]["pendentes"] and
           all(x["manter"] is False for x in lr[0]["itens"]), "8 recertificação vencida: o não confirmado é revogado",
           m.papeis("w2teste2"))
    # vigia: papel alterado direto no console do Keycloak
    time.sleep(8)
    j("auditor1", "POST", "/api/notificacoes/lidas")
    m.mudar("w2teste1", conceder=["aprovador"])
    alerta = esperar(lambda: [n for n in notif("auditor1", "papel_alterado") if "w2teste1" in n["texto"]
                              and "Keycloak" in n["texto"]], limite=40, passo=2)
    checar(bool(alerta) and "+aprovador" in alerta[0]["texto"], "8 vigia: papel concedido direto no Keycloak gera "
           "alerta ao auditor interno", alerta and alerta[0]["texto"])
    siem = [json.loads(x) for x in SIEM.read_text().splitlines()]
    checar(any(e["acao"] == "mudanca_de_papel" and e.get("motivo_codigo") == "console" for e in siem),
           "8 vigia: alerta no SIEM")
    m.mudar("w2teste1", revogar=["aprovador"])
    alerta = esperar(lambda: [n for n in notif("auditor1", "papel_alterado") if "-aprovador" in n["texto"]],
                     limite=40, passo=2)
    checar(bool(alerta), "8 vigia: revogação direta também alerta")

    # ================================================================ 9. administração, SPA, erros
    c, s = j("admin1", "GET", "/api/servicos/saude")
    checar(c == 200 and set(s["filas"]) == {"tarefas", "jobs"} and set(s["filas"]["tarefas"]) == {
        "pendente", "executando", "falhou"} and s["workers"] and s["workers"][0]["papel"] == "todos",
           "9 saúde: filas e workers", s.get("workers", [])[:1])
    c, r = j("admin1", "POST", "/api/instancias/kc26/testar")
    c2, _ = j("admin1", "POST", "/api/instancias/naoexiste/testar")
    checar(c == 200 and r["ok"] is True and "ok" in r["texto"] and c2 == 404 and j("investigador1", "POST", "/api/instancias/kc26/testar")[0]
           == 403, "9 testar conexão da instância (sem sondas)", r)
    r = httpx.get(f"{API}/", trust_env=False)
    checar(r.status_code == 503 and "npm run build" in r.text and "unsafe-inline" not in
           r.headers.get("content-security-policy", "x"), "9 sem web/dist: / responde 503 com o texto", r.status_code)
    checar(httpx.get(f"{API}/api/naoexiste", trust_env=False).status_code in (401, 404),
           "9 /api desconhecida não cai na SPA")
    from fastapi.testclient import TestClient

    from auditor import api as api_mod
    dist = Path(tempfile.mkdtemp(prefix="dist_"))
    (dist / "assets").mkdir()
    (dist / "index.html").write_text("<!doctype html><title>kc-auditor</title><script src='/assets/a1.js'></script>")
    (dist / "assets" / "a1.js").write_text("console.log(1)")
    os.environ["AUDITOR_WEB_DIST"] = str(dist)
    tc = TestClient(api_mod.app, raise_server_exceptions=False)
    r1, r2, r3 = tc.get("/"), tc.get("/investigacoes/7"), tc.get("/assets/a1.js")
    csp = r1.headers.get("content-security-policy", "")
    checar(r1.status_code == r2.status_code == r3.status_code == 200 and "kc-auditor" in r2.text and
           "immutable" in r3.headers.get("cache-control", "") and r1.headers["cache-control"] == "no-store" and
           "default-src 'self'" in csp and "unsafe-inline" not in csp and tc.get("/../etc/passwd").status_code != 500,
           "9 SPA: index nas rotas da tela, assets com cache longo, CSP do W1", r3.headers.get("cache-control"))
    os.environ.pop("AUDITOR_WEB_DIST")

    def explode():
        raise RuntimeError(f"falha com {ALVO} e 10.1.2.3")
    from fastapi.routing import APIRoute
    api_mod.app.router.routes.insert(0, APIRoute("/api/_teste_erro", explode, methods=["GET"]))
    r = tc.get("/api/_teste_erro")
    log = ERROS.read_text() if ERROS.exists() else ""
    cod = (r.json() if r.headers.get("content-type", "").startswith("application/json") else {}).get("correlacao", "?")
    checar(r.status_code == 500 and r.json()["erro"] == "interno" and cod in r.json()["mensagem"] and cod in log and
           ALVO not in log and "10.1.2.3" not in log and ALVO not in r.text, "9 erro 500 com código de correlação, "
           "sem dado pessoal na resposta nem no log", cod)
    r = req("solicitante1", "POST", "/api/investigacoes", json={"cpf": ALVO, "justificativa": 3})
    checar(r.status_code == 422 and ALVO not in r.text and r.json().get("erro") == "validacao",
           "9 erro de validação não ecoa o CPF", r.text[:80])

    # ================================================================ 10. varredura
    for nome in ("kc26", "rhsso"):
        j("admin1", "POST", f"/api/instancias/{nome}/orcamento", json={"concorrencia": 2, "req_por_s": 5})
    import varredura_pii
    ag = varredura_pii.agulhas()
    res = varredura_pii.varrer_banco(ag)
    checar(not res, "10 varredura: nenhum dado pessoal em claro no banco", dict(list(res.items())[:3]))
    sujos = {}
    for p in LOGS.glob("*"):
        if p.is_file() and (p.name.startswith(("teste_gestao_", "siem_teste_gestao", "email_teste_gestao",
                                               "api_erros_teste_gestao"))):
            n = varredura_pii.achados(p.read_text(errors="replace"), ag)
            if n:
                sujos[p.name] = dict(n)
    checar(not sujos, "10 varredura: nada em claro em logs/ (API, worker, SIEM, e-mail, erros)", sujos)
    n = varredura_pii.achados("\n".join(RESPOSTAS), ag)
    checar(not n, "10 varredura: nenhuma resposta da API levou CPF/título em claro",
           f"{dict(n)} em {len(RESPOSTAS)} respostas")
    print(f"  (duração: {time.time() - t0:.0f}s)")


if __name__ == "__main__":
    main()

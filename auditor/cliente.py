"""CLI de produção (AUDITOR_MODO=producao): cliente fino da API (W1, PROPOSTA_WEB §8.7).

Não tem DSN do banco, chave nem certificado: quem tem shell no posto de trabalho não ganha nenhum acesso que não
teria pelo navegador. A identidade vem do login OIDC por device flow, com MFA; cada comando é uma chamada à API, com
as mesmas regras da web.

  export AUDITOR_MODO=producao AUDITOR_API=https://auditor.exemplo AUDITOR_OIDC_EMISSOR=https://sso/realms/auditor
  python -m auditor login                     # mostra o endereço e o código; aprove no navegador (MFA)
  python -m auditor pedir --cpf ... --de ... --ate ... --justificativa "..."
  python -m auditor aprovar --id 3 --investigador maria --motivo "..."
  python -m auditor exportar --id 3 --saida d/   # pede o pacote, espera o worker e baixa

O token fica em ~/.config/kc-auditor/sessao.json (permissão 600), válido só para este dispositivo.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path

import httpx

from . import oidc   # só OIDC e HTTP: nada de banco, chave ou certificado

CLI_ID = "kc-auditor-cli"


def _arq() -> Path:
    return Path(os.environ.get("AUDITOR_SESSAO_CLI", Path.home() / ".config" / "kc-auditor" / "sessao.json"))


def _salvar(t: dict):
    p = _arq()
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps({k: t[k] for k in ("access_token", "refresh_token") if k in t}))
    os.chmod(p, 0o600)


def _token() -> str:
    p = _arq()
    if not p.exists():
        sys.exit("Sem login. Rode: python -m auditor login")
    t = json.loads(p.read_text())
    try:
        oidc.validar(t["access_token"])
        return t["access_token"]
    except oidc.TokenInvalido:
        try:
            n = oidc.renovar(CLI_ID, None, t["refresh_token"])
            _salvar(n)
            return n["access_token"]
        except oidc.TokenInvalido:
            sys.exit("Sessão expirada. Rode: python -m auditor login")


def api(metodo: str, caminho: str, corpo: dict | None = None, bruto: bool = False):
    base = os.environ.get("AUDITOR_API", "http://localhost:8000").rstrip("/")
    r = httpx.request(metodo, f"{base}{caminho}", json=corpo, timeout=60, trust_env=False,
                      headers={"Authorization": f"Bearer {_token()}"})
    if r.status_code >= 400:
        try:
            e = r.json()
        except ValueError:
            e = {"erro": "http", "mensagem": r.text[:200]}
        if e.get("erro") == "step_up":
            sys.exit("Esta ação exige autenticação recente (MFA nos últimos 5 min). Rode `python -m auditor login` e "
                     "repita o comando.")
        sys.exit(f"[{r.status_code} {e.get('erro')}] {e.get('mensagem') or e.get('detail')}")
    return r if bruto else r.json()


def mostrar(x):
    print(json.dumps(x, ensure_ascii=False, indent=1, default=str))


# ------------------------------------------------------------------ comandos
def c_login(a):
    d = oidc.iniciar_dispositivo(CLI_ID)
    print(f"Abra {d['verification_uri_complete']}", flush=True)
    print(f"ou {d['verification_uri']} e digite o código {d['user_code']} (vale {d.get('expires_in', 300) // 60} "
          "min). Confirme só se foi você quem pediu este login, neste dispositivo.", flush=True)
    t = oidc.aguardar_dispositivo(d, CLI_ID)
    _salvar(t)
    mostrar(api("GET", "/api/eu"))


def c_sair(a):
    _arq().unlink(missing_ok=True)
    print("token removido deste dispositivo")


def c_pedir(a):
    corpo = {"cpf": a.cpf, "titulo": a.titulo, "de": a.de, "ate": a.ate, "justificativa": a.justificativa,
             "fuso": a.fuso, "granularidade": a.granularidade, "varredura": a.varredura, "base_dias": a.base_dias,
             "instancias": a.instancias.split(",") if a.instancias else None}
    if a.orgao:
        corpo["origem"] = {"orgao": a.orgao, "documento": a.documento, "processo": a.processo,
                           "fundamento": a.fundamento, "destinatario": a.destinatario}
    mostrar(api("POST", "/api/investigacoes", corpo))


def c_exportar(a):
    r = api("POST", f"/api/investigacoes/{a.id}/pacotes", {"sem_mascara": a.sem_mascara, "destino": a.destino})
    if "pacote" not in r:
        mostrar(r)
        print("pacote sem máscara aguarda aprovação; depois: python -m auditor baixar --pacote N")
        return
    _baixar(r["pacote"], Path(a.saida), a.espera)


def _baixar(pacote: int, saida: Path, espera: float = 600):
    fim = time.monotonic() + espera
    while True:
        ps = {p["pacote"]: p for p in api("GET", f"/api/investigacoes/{_inv_do_pacote(pacote)}/pacotes")}
        st = ps[pacote]["status"]
        if st == "pronto":
            break
        if st == "falhou" or time.monotonic() > fim:
            sys.exit(f"pacote {pacote}: {st}")
        time.sleep(2)
    link = api("POST", f"/api/pacotes/{pacote}/link")["link"]
    r = api("GET", link, bruto=True)
    saida.mkdir(parents=True, exist_ok=True)
    nome = r.headers["content-disposition"].split('filename="')[1].rstrip('"')
    (saida / nome).write_bytes(r.content)
    print(json.dumps({"arquivo": str(saida / nome), "sha256": r.headers.get("x-conteudo-sha256")}))


_pacote_inv: dict[int, int] = {}


def _inv_do_pacote(pacote: int) -> int:
    if pacote not in _pacote_inv:
        for i in api("GET", "/api/investigacoes"):
            for p in api("GET", f"/api/investigacoes/{i['id']}/pacotes") if "investigador" in i.get(
                    "minhas_funcoes", []) else []:
                _pacote_inv[p["pacote"]] = i["id"]
    if pacote not in _pacote_inv:
        sys.exit(f"pacote {pacote} não encontrado entre as suas investigações")
    return _pacote_inv[pacote]


def main(argv: list[str] | None = None):
    ap = argparse.ArgumentParser(prog="auditor", description="CLI de produção: cliente da API")
    sp = ap.add_subparsers(dest="cmd", required=True)
    sp.add_parser("login").set_defaults(f=c_login)
    sp.add_parser("sair").set_defaults(f=c_sair)
    sp.add_parser("eu").set_defaults(f=lambda a: mostrar(api("GET", "/api/eu")))
    for nome in ("pedir", "investigar"):    # `investigar` vira pedido, sujeito a aprovação
        p = sp.add_parser(nome)
        g = p.add_mutually_exclusive_group(required=True); g.add_argument("--cpf"); g.add_argument("--titulo")
        p.add_argument("--de", required=True); p.add_argument("--ate", required=True)
        p.add_argument("--justificativa", required=True); p.add_argument("--fuso", default="America/Bahia")
        p.add_argument("--granularidade", default="dia"); p.add_argument("--instancias")
        p.add_argument("--varredura", action="store_true"); p.add_argument("--base-dias", type=int, default=0)
        p.add_argument("--orgao", help="pedido externo: órgão de origem"); p.add_argument("--documento")
        p.add_argument("--processo"); p.add_argument("--fundamento"); p.add_argument("--destinatario")
        p.add_argument("--operador", help="ignorado: a identidade é a do login")
        p.set_defaults(f=c_pedir)
    sp.add_parser("pedidos").set_defaults(f=lambda a: mostrar(api("GET", "/api/investigacoes")))
    sp.add_parser("aprovacoes").set_defaults(f=lambda a: mostrar(api("GET", "/api/aprovacoes")))
    p = sp.add_parser("ver"); p.add_argument("--id", type=int, required=True)
    p.set_defaults(f=lambda a: mostrar(api("GET", f"/api/investigacoes/{a.id}")))
    p = sp.add_parser("progresso"); p.add_argument("--id", type=int, required=True)
    p.set_defaults(f=lambda a: mostrar(api("GET", f"/api/investigacoes/{a.id}/progresso")))
    p = sp.add_parser("aprovar"); p.add_argument("--id", type=int, required=True)
    p.add_argument("--investigador", required=True); p.add_argument("--motivo", required=True)
    p.add_argument("--sigilosa", action="store_true")
    p.set_defaults(f=lambda a: mostrar(api("POST", f"/api/investigacoes/{a.id}/aprovar", {
        "investigador": a.investigador, "motivo": a.motivo, "sigilosa": a.sigilosa})))
    for nome in ("devolver", "recusar", "reenviar", "cancelar"):
        p = sp.add_parser(nome); p.add_argument("--id", type=int, required=True)
        p.add_argument("--motivo", required=True); p.add_argument("--operador")
        p.set_defaults(f=lambda a, n=nome: mostrar(api("POST", f"/api/investigacoes/{a.id}/{n}", {"motivo": a.motivo})))
    for nome in ("iniciar", "pausar", "retomar"):
        p = sp.add_parser(nome); p.add_argument("--id", type=int, required=True); p.add_argument("--operador")
        p.add_argument("--fila", action="store_true", help="ignorado: em produção é sempre pela fila")
        p.set_defaults(f=lambda a, n=nome: mostrar(api("POST", f"/api/investigacoes/{a.id}/{n}")))
    p = sp.add_parser("pacotes"); p.add_argument("--id", type=int, required=True)
    p.set_defaults(f=lambda a: mostrar(api("GET", f"/api/investigacoes/{a.id}/pacotes")))
    p = sp.add_parser("exportar"); p.add_argument("--id", type=int, required=True)
    p.add_argument("--saida", default="saida"); p.add_argument("--sem-mascara", action="store_true")
    p.add_argument("--destino", help="sem máscara: destino formal declarado (processo, nível de sigilo)")
    p.add_argument("--espera", type=float, default=600); p.add_argument("--operador")
    p.set_defaults(f=c_exportar)
    p = sp.add_parser("decidir-pacote"); p.add_argument("--pedido", type=int, required=True)
    g = p.add_mutually_exclusive_group(required=True); g.add_argument("--aprovar", action="store_true")
    g.add_argument("--recusar", action="store_true"); p.add_argument("--motivo", required=True)
    p.set_defaults(f=lambda a: mostrar(api("POST", f"/api/aprovacoes/{a.pedido}/decidir",
                                           {"aprovar": a.aprovar, "motivo": a.motivo})))
    p = sp.add_parser("baixar"); p.add_argument("--pacote", type=int, required=True)
    p.add_argument("--saida", default="saida")
    p.set_defaults(f=lambda a: _baixar(a.pacote, Path(a.saida)))
    p = sp.add_parser("trilha"); p.add_argument("--id", type=int)
    p.set_defaults(f=lambda a: mostrar(api("GET", "/api/trilha" + (f"?investigacao={a.id}" if a.id else ""))))
    for nome in ("verificar-cadeia", "verificar-trilha"):
        p = sp.add_parser(nome); p.add_argument("--id", type=int)
        p.set_defaults(f=lambda a: mostrar(api("GET", "/api/trilha/verificar" + (
            f"?investigacao={a.id}" if a.id else ""))))
    sp.add_parser("instancias").set_defaults(f=lambda a: mostrar(api("GET", "/api/instancias")))
    p = sp.add_parser("orcamento"); p.add_argument("--nome", required=True)
    p.add_argument("--concorrencia", type=int, required=True); p.add_argument("--req-por-s", type=float, required=True)
    p.set_defaults(f=lambda a: mostrar(api("POST", f"/api/instancias/{a.nome}/orcamento",
                                           {"concorrencia": a.concorrencia, "req_por_s": a.req_por_s})))
    sp.add_parser("saude").set_defaults(f=lambda a: mostrar(api("GET", "/api/servicos/saude")))
    sp.add_parser("usuarios").set_defaults(f=lambda a: mostrar(api("GET", "/api/usuarios")))
    p = sp.add_parser("instancia-add")
    for k in ("nome", "url", "client-id", "segredo"):
        p.add_argument(f"--{k}", required=True)
    p.add_argument("--realm-auth", default="master"); p.add_argument("--concorrencia", type=int, default=2)
    p.add_argument("--req-por-s", type=float, default=5); p.add_argument("--versao")
    p.add_argument("--realms-esperados", default=""); p.add_argument("--homologacao"); p.add_argument("--sonda")
    p.add_argument("--operador")
    p.set_defaults(f=lambda a: mostrar(api("POST", "/api/instancias", {
        "nome": a.nome, "url": a.url, "client_id": a.client_id, "segredo": a.segredo, "realm_auth": a.realm_auth,
        "concorrencia": a.concorrencia, "req_por_s": a.req_por_s, "versao": a.versao, "homologacao": a.homologacao,
        "sonda": a.sonda, "realms_esperados": [x for x in a.realms_esperados.split(",") if x]})))
    p = sp.add_parser("sondas"); p.add_argument("--nome", required=True)
    p.set_defaults(f=lambda a: mostrar(api("POST", f"/api/instancias/{a.nome}/sondas")))
    for nome in ("init", "chave", "worker", "chaveiro", "api", "ancorar", "migrar-cifra"):
        sp.add_parser(nome).set_defaults(f=lambda a, n=nome: sys.exit(
            f"`{n}` não existe no modo producao: é do servidor (Administrador técnico ou Operador do Vault)"))
    a = ap.parse_args(argv)
    a.f(a)

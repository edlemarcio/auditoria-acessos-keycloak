"""Gera eventos de usuário diretamente na tabela EVENT_ENTITY de um Keycloak (real ou simulador).

Funciona no banco PostgreSQL de um Keycloak real (26.x ou 18/RH-SSO 7.6): lê realms, usuários e clients
das tabelas do próprio Keycloak e insere linhas com o mesmo formato que o Keycloak grava.

Uso:
  python tools/gerar_eventos.py --dsn postgresql://keycloak:senha@localhost:5433/keycloak \
      --instancia kc26 --total 1000000
"""
from __future__ import annotations

import argparse
import json
import random
import sys
import time
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

import psycopg

RAIZ = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(RAIZ))
from auditor.identificador import formatar_cpf  # noqa: E402
from tools.cenario import PERIODO_DIAS, REALMS, SONDA  # noqa: E402

SALVA_POR_PADRAO = {"LOGIN", "LOGIN_ERROR", "LOGOUT", "LOGOUT_ERROR", "CODE_TO_TOKEN", "CODE_TO_TOKEN_ERROR",
                    "UPDATE_PASSWORD", "RESET_PASSWORD", "IDENTITY_PROVIDER_LOGIN", "IDENTITY_PROVIDER_LOGIN_ERROR"}
# Peso de início de sessão por hora local (UTC-3): pico em horário comercial
PESO_HORA = [1, 1, 1, 1, 1, 2, 4, 8, 14, 16, 16, 14, 10, 13, 16, 16, 14, 11, 8, 6, 5, 4, 3, 2]
FUSO_LOCAL = timezone(timedelta(hours=-3))


class Gerador:
    def __init__(self, rnd: random.Random, agora_ms: int):
        self.rnd = rnd
        self.agora = agora_ms
        self.linhas = []

    def uid(self) -> str:
        return str(uuid.UUID(int=self.rnd.getrandbits(128), version=4))

    def add(self, t, tipo, realm_id, client, user_id, sess, ip, details, error=None):
        self.linhas.append((self.uid(), client, json.dumps(details, separators=(",", ":")), error, ip,
                            realm_id, sess, int(t), tipo, user_id))

    def inicio_sessao(self, max_dias: float = PERIODO_DIAS) -> int:
        dias = self.rnd.uniform(0, max_dias)
        base = datetime.fromtimestamp(self.agora / 1000, FUSO_LOCAL) - timedelta(days=dias)
        hora = self.rnd.choices(range(24), weights=PESO_HORA)[0]
        dt = base.replace(hour=hora, minute=self.rnd.randint(0, 59), second=self.rnd.randint(0, 59),
                          microsecond=self.rnd.randint(0, 999) * 1000)
        t = int(dt.timestamp() * 1000)
        return min(t, self.agora - 3600_000 - self.rnd.randint(0, 3600_000))

    def sessao(self, conta, realm_id, salvos, clientes, ips, limite, max_dias=PERIODO_DIAS):
        r = self.rnd
        t = self.inicio_sessao(max_dias)
        client = r.choice(clientes)
        ip = r.choice(ips) if r.random() < 0.9 else f"200.{r.randint(0, 255)}.{r.randint(0, 255)}.{r.randint(1, 254)}"
        sess = self.uid()
        uid = conta["db_id"]
        uname = conta["username"]
        redirect = f"https://{client}.exemplo.gov.br/callback"
        n0 = len(self.linhas)
        if "LOGIN_ERROR" in salvos and r.random() < 0.12:
            for _ in range(r.randint(1, 3)):
                t += r.randint(2000, 20000)
                self.add(t, "LOGIN_ERROR", realm_id, client, uid, None, ip,
                         {"auth_method": "openid-connect", "auth_type": "code", "redirect_uri": redirect,
                          "code_id": sess, "username": uname}, "invalid_user_credentials")
        if r.random() < 0.97 and "LOGIN" in salvos:
            t += r.randint(1000, 15000)
            self.add(t, "LOGIN", realm_id, client, uid, sess, ip,
                     {"auth_method": "openid-connect", "auth_type": "code", "redirect_uri": redirect,
                      "consent": "no_consent_required", "code_id": sess, "username": uname})
            if "CODE_TO_TOKEN" in salvos:
                t += r.randint(200, 2000)
                self.add(t, "CODE_TO_TOKEN", realm_id, client, uid, sess, ip,
                         {"token_id": self.uid(), "grant_type": "authorization_code", "refresh_token_type": "Refresh",
                          "scope": "openid profile email", "refresh_token_id": self.uid(), "code_id": sess,
                          "client_auth_method": "client-secret"})
            if "REFRESH_TOKEN" in salvos:
                for _ in range(r.choices([0, 1, 2, 3, 4, 5], weights=[30, 25, 18, 12, 9, 6])[0]):
                    t += r.randint(300_000, 1_800_000)
                    self.add(t, "REFRESH_TOKEN", realm_id, client, uid, sess, ip,
                             {"token_id": self.uid(), "grant_type": "refresh_token", "refresh_token_id": self.uid(),
                              "updated_refresh_token_id": self.uid(), "refresh_token_type": "Refresh",
                              "scope": "openid profile email", "client_auth_method": "client-secret"})
            if "UPDATE_PASSWORD" in salvos and r.random() < 0.005:
                t += r.randint(5000, 60000)
                self.add(t, "UPDATE_PASSWORD", realm_id, "account-console", uid, sess, ip,
                         {"auth_method": "openid-connect", "username": uname})
            if "LOGOUT" in salvos and r.random() < 0.4:
                t += r.randint(60_000, 3_600_000)
                self.add(t, "LOGOUT", realm_id, client, uid, sess, ip, {"redirect_uri": redirect})
        # não ultrapassa o total pedido nem o "agora"
        del self.linhas[n0 + max(0, limite):]
        self.linhas[n0:] = [x for x in self.linhas[n0:] if x[7] < self.agora - 60_000]
        return len(self.linhas) - n0


def salvos_do_realm(cfg) -> set[str]:
    return set(cfg["types"]) if cfg["types"] else set(SALVA_POR_PADRAO)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dsn", required=True)
    ap.add_argument("--instancia", required=True, choices=list(REALMS))
    ap.add_argument("--total", type=int, default=1_000_000)
    ap.add_argument("--pessoas", default=str(RAIZ / "dados/pessoas.json"))
    ap.add_argument("--seed", type=int, default=7)
    ap.add_argument("--limpar", action="store_true", help="apaga os eventos existentes antes")
    ap.add_argument("--evento-admin-exclusao", action="store_true",
                    help="grava admin event DELETE da conta excluída (use só no simulador)")
    a = ap.parse_args()

    rnd = random.Random(f"{a.seed}-{a.instancia}")
    agora = int(time.time() * 1000)
    dados = json.loads(Path(a.pessoas).read_text())
    cfg = REALMS[a.instancia]
    g = Gerador(rnd, agora)
    t0 = time.time()

    with psycopg.connect(a.dsn) as cx, cx.cursor() as cur:
        cur.execute("SELECT name, id FROM realm")
        realm_id = dict(cur.fetchall())
        cur.execute("SELECT r.name, u.username, u.id FROM user_entity u JOIN realm r ON r.id = u.realm_id")
        uid = {(rn, un): i for rn, un, i in cur.fetchall()}
        if a.limpar:
            cur.execute("TRUNCATE event_entity")

        contas = []
        for c in dados["contas"]:
            if c["instancia"] != a.instancia or c["realm"] not in realm_id:
                continue
            rc = cfg[c["realm"]]
            if not rc["events_enabled"]:
                continue
            db_id = uid.get((c["realm"], c["username"]))
            if db_id is None:
                if c["marca"] != "EXCLUIDA":
                    continue
                db_id = c["id"]  # conta removida: os eventos antigos continuam com o id dela
            r2 = random.Random(c["cpf"])
            ips = [f"177.{r2.randint(0, 255)}.{r2.randint(0, 255)}.{r2.randint(1, 254)}"
                   for _ in range(r2.randint(1, 3))]
            contas.append({**c, "db_id": db_id, "ips": ips})
        print(f"contas com eventos: {len(contas)}")

        alvo = dados["casos"]["ALVO"]
        # --- casos especiais (contam no total) ---
        realm_burst = "portal-cidadao"
        conta_alvo = next(c for c in contas if c["marca"] == "ALVO" and c["realm"] == realm_burst)
        n_burst = 300 if a.instancia == "kc26" else 250
        t_burst = agora - 20 * 86400_000 + 37_123
        for _ in range(n_burst):  # rajada: muitos eventos no MESMO milissegundo
            g.add(t_burst, "LOGIN_ERROR", realm_id[realm_burst], "portal-web", conta_alvo["db_id"], None,
                  "45.160.10.7", {"auth_method": "openid-connect", "username": conta_alvo["username"]},
                  "invalid_user_credentials")
        for i in range(20 if a.instancia == "kc26" else 10):  # usuário inexistente (sem userId)
            uname = alvo["cpf"] if i % 2 == 0 else formatar_cpf(alvo["cpf"])
            g.add(agora - rnd.randint(2, 170) * 86400_000, "LOGIN_ERROR", realm_id[realm_burst], "portal-web",
                  None, None, "45.160.10.7", {"auth_method": "openid-connect", "username": uname},
                  "user_not_found")

        # --- tráfego regular até completar o total ---
        pesos = [c["peso"] for c in contas]
        clientes = dados["clientes"]
        salvos = {n: salvos_do_realm(rc) for n, rc in cfg.items()}
        # Realm com retenção menor que o período: o Keycloak real já teria expurgado o excedente,
        # então só geramos dentro da retenção (menos 1 dia de folga).
        max_dias = {n: min(PERIODO_DIAS, rc["expiration"] / 86400 - 1) if rc["expiration"] else PERIODO_DIAS
                    for n, rc in cfg.items()}
        while len(g.linhas) < a.total:
            c = rnd.choices(contas, weights=pesos)[0]
            g.sessao(c, realm_id[c["realm"]], salvos[c["realm"]], clientes[c["realm"]], c["ips"],
                     a.total - len(g.linhas), max_dias[c["realm"]])
        assert len(g.linhas) == a.total, len(g.linhas)

        # --- realm de homologação (sondas): fora do total ---
        sonda_id = uid[("homologacao", SONDA["username"])]
        hom = realm_id["homologacao"]
        d = datetime.fromtimestamp(agora / 1000, timezone.utc).replace(hour=0, minute=0, second=0,
                                                                         microsecond=0) - timedelta(days=10)
        d_ms = int(d.timestamp() * 1000)
        for k in range(-28, 29):  # D-14h .. D+14h, a cada 30 min
            g.add(d_ms + k * 1800_000, "LOGIN", hom, "app-homologacao", sonda_id, g.uid(), "10.0.0.1",
                  {"auth_method": "openid-connect", "username": SONDA["username"]})
        t_same = d_ms - 3 * 86400_000 + 12 * 3600_000
        for _ in range(3):
            g.add(t_same, "LOGOUT", hom, "app-homologacao", sonda_id, g.uid(), "10.0.0.1", {})

        print(f"gerados {len(g.linhas)} eventos em {time.time() - t0:.1f}s; gravando...")
        with cur.copy("COPY event_entity (id,client_id,details_json,error,ip_address,realm_id,session_id,"
                      "event_time,type,user_id) FROM STDIN") as cp:
            for linha in g.linhas:
                cp.write_row(linha)
        if a.evento_admin_exclusao:
            exc = next(c for c in dados["contas"] if c["marca"] == "EXCLUIDA")
            cur.execute("INSERT INTO admin_event_entity (id,admin_event_time,realm_id,operation_type,auth_realm_id,"
                        "auth_user_id,ip_address,resource_path,representation,resource_type) "
                        "VALUES (%s,%s,%s,'DELETE',%s,'admin','10.0.0.5',%s,NULL,'USER')",
                        (g.uid(), agora - 5 * 86400_000, realm_id[exc["realm"]], realm_id["master"],
                         f"users/{exc['id']}"))
        cx.commit()
        cur.execute("ANALYZE event_entity")
    print(f"ok em {time.time() - t0:.1f}s")


if __name__ == "__main__":
    main()

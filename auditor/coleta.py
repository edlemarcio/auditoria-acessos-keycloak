"""Coleta em etapas, retomável, com cursor de tempo e releitura de consistência.

Cada tarefa = (conta, fatia [inicio, fim)). O checkpoint é o cursor de tempo (modos epoch) ou a
posição dentro do dia em ordem decrescente (modo dia), gravado a cada página.
"""
from __future__ import annotations

import json
import threading
import time
import zlib
from datetime import datetime, timedelta, timezone

from psycopg.types.json import Jsonb

from .db import SNAPSHOTS_DA_INVESTIGACAO, conectar
from .identificador import variantes
from .kc import ClienteKC, ErroKC, FalhaTemporaria, SemPermissao

PAGINA = 200
PONTUAL = 5000
DIA_MS = 86400_000
MARGEM_FECHADA_MS = 5 * 60_000
LEASE = timedelta(minutes=5)


# ------------------------------------------------------------------ planejamento
def fatias(inicio: int, fim: int, modo: str, deslocamento_h: float) -> list[tuple[int, int]]:
    """Fatias de 1 dia. No modo 'dia' seguem a meia-noite do servidor (fuso medido pela S6)."""
    fim = min(fim, int(time.time() * 1000) - MARGEM_FECHADA_MS)
    if modo == "dia":
        off = int(-deslocamento_h * 3600_000)     # início do dia do servidor em relação à meia-noite UTC
        base = (inicio - off) // DIA_MS * DIA_MS + off
    else:
        base = inicio // DIA_MS * DIA_MS
    out, t = [], base
    while t < fim:
        a, b = max(t, inicio), min(t + DIA_MS, fim)
        if a < b:
            out.append((a, b))
        t += DIA_MS
    return out


def planejar(cx, inv: dict, contas: list[dict], insts: dict[int, dict], snaps: dict):
    for c in contas:
        if not c["incluida"]:
            continue
        inst = insts[c["instancia_id"]]
        snap = snaps.get((c["instancia_id"], c["realm"]))
        if snap and snap["status"] in ("eventos_nao_gravados", "sem_permissao", "esperado_invisivel"):
            continue
        modo = (inst["sondas"] or {}).get("modo", "dia")
        desl = ((inst["sondas"] or {}).get("S6_fuso") or {}).get("deslocamento_horas", 0.0)
        for a, b in fatias(inv["inicio_ms"], inv["fim_ms"], modo, desl):
            cx.execute("INSERT INTO tarefa (investigacao_id, conta_id, inicio_ms, fim_ms, modo) "
                       "VALUES (%s,%s,%s,%s,%s)", (inv["id"], c["id"], a, b, modo))


# ------------------------------------------------------------------ execução de uma fatia
class Coletor:
    def __init__(self, cx, cli: ClienteKC, inv: dict, conta: dict, tarefa: dict, inst: dict, alvo: tuple | None):
        self.cx, self.cli, self.inv, self.conta, self.t, self.inst = cx, cli, inv, conta, tarefa, inst
        self.realm = conta["realm"]
        self.sem_dateto = (inst["sondas"] or {}).get("sem_dateTo", False)
        self.alvo = alvo            # (tipo, digitos) para filtrar a varredura de falhas sem userId
        self.limite_atingido = False

    def _base(self) -> list[tuple[str, str]]:
        p = []
        if self.conta["user_id"]:
            p.append(("user", self.conta["user_id"]))
        if self.conta["via"] == "varredura":
            p.append(("type", "LOGIN_ERROR"))
        return p   # via 'realm': realm inteiro (teste de carga)

    def _aceitar(self, e: dict) -> bool:
        if not (self.t["inicio_ms"] <= e["time"] < self.t["fim_ms"]):
            return False
        if self.conta["via"] == "varredura":
            if e.get("userId"):
                return False
            nomes = set(variantes(*self.alvo)) if self.alvo else set()
            return (e.get("details") or {}).get("username") in nomes
        return True

    def gravar(self, evs: list[dict]) -> int:
        linhas = [e for e in evs if self._aceitar(e)]
        if not linhas:
            return 0
        with self.cx.cursor() as cur:
            cur.executemany(
                "INSERT INTO evento (investigacao_id, instancia_id, realm, id, conta_id, time_ms, type, client_id, "
                "user_id, session_id, ip, error, details, bruto) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s) "
                "ON CONFLICT DO NOTHING",
                [(self.inv["id"], self.inst["id"], self.realm, e["id"], self.conta["id"], e["time"], e["type"],
                  e.get("clientId"), e.get("userId"), e.get("sessionId"), e.get("ipAddress"), e.get("error"),
                  Jsonb(e.get("details")), Jsonb(e)) for e in linhas])
        return len(linhas)

    def checkpoint(self, **campos):
        sets = ", ".join(f"{k}=%s" for k in campos)
        self.cx.execute(f"UPDATE tarefa SET {sets}, lease_ate=now()+%s, atualizado=now() WHERE id=%s",
                        (*campos.values(), LEASE, self.t["id"]))
        self.t.update(campos)

    # ---- modos epoch: cursor de tempo
    def _pontual(self, T: int) -> list[dict]:
        """Lê o milissegundo T inteiro (a API não desempata eventos com o mesmo time)."""
        anterior = None
        for _ in range(5):
            if self.sem_dateto:   # regressão do dateTo: lê a partir de T em ordem crescente e fica só com T
                evs = [e for e in self.cli.eventos(self.realm, self._base() + [
                    ("dateFrom", str(T)), ("direction", "asc"), ("max", str(PONTUAL))]) if e["time"] == T]
            else:
                evs = self.cli.eventos(self.realm, self._base() + [("dateFrom", str(T)), ("dateTo", str(T)),
                                                                   ("max", str(PONTUAL))])
            if len(evs) >= PONTUAL:
                self.limite_atingido = True
            ids = {e["id"] for e in evs}
            if ids == anterior:
                return evs
            anterior = ids
        return evs

    def rodar_epoch(self, coletar=True) -> set[str]:
        asc = self.t["modo"] == "epoch_asc"
        ini, fim = self.t["inicio_ms"], self.t["fim_ms"]
        cursor = self.t["cursor_ms"] if (coletar and self.t["cursor_ms"] is not None) else (ini if asc else fim - 1)
        vistos: set[str] = set()
        while (cursor < fim) if asc else (cursor >= ini):
            p = self._base() + [("max", str(PAGINA)), ("first", "0")]
            if asc:
                p += [("dateFrom", str(cursor)), ("direction", "asc")]
                if not self.sem_dateto:
                    p.append(("dateTo", str(fim - 1)))
            else:
                p += [("dateFrom", str(ini)), ("dateTo", str(cursor)), ("direction", "desc")]
            pag = self.cli.eventos(self.realm, p)
            if asc and self.sem_dateto:
                pag = [e for e in pag if e["time"] < fim]
            if len(pag) < PAGINA:
                vistos |= {e["id"] for e in pag if self._aceitar(e)}
                if coletar:
                    self.gravar(pag)
                    self.checkpoint(cursor_ms=fim if asc else ini - 1)
                break
            T = pag[-1]["time"]
            parte = [e for e in pag if (e["time"] < T if asc else e["time"] > T)]
            mesmo_ms = self._pontual(T)
            vistos |= {e["id"] for e in parte + mesmo_ms if self._aceitar(e)}
            if coletar:
                self.gravar(parte + mesmo_ms)
            cursor = T + 1 if asc else T - 1
            if coletar:
                self.checkpoint(cursor_ms=cursor)
        return vistos

    # ---- modo dia: só yyyy-MM-dd, ordem decrescente, posição dentro do dia
    def rodar_dia(self, coletar=True) -> set[str]:
        desl = ((self.inst["sondas"] or {}).get("S6_fuso") or {}).get("deslocamento_horas", 0.0)
        # dia do servidor que contém a fatia
        dia = datetime.fromtimestamp((self.t["inicio_ms"] + desl * 3600_000) / 1000, timezone.utc).date()
        d1, d2 = dia.isoformat(), (dia + timedelta(days=1)).isoformat()
        # dateTo = dia seguinte cobre tanto "fim do dia" (26.x) quanto "meia-noite" (18.x); o excesso é filtrado.
        # Sem epoch não há consulta pontual: o dia é lido numa página grande (PONTUAL), porque a paginação por
        # posição não é estável entre eventos com o mesmo time. Página cheia continua por posição e a
        # releitura (obrigatória neste modo) aponta divergência, se houver.
        first = self.t["offset_n"] if coletar else 0
        vistos: set[str] = set()
        while True:
            pag = self.cli.eventos(self.realm, self._base() + [("dateFrom", d1), ("dateTo", d2),
                                                               ("first", str(first)), ("max", str(PONTUAL))])
            vistos |= {e["id"] for e in pag if self._aceitar(e)}
            if coletar:
                self.gravar(pag)
            first += len(pag)
            if coletar:
                self.checkpoint(offset_n=first)
            if len(pag) < PONTUAL:
                break
        return vistos

    def rodar(self, coletar=True) -> set[str]:
        return self.rodar_dia(coletar) if self.t["modo"] == "dia" else self.rodar_epoch(coletar)

    # ---- releitura de consistência
    def precisa_reler(self, expiracao_s: int | None) -> bool:
        if self.t["modo"] == "dia":
            return True
        if expiracao_s and self.t["inicio_ms"] < time.time() * 1000 - expiracao_s * 1000 + 2 * DIA_MS:
            return True
        return zlib.crc32(str(self.t["id"]).encode()) % 10 == 0   # amostra de 10%

    def reler(self, expiracao_s: int | None) -> str:
        def gravados():
            if self.conta["via"] == "realm":   # realm inteiro: inclui eventos gravados sob contas localizadas
                return {r["id"] for r in self.cx.execute(
                    "SELECT id FROM evento WHERE investigacao_id=%s AND instancia_id=%s AND realm=%s AND time_ms>=%s "
                    "AND time_ms<%s", (self.inv["id"], self.inst["id"], self.realm, self.t["inicio_ms"],
                                       self.t["fim_ms"])).fetchall()}
            return {r["id"] for r in self.cx.execute(
                "SELECT id FROM evento WHERE investigacao_id=%s AND conta_id=%s AND time_ms>=%s AND time_ms<%s",
                (self.inv["id"], self.conta["id"], self.t["inicio_ms"], self.t["fim_ms"])).fetchall()}
        for tentativa in (1, 2):
            relidos = {i for i in self.rodar(coletar=False)}
            g = gravados()
            extras, faltando = relidos - g, g - relidos
            if not extras and not faltando:
                return "ok"
            if not extras and faltando:
                limite = time.time() * 1000 - (expiracao_s or 0) * 1000
                tempos = [r["time_ms"] for r in self.cx.execute(
                    "SELECT time_ms FROM evento WHERE investigacao_id=%s AND id = ANY(%s)",
                    (self.inv["id"], list(faltando))).fetchall()]
                if expiracao_s and all(t < limite for t in tempos):
                    return "expirado"
            if tentativa == 1:   # recoleta uma vez a fatia inteira
                self.t["cursor_ms"], self.t["offset_n"] = None, 0
                self.rodar(coletar=True)
        return "divergente"


# ------------------------------------------------------------------ fila de tarefas
def _pegar_tarefa(cx, inv_id: int):
    with cx.transaction():
        r = cx.execute("SELECT * FROM tarefa WHERE investigacao_id=%s AND status='pendente' "
                       "ORDER BY inicio_ms, id FOR UPDATE SKIP LOCKED LIMIT 1", (inv_id,)).fetchone()
        if r:
            cx.execute("UPDATE tarefa SET status='executando', tentativas=tentativas+1, lease_ate=now()+%s "
                       "WHERE id=%s", (LEASE, r["id"]))
        return r


def executar(inv_id: int, threads: int | None = None, parar_apos: int | None = None, progresso=None):
    """Executa (ou retoma) as tarefas pendentes da investigação."""
    with conectar() as cx:
        # retomada após queda: tarefas 'executando' com lease vencido voltam para a fila
        cx.execute("UPDATE tarefa SET status='pendente' WHERE investigacao_id=%s AND status='executando' "
                   "AND lease_ate < now()", (inv_id,))
        cx.execute("UPDATE investigacao SET status='coletando' WHERE id=%s", (inv_id,))
        inv = cx.execute("SELECT * FROM investigacao WHERE id=%s", (inv_id,)).fetchone()
        insts = {i["id"]: i for i in cx.execute("SELECT * FROM instancia").fetchall()}
        contas = {c["id"]: c for c in cx.execute("SELECT * FROM conta WHERE investigacao_id=%s", (inv_id,))}
        exp = {(s["instancia_id"], s["realm"]): (s["config"] or {}).get("eventsExpiration")
               for s in cx.execute("SELECT DISTINCT ON (instancia_id, realm) * FROM realm_snapshot s WHERE "
                                   + SNAPSHOTS_DA_INVESTIGACAO + " ORDER BY instancia_id, realm, lido_em DESC",
                                   {"inv": inv_id})}
    alvo = None
    if inv["parametros"].get("varredura"):
        from .cripto import ctx_alvo, decifrar
        alvo = (inv["tipo"], decifrar(inv["alvo_cifrado"], ctx_alvo(inv["alvo_hmac"])))
    clientes = {i: ClienteKC(insts[i], inv_id) for i in {c["instancia_id"] for c in contas.values()}}
    n = threads or max(1, min(8, sum(insts[i]["concorrencia"] for i in clientes)))
    feitas = [0]
    lock = threading.Lock()

    def trabalhador():
        with conectar() as cx:
            while True:
                with lock:
                    if parar_apos is not None and feitas[0] >= parar_apos:
                        return
                t = _pegar_tarefa(cx, inv_id)
                if not t:
                    return
                conta = contas[t["conta_id"]]
                inst = insts[conta["instancia_id"]]
                col = Coletor(cx, clientes[inst["id"]], inv, conta, t, inst, alvo)
                try:
                    col.rodar()
                    expiracao = exp.get((inst["id"], conta["realm"]))
                    rel = col.reler(expiracao) if col.precisa_reler(expiracao) else None
                    n_ev = cx.execute("SELECT count(*) AS n FROM evento WHERE investigacao_id=%s AND conta_id=%s "
                                      "AND time_ms>=%s AND time_ms<%s",
                                      (inv_id, conta["id"], t["inicio_ms"], t["fim_ms"])).fetchone()["n"]
                    status = "limite" if col.limite_atingido else "concluida"
                    cx.execute("UPDATE tarefa SET status=%s, releitura=%s, eventos=%s, erro=NULL, atualizado=now() "
                               "WHERE id=%s", (status, rel, n_ev, t["id"]))
                except SemPermissao as e:
                    cx.execute("UPDATE tarefa SET status='sem_permissao', erro=%s WHERE id=%s", (str(e), t["id"]))
                except (FalhaTemporaria, ErroKC) as e:
                    novo = "falhou" if t["tentativas"] >= 3 else "pendente"
                    cx.execute("UPDATE tarefa SET status=%s, erro=%s WHERE id=%s", (novo, str(e)[:500], t["id"]))
                with lock:
                    feitas[0] += 1
                    if progresso:
                        progresso(feitas[0])

    ths = [threading.Thread(target=trabalhador, daemon=True) for _ in range(n)]
    for th in ths:
        th.start()
    for th in ths:
        th.join()
    for c in clientes.values():
        c.fechar()
    with conectar() as cx:
        pend = cx.execute("SELECT count(*) AS n FROM tarefa WHERE investigacao_id=%s AND status IN "
                          "('pendente','executando')", (inv_id,)).fetchone()["n"]
        if pend == 0:
            cx.execute("UPDATE investigacao SET status='coletada' WHERE id=%s", (inv_id,))
        else:
            cx.execute("UPDATE investigacao SET status='parcial' WHERE id=%s", (inv_id,))
    return feitas[0]

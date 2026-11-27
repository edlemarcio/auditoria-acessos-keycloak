"""Coleta em etapas, retomável, com cursor de tempo e releitura de consistência.

Cada tarefa = (conta, fatia [inicio, fim)). O checkpoint é o cursor de tempo (modos epoch) ou a
posição dentro do dia em ordem decrescente (modo dia), gravado a cada página.
"""
from __future__ import annotations

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
class Interrompida(Exception):
    """A investigação foi pausada ou cancelada durante a coleta da fatia."""

    def __init__(self, estado: str):
        super().__init__(estado)
        self.estado = estado


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
        # pausar e cancelar valem a partir da próxima página: o cursor acabou de ser salvo
        st = self.cx.execute("SELECT status FROM investigacao WHERE id=%s", (self.inv["id"],)).fetchone()["status"]
        if st in ESTADOS_PARADA:
            raise Interrompida(st)

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
CHAVE_INV = 0x6B64   # namespace dos advisory locks por investigação ("kd")
ESTADOS_PARADA = ("pausada", "cancelada")


def pegar_tarefa(cx, inv_id: int | None = None):
    """Próxima tarefa pendente de investigações em coleta, com rodízio: prioridade maior primeiro e, dentro dela,
    a investigação atendida há mais tempo. Com `inv_id`, só daquela investigação (CLI)."""
    with cx.transaction():
        t = cx.execute("""
            WITH c AS (
              SELECT t.id FROM tarefa t JOIN investigacao i ON i.id = t.investigacao_id
              WHERE t.status = 'pendente' AND i.status = 'coletando'
                AND (%(inv)s::int IS NULL OR t.investigacao_id = %(inv)s)
              ORDER BY i.prioridade DESC, i.ultimo_atendimento NULLS FIRST, t.inicio_ms, t.id
              FOR UPDATE OF t SKIP LOCKED LIMIT 1)
            UPDATE tarefa t SET status = 'executando', tentativas = t.tentativas + 1, lease_ate = now() + %(lease)s
            FROM c WHERE t.id = c.id RETURNING t.*""", {"inv": inv_id, "lease": LEASE}).fetchone()
        if t:
            cx.execute("UPDATE investigacao SET ultimo_atendimento = clock_timestamp() WHERE id = %s",
                       (t["investigacao_id"],))
        return t


def devolver_leases_vencidos(cx, inv_id: int | None = None):
    """Retomada após queda: tarefas 'executando' com lease vencido voltam para a fila."""
    cx.execute("UPDATE tarefa SET status='pendente' WHERE status='executando' AND lease_ate < now() "
               "AND (%(inv)s::int IS NULL OR investigacao_id = %(inv)s)", {"inv": inv_id})


class Clientes:
    """Clientes da Admin API por (instância, investigação), reaproveitados entre tarefas de uma thread."""

    def __init__(self):
        self._c: dict[tuple[int, int], ClienteKC] = {}

    def de(self, inst: dict, inv_id: int) -> ClienteKC:
        k = (inst["id"], inv_id)
        if k not in self._c:
            self._c[k] = ClienteKC(inst, inv_id)
        return self._c[k]

    def fechar(self, inv_id: int | None = None):
        for k in [k for k in self._c if inv_id is None or k[1] == inv_id]:
            self._c.pop(k).fechar()


def executar_tarefa(cx, t: dict, clientes: Clientes) -> str:
    """Executa uma fatia já reservada (status 'executando') e grava o resultado. Devolve o novo status."""
    inv = cx.execute("SELECT * FROM investigacao WHERE id=%s", (t["investigacao_id"],)).fetchone()
    conta = cx.execute("SELECT * FROM conta WHERE id=%s", (t["conta_id"],)).fetchone()
    inst = cx.execute("SELECT * FROM instancia WHERE id=%s", (conta["instancia_id"],)).fetchone()
    snap = cx.execute("SELECT config FROM realm_snapshot s WHERE s.instancia_id=%(i)s AND s.realm=%(r)s AND "
                      + SNAPSHOTS_DA_INVESTIGACAO + " ORDER BY lido_em DESC LIMIT 1",
                      {"i": inst["id"], "r": conta["realm"], "inv": inv["id"]}).fetchone()
    expiracao = ((snap or {}).get("config") or {}).get("eventsExpiration")
    alvo = None
    if inv["parametros"].get("varredura"):
        from .chaves import alvo as alvo_de
        alvo = (inv["tipo"], alvo_de(inv, "coleta"))
    col = Coletor(cx, clientes.de(inst, inv["id"]), inv, conta, t, inst, alvo)
    try:
        col.rodar()
        rel = col.reler(expiracao) if col.precisa_reler(expiracao) else None
        n_ev = cx.execute("SELECT count(*) AS n FROM evento WHERE investigacao_id=%s AND conta_id=%s "
                          "AND time_ms>=%s AND time_ms<%s",
                          (inv["id"], conta["id"], t["inicio_ms"], t["fim_ms"])).fetchone()["n"]
        status = "limite" if col.limite_atingido else "concluida"
        cx.execute("UPDATE tarefa SET status=%s, releitura=%s, eventos=%s, erro=NULL, atualizado=now() "
                   "WHERE id=%s", (status, rel, n_ev, t["id"]))
    except Interrompida as e:
        # pausa: volta à fila com o cursor salvo no último checkpoint; cancelamento: encerra a fatia
        status = "pendente" if e.estado == "pausada" else "cancelada"
        cx.execute("UPDATE tarefa SET status=%s, tentativas=tentativas-1, lease_ate=NULL WHERE id=%s",
                   (status, t["id"]))
    except SemPermissao as e:
        status = "sem_permissao"
        cx.execute("UPDATE tarefa SET status='sem_permissao', erro=%s WHERE id=%s", (str(e), t["id"]))
    except Exception as e:  # noqa: BLE001 — erro inesperado não pode deixar a fatia presa em 'executando'
        status = "falhou" if t["tentativas"] >= 3 else "pendente"
        erro = str(e) if isinstance(e, (FalhaTemporaria, ErroKC)) else f"{type(e).__name__}: {e}"
        cx.execute("UPDATE tarefa SET status=%s, erro=%s WHERE id=%s", (status, erro[:500], t["id"]))
    return status


def concluir_se_terminou(cx, inv_id: int, enfileirar_fechamento: bool = True) -> bool:
    """Sem tarefas pendentes ou em execução, a investigação em coleta passa a 'coletada' e (no modo worker)
    ganha um job de fechamento. Protegido por lock por investigação: só um processo conclui."""
    with cx.transaction():
        cx.execute("SELECT pg_advisory_xact_lock(%s, %s)", (CHAVE_INV, inv_id))
        st = cx.execute("SELECT status FROM investigacao WHERE id=%s FOR UPDATE", (inv_id,)).fetchone()["status"]
        if st != "coletando":
            return False
        pend = cx.execute("SELECT count(*) AS n FROM tarefa WHERE investigacao_id=%s AND status IN "
                          "('pendente','executando')", (inv_id,)).fetchone()["n"]
        if pend:
            return False
        cx.execute("UPDATE investigacao SET status='coletada' WHERE id=%s", (inv_id,))
        if enfileirar_fechamento:
            cx.execute("INSERT INTO job (tipo, investigacao_id) VALUES ('fechar', %s) ON CONFLICT DO NOTHING",
                       (inv_id,))
        return True


def executar(inv_id: int, threads: int | None = None, parar_apos: int | None = None, progresso=None):
    """CLI: executa (ou retoma) as tarefas pendentes de uma investigação, pela mesma fila do worker."""
    with conectar() as cx:
        devolver_leases_vencidos(cx, inv_id)
        # pausada e cancelada não são retomadas aqui: isso é `servicos.retomar`
        cx.execute("UPDATE investigacao SET status='coletando' WHERE id=%s AND status IN ('na_fila','parcial')",
                   (inv_id,))
        insts = {r["instancia_id"]: r for r in cx.execute(
            "SELECT DISTINCT c.instancia_id, i.concorrencia FROM conta c JOIN instancia i ON i.id=c.instancia_id "
            "WHERE c.investigacao_id=%s", (inv_id,))}
    n = threads or max(1, min(8, sum(i["concorrencia"] for i in insts.values())))
    feitas = [0]
    lock = threading.Lock()

    def trabalhador():
        clientes = Clientes()
        try:
            with conectar() as cx:
                while True:
                    with lock:
                        if parar_apos is not None and feitas[0] >= parar_apos:
                            return
                    t = pegar_tarefa(cx, inv_id)
                    if not t:
                        return
                    executar_tarefa(cx, t, clientes)
                    with lock:
                        feitas[0] += 1
                        if progresso:
                            progresso(feitas[0])
        finally:
            clientes.fechar()

    ths = [threading.Thread(target=trabalhador, daemon=True) for _ in range(n)]
    for th in ths:
        th.start()
    for th in ths:
        th.join()
    with conectar() as cx:
        if not concluir_se_terminou(cx, inv_id, enfileirar_fechamento=False):
            # parou antes do fim: 'parcial', salvo se foi pausada ou cancelada
            cx.execute("UPDATE investigacao SET status='parcial' WHERE id=%s AND status='coletando'", (inv_id,))
    return feitas[0]

"""Coleta em etapas, retomável, com cursor de tempo e releitura de consistência.

Cada tarefa = (conta, fatia [inicio, fim)). O checkpoint é o cursor de tempo (modos epoch) ou a
posição dentro do dia em ordem decrescente (modo dia), gravado a cada página.
"""
from __future__ import annotations

import os
import threading
import time
import zlib
from datetime import datetime, timedelta, timezone

from . import merkle, redigir, sigilo
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
        self.cx, self.cli, self.inv, self.t, self.inst = cx, cli, inv, tarefa, inst
        self.cofre = sigilo.Cofre(inv["id"], "coleta")
        self.conta = sigilo.abrir_conta(self.cofre, conta)
        self.realm = conta["realm"]
        # corpo minimizado (§6.1): inteiro nas contas do alvo; na varredura, só as linhas aproveitadas
        self._guardar = self._aceitar if conta["via"] == "varredura" else "inteiro"
        self.sem_dateto = (inst["sondas"] or {}).get("sem_dateTo", False)
        self.alvo = alvo            # (tipo, digitos) para filtrar a varredura de falhas sem userId
        self.limite_atingido = False
        self.divergencias = 0

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

    def _eventos(self, params: list[tuple[str, str]]) -> list[dict]:
        evs = self.cli.eventos(self.realm, params, self._guardar)
        for e in evs:
            e["id_g"] = sigilo.id_gravado(self.cofre, e["id"])
        return evs

    def _conteudo(self, e: dict) -> tuple[bytes, str]:
        """Forma canônica do evento como recebido e o HMAC do conteúdo (compara sem servir de oráculo)."""
        c = merkle.canonico(e)
        return c, self.cofre.ps("conteudo", c.decode())

    def gravar(self, evs: list[dict]) -> int:
        """Grava cifrado (DEK da investigação): em claro só o técnico, os pseudônimos de conta, IP e sessão, a folha
        (compromisso com sal) e o HMAC do conteúdo. Evento já gravado com conteúdo diferente vira versão divergente
        (§6.1 item 4): nada é descartado em silêncio."""
        linhas = [e for e in evs if self._aceitar(e)]
        if not linhas:
            return 0
        cf, inst = self.cofre, self.inst["id"]
        ja = {r["id"]: r["hash_conteudo"] for r in self.cx.execute(
            "SELECT id, hash_conteudo FROM evento WHERE investigacao_id=%s AND instancia_id=%s AND realm=%s "
            "AND id = ANY(%s)", (self.inv["id"], inst, self.realm, [e["id_g"] for e in linhas]))}
        novos = []
        for e in linhas:
            canon, h = self._conteudo(e)
            if e["id_g"] in ja:
                if ja[e["id_g"]] and ja[e["id_g"]] != h:
                    self.guardar_divergente(e, h, "conteudo")
                continue
            sal = os.urandom(32)
            bruto = {k: v for k, v in e.items() if k != "id_g"}
            novos.append((self.inv["id"], inst, self.realm, e["id_g"], self.conta["id"], e["time"], e["type"],
                          e.get("clientId"), e.get("error"),
                          sigilo.cifrar_evento(cf, inst, self.realm, e["id_g"], bruto, sal=sal.hex()),
                          cf.ps("conta", e.get("userId")), cf.ps("ip", e.get("ipAddress")),
                          cf.ps("sessao", e.get("sessionId")), merkle.folha(sal, canon), h))
        with self.cx.cursor() as cur:
            cur.executemany(
                "INSERT INTO evento (investigacao_id, instancia_id, realm, id, conta_id, time_ms, type, client_id, "
                "error, cifrado, ps_conta, ps_ip, ps_sessao, folha, hash_conteudo) "
                "VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s) ON CONFLICT DO NOTHING", novos)
        return len(linhas)

    def guardar_divergente(self, e: dict, h: str, tipo: str):
        did = self.cx.execute("SELECT nextval('evento_divergente_id_seq') AS n").fetchone()["n"]
        r = self.cx.execute(
            "INSERT INTO evento_divergente (id, investigacao_id, instancia_id, realm, evento_id, conta_id, tarefa_id, "
            "time_ms, tipo, hash_conteudo, cifrado) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s) ON CONFLICT DO NOTHING "
            "RETURNING id",
            (did, self.inv["id"], self.inst["id"], self.realm, e["id_g"], self.conta["id"], self.t["id"], e["time"],
             tipo, h, self.cofre.cifrar("evento_divergente", "cifrado", did,
                                        {"bruto": {k: v for k, v in e.items() if k != "id_g"}}))).fetchone()
        if r:
            self.divergencias += 1
            from .db import trilha
            trilha(self.cx, "coletor", "evento_divergente", self.inv["id"], tarefa=self.t["id"], tipo=tipo,
                   divergente=did)

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
                evs = [e for e in self._eventos(self._base() + [
                    ("dateFrom", str(T)), ("direction", "asc"), ("max", str(PONTUAL))]) if e["time"] == T]
            else:
                evs = self._eventos(self._base() + [("dateFrom", str(T)), ("dateTo", str(T)),
                                                                   ("max", str(PONTUAL))])
            if len(evs) >= PONTUAL:
                self.limite_atingido = True
            ids = {e["id_g"] for e in evs}
            if ids == anterior:
                return evs
            anterior = ids
        return evs

    def rodar_epoch(self, coletar=True) -> dict[str, dict]:
        asc = self.t["modo"] == "epoch_asc"
        ini, fim = self.t["inicio_ms"], self.t["fim_ms"]
        cursor = self.t["cursor_ms"] if (coletar and self.t["cursor_ms"] is not None) else (ini if asc else fim - 1)
        vistos: dict[str, dict] = {}
        while (cursor < fim) if asc else (cursor >= ini):
            p = self._base() + [("max", str(PAGINA)), ("first", "0")]
            if asc:
                p += [("dateFrom", str(cursor)), ("direction", "asc")]
                if not self.sem_dateto:
                    p.append(("dateTo", str(fim - 1)))
            else:
                p += [("dateFrom", str(ini)), ("dateTo", str(cursor)), ("direction", "desc")]
            pag = self._eventos(p)
            if asc and self.sem_dateto:
                pag = [e for e in pag if e["time"] < fim]
            if len(pag) < PAGINA:
                vistos.update({e["id_g"]: e for e in pag if self._aceitar(e)})
                if coletar:
                    self.gravar(pag)
                    self.checkpoint(cursor_ms=fim if asc else ini - 1)
                break
            T = pag[-1]["time"]
            parte = [e for e in pag if (e["time"] < T if asc else e["time"] > T)]
            mesmo_ms = self._pontual(T)
            vistos.update({e["id_g"]: e for e in parte + mesmo_ms if self._aceitar(e)})
            if coletar:
                self.gravar(parte + mesmo_ms)
            cursor = T + 1 if asc else T - 1
            if coletar:
                self.checkpoint(cursor_ms=cursor)
        return vistos

    # ---- modo dia: só yyyy-MM-dd, ordem decrescente, posição dentro do dia
    def rodar_dia(self, coletar=True) -> dict[str, dict]:
        desl = ((self.inst["sondas"] or {}).get("S6_fuso") or {}).get("deslocamento_horas", 0.0)
        # dia do servidor que contém a fatia
        dia = datetime.fromtimestamp((self.t["inicio_ms"] + desl * 3600_000) / 1000, timezone.utc).date()
        d1, d2 = dia.isoformat(), (dia + timedelta(days=1)).isoformat()
        # dateTo = dia seguinte cobre tanto "fim do dia" (26.x) quanto "meia-noite" (18.x); o excesso é filtrado.
        # Sem epoch não há consulta pontual: o dia é lido numa página grande (PONTUAL), porque a paginação por
        # posição não é estável entre eventos com o mesmo time. Página cheia continua por posição e a
        # releitura (obrigatória neste modo) aponta divergência, se houver.
        first = self.t["offset_n"] if coletar else 0
        vistos: dict[str, dict] = {}
        while True:
            pag = self._eventos(self._base() + [("dateFrom", d1), ("dateTo", d2),
                                                               ("first", str(first)), ("max", str(PONTUAL))])
            vistos.update({e["id_g"]: e for e in pag if self._aceitar(e)})
            if coletar:
                self.gravar(pag)
            first += len(pag)
            if coletar:
                self.checkpoint(offset_n=first)
            if len(pag) < PONTUAL:
                break
        return vistos

    def rodar(self, coletar=True) -> dict[str, dict]:
        """Lê a fatia; devolve os eventos aceitos por id gravado."""
        return self.rodar_dia(coletar) if self.t["modo"] == "dia" else self.rodar_epoch(coletar)

    # ---- releitura de consistência
    def precisa_reler(self, expiracao_s: int | None) -> bool:
        if self.t["modo"] == "dia":
            return True
        if expiracao_s and self.t["inicio_ms"] < time.time() * 1000 - expiracao_s * 1000 + 2 * DIA_MS:
            return True
        return zlib.crc32(str(self.t["id"]).encode()) % 10 == 0   # amostra de 10%

    def reler(self, expiracao_s: int | None) -> str:
        """Relê a fatia e compara ids **e conteúdo** com o que foi gravado (§6.1 item 4).

        ok | expirado | divergente (conjuntos diferentes) | divergente_conteudo (mesmo id, conteúdo diferente:
        as duas versões ficam guardadas) | possivel_alteracao (Keycloak <= 21: o id vem do conteúdo, então um evento
        alterado aparece como par faltando + extra com o mesmo horário e tipo)."""
        def gravados() -> dict[str, dict]:
            if self.conta["via"] == "realm":   # realm inteiro: inclui eventos gravados sob contas localizadas
                q, a = ("SELECT id, hash_conteudo, time_ms, type FROM evento WHERE investigacao_id=%s AND "
                        "instancia_id=%s AND realm=%s AND time_ms>=%s AND time_ms<%s",
                        (self.inv["id"], self.inst["id"], self.realm, self.t["inicio_ms"], self.t["fim_ms"]))
            else:
                q, a = ("SELECT id, hash_conteudo, time_ms, type FROM evento WHERE investigacao_id=%s AND "
                        "conta_id=%s AND time_ms>=%s AND time_ms<%s",
                        (self.inv["id"], self.conta["id"], self.t["inicio_ms"], self.t["fim_ms"]))
            return {r["id"]: r for r in self.cx.execute(q, a)}
        for tentativa in (1, 2):
            relidos = self.rodar(coletar=False)
            g = gravados()
            extras, faltando = relidos.keys() - g.keys(), g.keys() - relidos.keys()
            difs = [(relidos[i], h) for i in relidos.keys() & g.keys()
                    if g[i]["hash_conteudo"] and (h := self._conteudo(relidos[i])[1]) != g[i]["hash_conteudo"]]
            if difs:
                for e, h in difs:
                    self.guardar_divergente(e, h, "conteudo")
                return "divergente_conteudo"
            if extras and faltando and any(i.startswith("h:") for i in extras):
                antes = {(g[i]["time_ms"], g[i]["type"]) for i in faltando}
                pares = [relidos[i] for i in extras if (relidos[i]["time"], relidos[i]["type"]) in antes]
                if pares:
                    for e in pares:
                        self.guardar_divergente(e, self._conteudo(e)[1], "possivel_alteracao")
                    return "possivel_alteracao"
            if not extras and not faltando:
                return "ok"
            if not extras and faltando:
                limite = time.time() * 1000 - (expiracao_s or 0) * 1000
                if expiracao_s and all(g[i]["time_ms"] < limite for i in faltando):
                    return "expirado"
            if tentativa == 1:   # recoleta uma vez a fatia inteira
                self.t["cursor_ms"], self.t["offset_n"] = None, 0
                self.rodar(coletar=True)
        return "divergente"


def selar(cx, inv_id: int, t: dict, origem: str = "coleta") -> dict:
    """Selo da fatia: raiz Merkle das folhas dos eventos da conta no intervalo, ordenadas. Vai para a tabela selo
    (só inserção) e para a trilha."""
    folhas = [r["folha"] for r in cx.execute(
        "SELECT folha FROM evento WHERE investigacao_id=%s AND conta_id=%s AND time_ms>=%s AND time_ms<%s "
        "ORDER BY folha", (inv_id, t["conta_id"], t["inicio_ms"], t["fim_ms"]))]
    if any(f is None for f in folhas):
        raise RuntimeError(f"tarefa {t['id']}: evento sem folha (dados anteriores à W0b não migrados)")
    r = merkle.raiz(folhas)
    v = cx.execute("SELECT coalesce(max(versao), 0) + 1 AS v FROM selo WHERE tarefa_id=%s", (t["id"],)).fetchone()["v"]
    cx.execute("INSERT INTO selo (investigacao_id, tarefa_id, conta_id, inicio_ms, fim_ms, n_eventos, raiz, versao, "
               "origem) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)",
               (inv_id, t["id"], t["conta_id"], t["inicio_ms"], t["fim_ms"], len(folhas), r, v, origem))
    from .db import trilha
    trilha(cx, "coletor", "selar_fatia", inv_id, tarefa=t["id"], raiz=r, eventos=len(folhas), versao=v, origem=origem)
    return {"raiz": r, "eventos": len(folhas), "versao": v}


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
    from . import chaves
    col = None
    try:
        alvo = (inv["tipo"], chaves.alvo(inv, "coleta")) if inv["parametros"].get("varredura") else None
        col = Coletor(cx, clientes.de(inst, inv["id"]), inv, conta, t, inst, alvo)
        col.rodar()
        rel = col.reler(expiracao) if col.precisa_reler(expiracao) else None
        if col.divergencias and rel != "possivel_alteracao":
            rel = "divergente_conteudo"   # conteúdo diferente também numa recoleta durante a própria coleta
        n_ev = cx.execute("SELECT count(*) AS n FROM evento WHERE investigacao_id=%s AND conta_id=%s "
                          "AND time_ms>=%s AND time_ms<%s",
                          (inv["id"], conta["id"], t["inicio_ms"], t["fim_ms"])).fetchone()["n"]
        status = "limite" if col.limite_atingido else "concluida"
        with cx.transaction():   # o selo e o status da fatia entram juntos
            cx.execute("UPDATE tarefa SET status=%s, releitura=%s, eventos=%s, erro=NULL, atualizado=now() "
                       "WHERE id=%s", (status, rel, n_ev, t["id"]))
            selar(cx, inv["id"], t)
    except Interrompida as e:
        # pausa: volta à fila com o cursor salvo no último checkpoint; cancelamento: encerra a fatia
        status = "pendente" if e.estado == "pausada" else "cancelada"
        cx.execute("UPDATE tarefa SET status=%s, tentativas=tentativas-1, lease_ate=NULL WHERE id=%s",
                   (status, t["id"]))
    except (chaves.Recusado, chaves.ChaveiroIndisponivel):
        # sem DEK (a investigação saiu de coleta, ou o chaveiro caiu): a fatia volta à fila com o cursor salvo,
        # sem gastar tentativa
        status = "pendente"
        cx.execute("UPDATE tarefa SET status='pendente', tentativas=tentativas-1, lease_ate=NULL WHERE id=%s",
                   (t["id"],))
        time.sleep(2)
    except SemPermissao as e:
        status = "sem_permissao"
        cx.execute("UPDATE tarefa SET status='sem_permissao', erro=%s WHERE id=%s", (redigir.erro(str(e)), t["id"]))
    except Exception as e:  # noqa: BLE001 — erro inesperado não pode deixar a fatia presa em 'executando'
        status = "falhou" if t["tentativas"] >= 3 else "pendente"
        erro = str(e) if isinstance(e, (FalhaTemporaria, ErroKC)) else f"{type(e).__name__}: {e}"
        cx.execute("UPDATE tarefa SET status=%s, erro=%s, erro_cifrado=%s WHERE id=%s",
                   (status, redigir.erro(erro)[:500], col.cofre.cifrar("tarefa", "erro", t["id"], erro) if col else None,
                    t["id"]))
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

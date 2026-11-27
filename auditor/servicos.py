"""Camada de serviços: casos de uso sobre as investigações, usados pela CLI e (na W1) pela API.

Aqui ficam as transições de estado e a trilha. Autorização por perfil, segregação e quatro olhos entram na W1, também
aqui, para valer igual em qualquer porta.

Estados de coleta: na_fila → coletando ⇄ pausada → coletada → concluida | concluida_com_lacunas | parcial;
qualquer estado ainda não concluído → cancelada.
"""
from __future__ import annotations

import threading
import time
from datetime import timedelta

from psycopg.types.json import Jsonb

from . import coleta, investigar, redigir
from .db import conectar, trilha

LEASE_JOB = timedelta(minutes=30)
FINAIS = ("concluida", "concluida_com_lacunas", "cancelada")


class TransicaoInvalida(Exception):
    pass


def _mudar(cx, inv_id: int, de: tuple[str, ...], para: str, operador: str, acao: str, **detalhe) -> str:
    with cx.transaction():
        atual = cx.execute("SELECT status FROM investigacao WHERE id=%s FOR UPDATE", (inv_id,)).fetchone()
        if not atual or atual["status"] not in de:
            raise TransicaoInvalida(f"investigação {inv_id} está '{atual['status'] if atual else 'inexistente'}';"
                                    f" '{acao}' exige {', '.join(de)}")
        cx.execute("UPDATE investigacao SET status=%s WHERE id=%s", (para, inv_id))
        trilha(cx, operador, acao, inv_id, de=atual["status"], para=para, **detalhe)
        return atual["status"]


# ------------------------------------------------------------------ casos de uso
def enfileirar(inv_id: int, operador: str, contas: list[tuple[str, str, str]] | None = None) -> int:
    """Põe a preparação (descoberta, localização, plano) na fila do worker; a coleta começa sozinha depois."""
    param = {}
    if contas:   # userIds informados: cifrados com a DEK (a abertura acabou de recebê-la)
        import base64
        from .sigilo import Cofre
        param["contas_cifradas"] = base64.b64encode(
            Cofre(inv_id, "abrir").cifrar("job", "contas", inv_id, [list(c) for c in contas])).decode()
    with conectar() as cx:
        j = cx.execute("INSERT INTO job (tipo, investigacao_id, parametros) VALUES ('preparar', %s, %s) "
                       "ON CONFLICT DO NOTHING RETURNING id", (inv_id, Jsonb(param))).fetchone()
        trilha(cx, operador, "enfileirar_investigacao", inv_id)
        return j["id"] if j else 0


def iniciar_coleta(inv_id: int, operador: str):
    with conectar() as cx:
        _mudar(cx, inv_id, ("na_fila",), "coletando", operador, "iniciar_coleta")


def pausar(inv_id: int, operador: str):
    """A coleta para no próximo checkpoint de cada fatia em andamento; nada se perde."""
    with conectar() as cx:
        _mudar(cx, inv_id, ("coletando",), "pausada", operador, "pausar_coleta")


def retomar(inv_id: int, operador: str):
    with conectar() as cx:
        _mudar(cx, inv_id, ("pausada", "parcial", "coletando"), "coletando", operador, "retomar_coleta")
        coleta.devolver_leases_vencidos(cx, inv_id)


def cancelar(inv_id: int, operador: str, motivo: str):
    if not motivo or len(motivo.strip()) < 5:
        raise ValueError("Motivo do cancelamento obrigatório")
    with conectar() as cx:
        with cx.transaction():
            _mudar(cx, inv_id, ("na_fila", "coletando", "pausada", "coletada", "parcial"), "cancelada", operador,
                   "cancelar_investigacao", motivo=motivo)
            cx.execute("UPDATE tarefa SET status='cancelada' WHERE investigacao_id=%s AND status='pendente'",
                       (inv_id,))
            cx.execute("UPDATE job SET status='concluido', erro='investigação cancelada', atualizado=now() "
                       "WHERE investigacao_id=%s AND status='pendente'", (inv_id,))


def fechar(inv_id: int) -> dict | None:
    """Sessões e alterações da conta, cobertura e status final. Um processo por vez por investigação."""
    from .consolidar import extras_conta
    with conectar() as cx:
        cx.execute("SELECT pg_advisory_lock(%s, %s)", (coleta.CHAVE_INV, inv_id))
        try:
            st = cx.execute("SELECT status FROM investigacao WHERE id=%s", (inv_id,)).fetchone()["status"]
            if st in coleta.ESTADOS_PARADA:
                return None
            extras_conta(inv_id)
            r = investigar.fechar(inv_id)
            from .pseudonimos import atribuir
            from .sigilo import Cofre
            r["pseudonimos"] = atribuir(cx, Cofre(inv_id, "fechar"))
            cx.execute("UPDATE job SET status='concluido', atualizado=now() WHERE investigacao_id=%s "
                       "AND tipo='fechar' AND status='pendente'", (inv_id,))
            return r
        finally:
            cx.execute("SELECT pg_advisory_unlock(%s, %s)", (coleta.CHAVE_INV, inv_id))


# ------------------------------------------------------------------ jobs e worker
def pegar_job(cx):
    with cx.transaction():
        return cx.execute("""
            WITH c AS (SELECT id FROM job WHERE status='pendente' OR (status='executando' AND lease_ate < now())
                       ORDER BY id FOR UPDATE SKIP LOCKED LIMIT 1)
            UPDATE job j SET status='executando', tentativas=j.tentativas+1, lease_ate=now()+%s, atualizado=now()
            FROM c WHERE j.id=c.id RETURNING j.*""", (LEASE_JOB,)).fetchone()


def executar_job(cx, j: dict):
    try:
        if j["tipo"] == "preparar":
            contas = j["parametros"].get("contas", [])
            if j["parametros"].get("contas_cifradas"):
                import base64
                from .sigilo import Cofre
                contas = Cofre(j["investigacao_id"], "preparar").decifrar(
                    "job", "contas", j["investigacao_id"], base64.b64decode(j["parametros"]["contas_cifradas"]))
            investigar.preparar(j["investigacao_id"], [tuple(c) for c in contas])
            iniciar_coleta(j["investigacao_id"], "worker")
        elif j["tipo"] == "fechar":
            fechar(j["investigacao_id"])
        else:
            raise ValueError(f"tipo de job desconhecido: {j['tipo']}")
        cx.execute("UPDATE job SET status='concluido', erro=NULL, atualizado=now() WHERE id=%s", (j["id"],))
    except Exception as e:  # noqa: BLE001
        novo = "falhou" if j["tentativas"] >= 3 else "pendente"
        cx.execute("UPDATE job SET status=%s, erro=%s, atualizado=now() WHERE id=%s",
                   (novo, redigir.erro(f"{type(e).__name__}: {e}")[:500], j["id"]))


def worker(threads: int = 4, ocioso_s: float | None = None, parar: threading.Event | None = None,
           ao_fazer=None) -> int:
    """Worker contínuo: jobs primeiro, depois tarefas de qualquer investigação em coleta (rodízio).
    Com `ocioso_s`, encerra quando passar esse tempo sem trabalho (testes e execuções pontuais)."""
    parar = parar or threading.Event()
    feitas = [0]
    lock = threading.Lock()
    with conectar() as cx:
        coleta.devolver_leases_vencidos(cx)

    def laco(n: int):
        clientes = coleta.Clientes()
        ultimo, faxina = time.monotonic(), time.monotonic()
        try:
            with conectar() as cx:
                while not parar.is_set():
                    j = pegar_job(cx)
                    if j:
                        executar_job(cx, j)
                        o_que = f"job {j['tipo']} #{j['investigacao_id']}"
                    else:
                        t = coleta.pegar_tarefa(cx)
                        if t:
                            coleta.executar_tarefa(cx, t, clientes)
                            coleta.concluir_se_terminou(cx, t["investigacao_id"])
                            o_que = f"tarefa {t['id']} #{t['investigacao_id']}"
                        else:
                            o_que = None
                    agora = time.monotonic()
                    if o_que:
                        ultimo = agora
                        with lock:
                            feitas[0] += 1
                        if ao_fazer:
                            ao_fazer(o_que)
                        continue
                    if ocioso_s is not None and agora - ultimo > ocioso_s:
                        return
                    if n == 0 and agora - faxina > 60:   # uma thread cuida dos leases vencidos
                        coleta.devolver_leases_vencidos(cx)
                        faxina = agora
                    parar.wait(1.0)
        finally:
            clientes.fechar()

    ths = [threading.Thread(target=laco, args=(n,), daemon=True) for n in range(threads)]
    for th in ths:
        th.start()
    for th in ths:
        th.join()
    return feitas[0]

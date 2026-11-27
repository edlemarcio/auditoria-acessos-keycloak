"""Apoio da gestão (W2, docs/W2_CONTRATO.md): dias úteis, estado público, linha do tempo, expiração e estimativa,
acompanhamento, notificações (e-mail só em logs/email.jsonl), destruição da DEK, prazos da preservação urgente,
escalonamento dos pedidos parados e batimento dos workers.

Sem regra de permissão: quem chama (auditor/casos.py) já conferiu perfil, designação e segregação. O worker roda
`faxina` no laço de limpeza; os testes chamam as mesmas funções com um relógio simulado (`agora`).

  AUDITOR_EMAIL   arquivo JSONL do e-mail (padrão logs/email.jsonl)
"""
from __future__ import annotations

import json
import math
import os
import socket
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path

from .db import trilha

DIA_MS = 86400_000
PRAZO_APROVACAO_DU = 2          # prazo normal de uma aprovação, em dias úteis (para a expiração dos eventos)
ESCALONA_DU, DESTROI_DU, PRORROGA_DU = 3, 5, 10   # preservação urgente (§4.4)
PEDIDO_PARADO_DU = 1            # pedido sem decisão: substituto em 1 dia útil, coordenador em 2 (§4.2)
REQ_POR_TAREFA = 2.0            # média observada de requisições por fatia de um dia (eventos + sessões)
ESTADOS_PUBLICOS = {"abrindo": "preparando", "na_fila": "preparando", "coletada": "fechando", "parcial": "falhou"}
_lock_email = threading.Lock()


def agora_utc() -> datetime:
    return datetime.now(timezone.utc)


def somar_dias_uteis(t: datetime, n: int) -> datetime:
    """Soma n dias úteis (segunda a sexta; feriados ficam para o calendário institucional)."""
    d = t
    while n > 0:
        d += timedelta(days=1)
        if d.weekday() < 5:
            n -= 1
    return d


def iso(t) -> str | None:
    return t.astimezone(timezone.utc).isoformat() if t else None


# ------------------------------------------------------------------ estado e linha do tempo
def status_publico(i: dict) -> str:
    if i.get("lacrada"):
        return "preservacao_urgente"
    return ESTADOS_PUBLICOS.get(i["status"], i["status"])


ACAO_ESTADO = {
    "salvar_rascunho": "rascunho", "enviar_rascunho": "aguardando_aprovacao",
    "aprovar_investigacao": "aprovada", "devolver_investigacao": "devolvida", "recusar_investigacao": "recusada",
    "reenviar_investigacao": "aguardando_aprovacao", "autorizar_preservacao": "preservacao_urgente",
    "iniciar_coleta_pedida": "preparando", "iniciar_coleta": "coletando", "pausar_coleta": "pausada",
    "retomar_coleta": "coletando", "cancelar_pedido": "cancelada", "cancelar_investigacao": "cancelada",
    "descartar_rascunho": "descartada", "destruir_dek": "recusada",
}


def linha_do_tempo(cx, i: dict, cofre=None) -> list[dict]:
    """Mudanças de estado vistas na trilha da investigação. Com `cofre` (quem pode ler), traz o motivo."""
    from .sigilo import livres_trilha
    nomes = {r["sub"]: r["username"] for r in cx.execute("SELECT sub, username FROM usuario")}
    out = []
    for r in cx.execute("SELECT * FROM trilha_auditoria WHERE cadeia=%s ORDER BY seq", (i["id"],)):
        d = r["detalhe"] or {}
        if r["acao"] == "pedir_investigacao":
            st = "rascunho" if d.get("rascunho") else "aguardando_aprovacao"
        elif r["acao"] == "fechar_investigacao":
            st = ESTADOS_PUBLICOS.get(d.get("status"), d.get("status"))
        else:
            st = ACAO_ESTADO.get(r["acao"])
        if not st:
            continue
        item = {"status": st, "quando": iso(r["quando"]), "por": nomes.get(r["operador"], r["operador"])}
        if cofre is not None and r["livres_cifrado"] is not None:
            try:
                m = livres_trilha(cofre, i, r).get("motivo")
                if m:
                    item["motivo"] = m["valor"]
            except Exception:  # noqa: BLE001  (DEK destruída: o motivo some com ela)
                pass
        out.append(item)
    return out


# ------------------------------------------------------------------ expiração e estimativa
def _snapshots(cx, instancias: list[str] | None) -> list[dict]:
    return [s for s in cx.execute(
        "SELECT DISTINCT ON (s.instancia_id, s.realm) s.*, i.nome, i.req_por_s, i.concorrencia FROM realm_snapshot s "
        "JOIN instancia i ON i.id=s.instancia_id ORDER BY s.instancia_id, s.realm, s.lido_em DESC").fetchall()
        if not instancias or s["nome"] in instancias]


def expiracao(cx, inicio_ms: int, instancias: list[str] | None, agora: datetime | None = None) -> list[dict]:
    """Por realm: desde quando ainda há eventos e se os mais antigos do período somem antes do prazo normal de
    aprovação (o que recomenda a preservação urgente)."""
    agora = agora or agora_utc()
    limite = somar_dias_uteis(agora, PRAZO_APROVACAO_DU)
    out = []
    for s in _snapshots(cx, instancias):
        if not s["visivel"] or s["status"] in ("eventos_nao_gravados", "sem_permissao", "esperado_invisivel"):
            continue
        exp = (s["config"] or {}).get("eventsExpiration")
        desde = antes = None
        if exp:
            desde = agora - timedelta(seconds=int(exp))
            mais_antigo = max(datetime.fromtimestamp(inicio_ms / 1000, timezone.utc), desde)
            antes = mais_antigo + timedelta(seconds=int(exp)) < limite
        out.append({"instancia": s["nome"], "realm": s["realm"], "eventos_desde": iso(desde),
                    "expira_antes_da_aprovacao": bool(antes)})
    return out


def estimar(cx, inicio_ms: int, fim_ms: int, instancias: list[str] | None, varredura: bool = False,
            base_dias: int = 0) -> dict:
    """Sem o identificador: uma conta por realm pesquisável (limite superior), uma fatia por dia."""
    fim = min(fim_ms, int(agora_utc().timestamp() * 1000))
    dias = max(0, math.ceil((fim - (inicio_ms - base_dias * DIA_MS)) / DIA_MS))
    por_inst: dict[str, list] = {}
    for s in _snapshots(cx, instancias):
        if s["visivel"] and s["status"] not in ("eventos_nao_gravados", "sem_permissao", "esperado_invisivel"):
            por_inst.setdefault(s["nome"], [0, s["req_por_s"]])[0] += 1
    tarefas, segundos = 0, 0
    for n, rps in por_inst.values():
        t = dias * n * (2 if varredura else 1)
        tarefas += t
        segundos = max(segundos, math.ceil(t * REQ_POR_TAREFA / max(float(rps), 0.1)))
    return {"tarefas": tarefas, "segundos": segundos}


# ------------------------------------------------------------------ acompanhamento ao vivo (§8.8)
def acompanhamento(cx, inv_id: int) -> dict:
    i = cx.execute("SELECT id, status, lacrada FROM investigacao WHERE id=%s", (inv_id,)).fetchone()
    insts: dict[str, dict] = {}
    total = feitas = falhas = retent = eventos = 0
    for r in cx.execute("SELECT ins.id, ins.nome, ins.req_por_s, t.status, count(*) n, "
                        "sum(greatest(t.tentativas - 1, 0)) ret, sum(t.eventos) ev FROM tarefa t "
                        "JOIN conta c ON c.id=t.conta_id JOIN instancia ins ON ins.id=c.instancia_id "
                        "WHERE t.investigacao_id=%s GROUP BY 1,2,3,4 ORDER BY 2", (inv_id,)):
        x = insts.setdefault(r["nome"], {"id": r["id"], "nome": r["nome"], "tarefas": {
            "pendente": 0, "executando": 0, "concluida": 0, "falhou": 0}, "req_por_s": 0.0,
            "orcamento_req_por_s": r["req_por_s"], "fora_do_ar_desde": None})
        st = {"limite": "concluida", "sem_permissao": "falhou", "cancelada": "falhou"}.get(r["status"], r["status"])
        x["tarefas"][st] = x["tarefas"].get(st, 0) + r["n"]
        total += r["n"]
        feitas += r["n"] if r["status"] not in ("pendente", "executando") else 0
        falhas += r["n"] if r["status"] in ("falhou", "sem_permissao") else 0
        retent += int(r["ret"] or 0)
        eventos += int(r["ev"] or 0)
    for x in insts.values():
        q = cx.execute("SELECT count(*) n, max(inicio) FILTER (WHERE status BETWEEN 200 AND 499) ok, "
                       "min(inicio) FILTER (WHERE status IS NULL OR status >= 500) ruim FROM requisicao "
                       "WHERE investigacao_id=%s AND instancia_id=%s AND inicio > now() - interval '2 minutes'",
                       (inv_id, x["id"])).fetchone()
        n10 = cx.execute("SELECT count(*) n FROM requisicao WHERE investigacao_id=%s AND instancia_id=%s AND "
                         "inicio > now() - interval '10 seconds'", (inv_id, x["id"])).fetchone()["n"]
        x["req_por_s"] = round(n10 / 10, 1)
        if q["ruim"] and (not q["ok"] or q["ok"] < q["ruim"]):
            x["fora_do_ar_desde"] = iso(q["ruim"])
        del x["id"]
    st = status_publico(i)
    pct = 100 if st in ("concluida", "concluida_com_lacunas") else (int(feitas * 100 / total) if total else 0)
    termino = None
    restantes = total - feitas
    if restantes and st == "coletando":
        rec = cx.execute("SELECT count(*) n FROM tarefa WHERE investigacao_id=%s AND status NOT IN "
                         "('pendente','executando') AND atualizado > now() - interval '60 seconds'",
                         (inv_id,)).fetchone()["n"]
        if rec:
            termino = iso(agora_utc() + timedelta(seconds=restantes * 60 / rec))
    return {"status": st, "progresso_pct": pct, "eventos": eventos, "instancias": list(insts.values()),
            "falhas": falhas, "retentativas": retent, "termino_estimado": termino}


# ------------------------------------------------------------------ notificações (§7.12)
ROTULO_EMAIL = {
    "pedido_recebido": "Há uma decisão pendente", "preservacao_urgente": "Há um pedido de preservação urgente",
    "pedido_devolvido": "Um pedido seu foi devolvido para correção", "pedido_aprovado": "Um pedido seu foi aprovado",
    "pedido_recusado": "Um pedido seu foi recusado", "designacao": "Você foi designado para uma investigação",
    "preservacao_autorizada": "Uma coleta lacrada foi autorizada", "preservacao_expira": "Uma preservação urgente "
    "vence em breve", "escalonamento": "Um pedido parado foi escalonado para você",
    "pacote_sem_mascara": "Há um pedido de pacote sem máscara", "decisao_pacote": "Houve decisão sobre um pacote",
    "coleta_concluida": "Uma coleta terminou", "coleta_falhou": "Uma coleta falhou",
    "papel_alterado": "Houve mudança de perfil no auditor", "dek_destruida": "Os dados de uma investigação foram "
    "destruídos", "recertificacao": "Há uma recertificação de perfis aberta",
}


def notificar(cx, subs, tipo: str, texto: str, inv_id: int | None = None):
    """Central de notificações + e-mail. O texto nunca leva identificador, máscara nem texto livre: só o tipo, o nº
    da investigação e o link. O e-mail vai para logs/email.jsonl (até haver SMTP institucional), endereçado ao `sub`
    do usuário (o SMTP resolve o endereço no envio)."""
    subs = sorted({s for s in subs if s})
    if not subs:
        return
    base = os.environ.get("AUDITOR_API_URL", "http://localhost:8000").rstrip("/")
    linhas = []
    for s in subs:
        cx.execute("INSERT INTO notificacao (sub, tipo, texto, investigacao_id) VALUES (%s,%s,%s,%s)",
                   (s, tipo, texto, inv_id))
        assunto = ROTULO_EMAIL.get(tipo, "Há uma novidade no auditor")
        linhas.append(json.dumps({"quando": iso(agora_utc()), "para_sub": s, "tipo": tipo,
                                  "assunto": f"[kc-auditor] {assunto}",
                                  "corpo": f"{assunto}" + (f" na investigação {inv_id}" if inv_id else "")
                                           + f". Acesse {base}/" + (f"investigacoes/{inv_id}" if inv_id else "")},
                                 ensure_ascii=False))
    p = Path(os.environ.get("AUDITOR_EMAIL", "logs/email.jsonl"))
    with _lock_email:
        p.parent.mkdir(parents=True, exist_ok=True)
        with p.open("a", encoding="utf-8") as f:
            f.write("\n".join(linhas) + "\n")


def com_papel(cx, papel: str, exceto=()) -> list[str]:
    return [r["sub"] for r in cx.execute(
        "SELECT sub FROM usuario WHERE %s = ANY(papeis) UNION SELECT sub FROM papel_visto WHERE %s = ANY(papeis)",
        (papel, papel)) if r["sub"] not in exceto]


def coordenadores(cx) -> list[str]:
    return [r["sub"] for r in cx.execute(
        "SELECT sub FROM usuario WHERE coordenador UNION SELECT sub FROM papel_visto WHERE coordenador")]


def designados(cx, inv_id: int, *funcoes_: str) -> list[str]:
    return [r["sub"] for r in cx.execute("SELECT sub FROM designacao WHERE investigacao_id=%s AND funcao = ANY(%s)",
                                         (inv_id, list(funcoes_)))]


def avisar_pedido(cx, inv_id: int, solicitante: str, preservacao: bool):
    """Pedido novo (ou reenviado) na fila: todos os aprovadores, menos quem pediu."""
    tipo = "preservacao_urgente" if preservacao else "pedido_recebido"
    notificar(cx, com_papel(cx, "aprovador", exceto=(solicitante,)), tipo,
              f"{'Preservação urgente' if preservacao else 'Pedido de investigação'} nº {inv_id} aguardando decisão",
              inv_id)


# ------------------------------------------------------------------ destruição da DEK
def destruir_dek(cx, inv_id: int, operador: str, fundamento: str, motivo: str | None = None,
                 desfecho: str = "recusada"):
    """Destruição criptográfica (§4.4): os envelopes das DEKs são apagados; eventos, contas, alvo e documento ficam
    ilegíveis. A coleta lacrada é encerrada. Registro na trilha com o fundamento."""
    from . import chaves
    with cx.transaction():
        n = cx.execute("UPDATE chave_investigacao SET envelope=''::bytea, destruida_em=now() WHERE investigacao_id=%s "
                       "AND destruida_em IS NULL", (inv_id,)).rowcount
        cx.execute("UPDATE investigacao SET status='recusada', lacrada=false, atualizado_em=now() WHERE id=%s",
                   (inv_id,))
        cx.execute("UPDATE tarefa SET status='cancelada' WHERE investigacao_id=%s AND status IN "
                   "('pendente','executando')", (inv_id,))
        cx.execute("UPDATE job SET status='concluido', erro='DEK destruída', atualizado=now() WHERE investigacao_id=%s "
                   "AND status IN ('pendente','executando')", (inv_id,))
        cx.execute("UPDATE preservacao SET encerrada_em=now(), desfecho=%s WHERE investigacao_id=%s AND "
                   "encerrada_em IS NULL", (desfecho, inv_id))
        cx.execute("UPDATE pedido SET status=%s, decidido_por=%s, decidido_em=now() WHERE investigacao_id=%s AND "
                   "status='aguardando'", ("recusado" if desfecho == "recusada" else "expirado", operador, inv_id))
        trilha(cx, operador, "destruir_dek", inv_id, fundamento=fundamento, envelopes=n, motivo=motivo)
        notificar(cx, designados(cx, inv_id, "solicitante", "investigador", "aprovador"), "dek_destruida",
                  f"Os dados da investigação {inv_id} foram destruídos ({fundamento.replace('_', ' ')})", inv_id)
    chaves.esquecer(inv_id)


# ------------------------------------------------------------------ prazos e escalonamento (laço do worker)
def vencer_prazos(cx, agora: datetime | None = None) -> dict:
    """Preservação urgente: escalona ao coordenador em 3 dias úteis e destrói a DEK em 5 sem decisão (ou no fim da
    prorrogação). Pedidos parados: substituto depois de 1 dia útil, coordenador depois de 2."""
    agora = agora or agora_utc()
    feito = {"destruidas": [], "escalonadas": [], "pedidos": []}
    for p in cx.execute("SELECT * FROM preservacao WHERE encerrada_em IS NULL ORDER BY investigacao_id").fetchall():
        inv = p["investigacao_id"]
        if agora >= p["destroi_em"]:
            destruir_dek(cx, inv, "sistema", "prazo_preservacao_sem_decisao", desfecho="expirada")
            feito["destruidas"].append(inv)
        elif agora >= p["escalona_em"] and not p["escalonada_em"]:
            with cx.transaction():
                if cx.execute("UPDATE preservacao SET escalonada_em=%s WHERE investigacao_id=%s AND escalonada_em "
                              "IS NULL", (agora, inv)).rowcount:
                    para = coordenadores(cx)
                    trilha(cx, "sistema", "escalonar_preservacao", inv, para=len(para), destroi_em=iso(p["destroi_em"]))
                    notificar(cx, para, "preservacao_expira", f"Preservação urgente nº {inv} sem decisão: os dados "
                              f"serão destruídos em {p['destroi_em']:%d/%m/%Y} se ninguém decidir", inv)
                    feito["escalonadas"].append(inv)
    for p in cx.execute("SELECT * FROM pedido WHERE status='aguardando' AND escalonamento < 2 ORDER BY id").fetchall():
        nivel = 2 if agora >= somar_dias_uteis(p["criado_em"], 2 * PEDIDO_PARADO_DU) else (
            1 if agora >= somar_dias_uteis(p["criado_em"], PEDIDO_PARADO_DU) else 0)
        if nivel <= p["escalonamento"]:
            continue
        with cx.transaction():
            if not cx.execute("UPDATE pedido SET escalonamento=%s, escalonado_em=%s WHERE id=%s AND escalonamento<%s",
                              (nivel, agora, p["id"], nivel)).rowcount:
                continue
            if nivel == 1:
                para = [r["substituto_sub"] for r in cx.execute("SELECT DISTINCT substituto_sub FROM substituto")]
            else:
                para = coordenadores(cx)
            para = [s for s in para if s != p["solicitante_sub"]]
            trilha(cx, "sistema", "escalonar_pedido", p["investigacao_id"], pedido=p["id"], nivel=nivel,
                   para=len(para))
            notificar(cx, para, "escalonamento", f"Pedido nº {p['id']} (investigação {p['investigacao_id']}) parado "
                      f"há mais de {nivel} dia(s) útil(eis): escalonado para você "
                      f"({'substituto' if nivel == 1 else 'coordenação'})", p["investigacao_id"])
            feito["pedidos"].append((p["id"], nivel))
    return feito


def faxina(cx, agora: datetime | None = None) -> dict:
    """Laço de limpeza do worker (a cada minuto): prazos, escalonamento, recertificações vencidas e vigia de papéis."""
    out = vencer_prazos(cx, agora)
    from . import kc_gestao
    if kc_gestao.configurado():
        try:
            out["recertificacoes"] = kc_gestao.vencer_recertificacoes(cx, agora)
            out["papeis"] = kc_gestao.vigiar(cx)
        except Exception as e:  # noqa: BLE001  (Keycloak fora do ar: tenta no próximo minuto)
            from .redigir import erro
            out["erro_vigia"] = erro(f"{type(e).__name__}: {e}")
    return out


def bater_ponto(cx, papel: str):
    cx.execute("INSERT INTO worker_visto (id, papel) VALUES (%s,%s) ON CONFLICT (id) DO UPDATE SET visto_em=now()",
               (f"{papel}@{socket.gethostname()}:{os.getpid()}", papel))


def filas(cx) -> dict:
    t = {r["status"]: r["n"] for r in cx.execute("SELECT status, count(*) n FROM tarefa GROUP BY 1")}
    j = {r["status"]: r["n"] for r in cx.execute("SELECT status, count(*) n FROM job GROUP BY 1")}
    return {"tarefas": {k: t.get(k, 0) for k in ("pendente", "executando", "falhou")},
            "jobs": {k: j.get(k, 0) for k in ("pendente", "executando", "falhou")}}


def workers(cx) -> list[dict]:
    return [{"papel": r["papel"], "visto_em": iso(r["visto_em"]), "id": r["id"]} for r in cx.execute(
        "SELECT * FROM worker_visto WHERE visto_em > now() - interval '1 day' ORDER BY visto_em DESC")]


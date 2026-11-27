"""Ciclo de uma investigação: abrir, preparar (descoberta + localização + plano), coletar, fechar cobertura."""
from __future__ import annotations

import json
import time
from datetime import datetime
from zoneinfo import ZoneInfo

from psycopg.types.json import Jsonb

from . import coleta, descoberta
from . import chaves, cripto, sigilo
from .db import SNAPSHOTS_DA_INVESTIGACAO, conectar, trilha
from .identificador import mascarar, normalizar
from .kc import ClienteKC

DIA_MS = 86400_000


def abrir(operador: str, justificativa: str, tipo: str, valor: str, inicio: str, fim: str,
          fuso: str = "America/Bahia", granularidade: str = "dia", instancias: list[str] | None = None,
          varredura: bool = False, base_dias: int = 0, anterior: int | None = None, status: str = "na_fila",
          solicitante_sub: str | None = None, origem: dict | None = None) -> int:
    if not justificativa or len(justificativa.strip()) < 5:
        raise ValueError("Justificativa obrigatória")
    dig = normalizar(tipo, valor)
    tz = ZoneInfo(fuso)
    ini = int(datetime.fromisoformat(inicio).replace(tzinfo=tz).timestamp() * 1000)
    fim_ = int(datetime.fromisoformat(fim).replace(tzinfo=tz).timestamp() * 1000)
    if len(fim) <= 10:   # data sem hora: inclui o dia inteiro
        fim_ += DIA_MS
    if fim_ <= ini:
        raise ValueError("Período inválido")
    h = chaves.hmac_alvo(tipo, dig)
    with conectar() as cx:
        # 'abrindo' até a DEK existir: o chaveiro só cria DEK de investigação em abertura e o alvo é cifrado com ela
        r = cx.execute("INSERT INTO investigacao (operador, justificativa, tipo, alvo_cifrado, alvo_hmac, "
                       "alvo_mascarado, inicio_ms, fim_ms, fuso, granularidade, parametros, execucao_anterior, status) "
                       "VALUES (%s,'',%s,''::bytea,%s,%s,%s,%s,%s,%s,%s,%s,'abrindo') RETURNING id",
                       (operador, tipo, h, mascarar(tipo, dig), ini, fim_, fuso, granularidade,
                        Jsonb({"instancias": instancias, "varredura": varredura, "base_dias": base_dias}),
                        anterior)).fetchone()
        dek = chaves.criar_deks(cx, r["id"])
        pub, priv = cripto.par_trilha()   # campos livres da trilha: qualquer serviço registra, só a DEK lê
        cx.execute("UPDATE investigacao SET alvo_cifrado=%s, justificativa_cifrada=%s, trilha_publica=%s, "
                   "trilha_privada_cifrada=%s, status='na_fila' WHERE id=%s",
                   (chaves.cifrar_alvo(r["id"], dek, dig),
                    cripto.cifrar_dek(dek, json.dumps(justificativa, ensure_ascii=False),
                                      cripto.aad(r["id"], "investigacao", "justificativa", r["id"])),
                    pub, cripto.cifrar_dek(dek, priv, cripto.aad(r["id"], "investigacao", "trilha_privada", r["id"])),
                    r["id"]))
        if status != "na_fila" or solicitante_sub or origem:
            cx.execute("UPDATE investigacao SET status=%s, solicitante_sub=%s, origem_externa=%s, origem_cifrada=%s "
                       "WHERE id=%s", (status, solicitante_sub, bool(origem),
                                       cripto.cifrar_dek(dek, json.dumps(origem, ensure_ascii=False),
                                                         cripto.aad(r["id"], "investigacao", "origem", r["id"]))
                                       if origem else None, r["id"]))
        trilha(cx, operador, "abrir_investigacao", r["id"], tipo=tipo, alvo=mascarar(tipo, dig),
               justificativa=justificativa, inicio=inicio, fim=fim)
        return r["id"]


def preparar(inv_id: int, contas_informadas: list[tuple[str, str, str]] | None = None) -> dict:
    """Descoberta, localização (atributo, username, histórico), quadro de contas e plano de tarefas."""
    with conectar() as cx:
        inv = cx.execute("SELECT * FROM investigacao WHERE id=%s", (inv_id,)).fetchone()
        dig = chaves.alvo(inv, "preparar")
        cf = sigilo.Cofre(inv_id, "preparar")
        nomes = inv["parametros"].get("instancias")
        insts = [i for i in cx.execute("SELECT * FROM instancia ORDER BY id").fetchall()
                 if not nomes or i["nome"] in nomes]
        resumo = {"instancias": {}, "contas": 0}
        snaps = {}
        for inst in insts:
            cli = ClienteKC(inst, inv_id, finalidade="preparar")
            try:
                realms = descoberta.descobrir(cx, inst, cli, inv_id)
                for s in realms:
                    snaps[(inst["id"], s["realm"])] = s
                achadas, erros = descoberta.localizar(cli, inst, realms, inv["tipo"], dig)
            finally:
                cli.fechar()
            for u in achadas:
                fed = "LDAP" if u.get("federationLink") else "local"
                sigilo.inserir_conta(cx, cf, inst["id"], u["realm"], u["id"], u["username"], u.get("email"),
                                     u.get("createdTimestamp"), u.get("enabled"), fed, u["via"])
                hist = (inv_id, inv["alvo_hmac"], inst["id"], u["realm"])
                cx.execute("INSERT INTO historico_identidade (alvo_hmac, instancia_id, realm, uid_hmac, cifrado) "
                           "VALUES (%s,%s,%s,%s,%s) ON CONFLICT (alvo_hmac, instancia_id, realm, uid_hmac) "
                           "DO UPDATE SET visto_em=now(), cifrado=EXCLUDED.cifrado",
                           (inv["alvo_hmac"], inst["id"], u["realm"], chaves.hmac_historico(*hist, u["id"]),
                            chaves.cifrar_historico(*hist, {"user_id": u["id"], "username": u["username"]})))
            # contas vistas em investigações anteriores e que não existem mais (excluídas)
            for h in cx.execute("SELECT * FROM historico_identidade WHERE alvo_hmac=%s AND instancia_id=%s",
                                (inv["alvo_hmac"], inst["id"])).fetchall():
                if h["cifrado"] is not None:
                    h = {**h, **chaves.decifrar_historico(inv_id, inv["alvo_hmac"], inst["id"], h["realm"],
                                                          h["cifrado"])}
                sigilo.inserir_conta(cx, cf, inst["id"], h["realm"], h["user_id"], h["username"],
                                     origem="histórico", via="historico")
            for nome_inst, realm, uid in contas_informadas or []:
                if nome_inst == inst["nome"] and uid == "*":   # realm inteiro (teste de carga)
                    sigilo.inserir_conta(cx, cf, inst["id"], realm, None, "(realm inteiro)", origem="teste",
                                         via="realm")
                elif nome_inst == inst["nome"]:
                    sigilo.inserir_conta(cx, cf, inst["id"], realm, uid, None, origem="informada", via="informada")
            if inv["parametros"].get("varredura"):
                for s in realms:
                    if s["visivel"] and s["status"] in ("ok", "federacao_sem_importacao"):
                        sigilo.inserir_conta(cx, cf, inst["id"], s["realm"], None, "(falhas sem userId)",
                                             origem="varredura", via="varredura")
            resumo["instancias"][inst["nome"]] = {"realms": len(realms), "erros": erros,
                                                  "contas": len(achadas)}
        contas = cx.execute("SELECT * FROM conta WHERE investigacao_id=%s", (inv_id,)).fetchall()
        resumo["contas"] = len(contas)
        # duplicidade no mesmo realm
        dup = cx.execute("SELECT instancia_id, realm, count(*) n FROM conta WHERE investigacao_id=%s "
                         "AND via IN ('atributo','username') GROUP BY 1,2 HAVING count(*)>1", (inv_id,)).fetchall()
        resumo["duplicidades"] = [(d["instancia_id"], d["realm"], d["n"]) for d in dup]
        base = inv["parametros"].get("base_dias") or 0
        inv_plano = {**inv, "inicio_ms": inv["inicio_ms"] - base * DIA_MS}
        insts_d = {i["id"]: i for i in insts}
        coleta.planejar(cx, inv_plano, contas, insts_d, snaps)
        resumo["tarefas"] = cx.execute("SELECT count(*) n FROM tarefa WHERE investigacao_id=%s",
                                       (inv_id,)).fetchone()["n"]
        cx.execute("UPDATE investigacao SET status='na_fila' WHERE id=%s", (inv_id,))
        trilha(cx, inv["operador"], "preparar_investigacao", inv_id, contas=len(contas),
               tarefas=resumo["tarefas"])
        return resumo


def fechar(inv_id: int) -> dict:
    """Calcula a cobertura por par realm × conta e o status final."""
    agora = int(time.time() * 1000)
    with conectar() as cx:
        inv = cx.execute("SELECT * FROM investigacao WHERE id=%s", (inv_id,)).fetchone()
        cx.execute("DELETE FROM cobertura WHERE investigacao_id=%s", (inv_id,))
        snaps = cx.execute("SELECT DISTINCT ON (instancia_id, realm) * FROM realm_snapshot s WHERE "
                           + SNAPSHOTS_DA_INVESTIGACAO + " ORDER BY instancia_id, realm, lido_em DESC",
                           {"inv": inv_id}).fetchall()
        nomes = inv["parametros"].get("instancias")
        insts = {i["id"]: i for i in cx.execute("SELECT * FROM instancia").fetchall()
                 if not nomes or i["nome"] in nomes}
        snaps = [s for s in snaps if s["instancia_id"] in insts]
        contas = cx.execute("SELECT * FROM conta WHERE investigacao_id=%s AND incluida AND via<>'varredura'",
                            (inv_id,)).fetchall()
        tarefas = cx.execute("SELECT conta_id, status, releitura, inicio_ms, fim_ms FROM tarefa "
                             "WHERE investigacao_id=%s AND inicio_ms >= %s", (inv_id, inv["inicio_ms"])).fetchall()
        por_conta: dict[int, list] = {}
        for t in tarefas:
            por_conta.setdefault(t["conta_id"], []).append(t)
        linhas = []
        for s in snaps:
            cs = [c for c in contas if c["instancia_id"] == s["instancia_id"] and c["realm"] == s["realm"]]
            if not cs:
                if s["status"] in ("esperado_invisivel", "sem_permissao", "atributo_nao_pesquisavel"):
                    linhas.append((s, None, "sem_dados", s["status"], s["detalhe"], s["acao"], None))
                elif s["status"] == "federacao_sem_importacao":
                    linhas.append((s, None, "parcial", s["status"], s["detalhe"], s["acao"], None))
                else:
                    linhas.append((s, None, "coberto", "pesquisado_sem_conta",
                                   "Realm pesquisado; nenhuma conta com este identificador", None, None))
                continue
            for c in cs:
                motivos, classe, desde = [], "coberto", None
                if s["status"] in ("eventos_nao_gravados", "tipo_nao_gravado", "sem_permissao"):
                    motivos.append((s["status"], s["detalhe"], s["acao"])); classe = "sem_dados"
                elif s["status"] == "falhas_nao_gravadas":
                    motivos.append((s["status"], s["detalhe"], s["acao"])); classe = "parcial"
                exp = (s["config"] or {}).get("eventsExpiration")
                if exp and inv["inicio_ms"] < agora - exp * 1000:
                    desde = agora - exp * 1000
                    motivos.append(("retencao_insuficiente",
                                    f"Retenção de {exp // 86400} dias: cobre desde "
                                    f"{datetime.fromtimestamp(desde / 1000, ZoneInfo(inv['fuso'])):%d/%m/%Y}",
                                    "Aumentar a retenção (eventsExpiration)"))
                    classe = "parcial" if classe == "coberto" else classe
                ts = por_conta.get(c["id"], [])
                ruins = [t for t in ts if t["status"] in ("falhou", "sem_permissao", "pendente", "executando")]
                if ts and len(ruins) == len(ts):
                    motivos.append(("erro", "Coleta não concluída", "Retomar a investigação")); classe = "sem_dados"
                elif ruins:
                    motivos.append(("erro", f"{len(ruins)} dia(s) sem coleta concluída", "Retomar"))
                    classe = "parcial" if classe == "coberto" else classe
                for st, rotulo in (("limite", "limite atingido"),):
                    n = sum(1 for t in ts if t["status"] == st)
                    if n:
                        motivos.append((st, f"{n} dia(s) com {rotulo} (incompleto)", "Acionar a equipe IAM"))
                        classe = "parcial" if classe == "coberto" else classe
                for rel, rotulo in (("divergente", "divergente na releitura"), ("expirado", "expirado durante a coleta"),
                                    ("divergente_conteudo", "conteúdo divergente entre duas leituras"),
                                    ("possivel_alteracao", "possível alteração na origem (divergente)")):
                    dias = [t for t in ts if t["releitura"] == rel]
                    if dias:
                        ds = ", ".join(sorted({datetime.fromtimestamp(t["inicio_ms"] / 1000, ZoneInfo(inv["fuso"]))
                                               .strftime("%d/%m") for t in dias}))
                        acao = {"divergente": "Recoletar", "divergente_conteudo": "Apurar a alteração na origem",
                                "possivel_alteracao": "Apurar a alteração na origem"}.get(rel)
                        motivos.append((rel, f"{rotulo}: {ds}", acao))
                        classe = "parcial" if classe == "coberto" else classe
                if not motivos:
                    motivos.append(("ok", "Coberto", None))
                linhas.append((s, c, classe, "; ".join(m[0] for m in motivos), "; ".join(m[1] for m in motivos if m[1]),
                               "; ".join(m[2] for m in motivos if m[2]) or None, desde))
        for s, c, classe, st, det, acao, desde in linhas:
            cx.execute("INSERT INTO cobertura (investigacao_id, instancia_id, realm, conta_id, classe, status, "
                       "detalhe, acao, desde_ms) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)",
                       (inv_id, s["instancia_id"], s["realm"], c["id"] if c else None, classe, st, det, acao, desde))
        pend = cx.execute("SELECT count(*) n FROM tarefa WHERE investigacao_id=%s AND status IN "
                          "('pendente','executando')", (inv_id,)).fetchone()["n"]
        lacunas = any(cl != "coberto" for _, _, cl, *_ in linhas)
        status = "parcial" if pend else ("concluida_com_lacunas" if lacunas else "concluida")
        cx.execute("UPDATE investigacao SET status=%s, concluido_em=CASE WHEN %s THEN NULL ELSE now() END "
                   "WHERE id=%s", (status, bool(pend), inv_id))
        trilha(cx, inv["operador"], "fechar_investigacao", inv_id, status=status)
        return {"status": status, "pares": len(linhas)}

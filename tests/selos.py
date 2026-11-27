"""Critérios de aceite dos selos e da releitura por conteúdo (docs/PROPOSTA_WEB.md §6.1, etapa W0b), contra a stack
real no modo local.

  AUDITOR_DSN=<kc_auditor_app> AUDITOR_DSN_DONO=<dono> KC_DSN_kc26=... KC_DSN_kc18=... \\
    python tests/selos.py [investigação já concluída ...]

1. Selos conferem em 100% das fatias (folha recalculada do evento decifrado e do sal; raiz recalculada das folhas),
   nas investigações indicadas e numa nova.
2. Alteração na origem entre duas leituras é detectada: no Keycloak 26 (mesmo id, conteúdo diferente) a fatia fica
   'divergente_conteudo'; no Keycloak 18 (id pelo conteúdo) fica 'possivel_alteracao'. As duas versões ficam
   guardadas, o evento oficial e o selo não mudam, e o fato vai para a trilha.
3. Alteração no banco do auditor (folha trocada, cifrados trocados entre linhas) bloqueia a exportação e alerta.
4. O pacote traz fatias.json e a raiz Merkle no manifesto; a raiz recalculada do pacote confere.
"""
from __future__ import annotations

import json
import os
import sys
import zipfile
from datetime import date, timedelta
from pathlib import Path

import psycopg

RAIZ = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(RAIZ))
from auditor import coleta, custodia, investigar, merkle, sigilo  # noqa: E402
from auditor.db import conectar  # noqa: E402
from auditor.kc import ClienteKC  # noqa: E402

falhas: list[str] = []


def checar(ok: bool, nome: str, detalhe: str = ""):
    print(f"{'OK   ' if ok else 'FALHA'} {nome}{(' — ' + detalhe) if detalhe else ''}", flush=True)
    if not ok:
        falhas.append(nome)


def conferir_inv(inv: int, rotulo: str):
    with conectar() as cx:
        r = custodia.conferir(cx, sigilo.Cofre(inv, "exportar"), inv)
        sem = cx.execute("SELECT count(*) n FROM tarefa t WHERE investigacao_id=%s AND status IN ('concluida','limite') "
                         "AND NOT EXISTS (SELECT 1 FROM selo s WHERE s.tarefa_id=t.id)", (inv,)).fetchone()["n"]
    checar(not r["problemas"] and r["eventos_sem_selo"] == 0 and sem == 0,
           f"1 selos conferem em 100% das fatias ({rotulo} {inv})",
           f"{len(r['fatias'])} fatias, {r['eventos_selados']} eventos, problemas={r['problemas'][:1]}")


def reler_tarefa(inv_id: int, tarefa_id: int) -> str:
    with conectar() as cx:
        inv = cx.execute("SELECT * FROM investigacao WHERE id=%s", (inv_id,)).fetchone()
        t = cx.execute("SELECT * FROM tarefa WHERE id=%s", (tarefa_id,)).fetchone()
        conta = cx.execute("SELECT * FROM conta WHERE id=%s", (t["conta_id"],)).fetchone()
        inst = cx.execute("SELECT * FROM instancia WHERE id=%s", (conta["instancia_id"],)).fetchone()
        cli = ClienteKC(inst, inv_id)
        try:
            return coleta.Coletor(cx, cli, inv, conta, t, inst, None).reler(None)
        finally:
            cli.fechar()


def adulterar_na_origem(inv: int, inst_nome: str, esperado: str):
    """Troca o IP de um evento do alvo direto na EVENT_ENTITY, relê a fatia e desfaz a troca."""
    kc_dsn = os.environ["KC_DSN_" + {"kc26": "kc26", "rhsso": "kc18"}[inst_nome]]
    with conectar() as cx:
        cf = sigilo.Cofre(inv, "exportar")
        e = cx.execute("SELECT e.*, t.id AS tarefa FROM evento e JOIN conta c ON c.id=e.conta_id "
                       "JOIN instancia i ON i.id=e.instancia_id JOIN tarefa t ON t.conta_id=e.conta_id AND "
                       "e.time_ms >= t.inicio_ms AND e.time_ms < t.fim_ms AND t.status='concluida' "
                       "WHERE e.investigacao_id=%s AND i.nome=%s AND c.via='atributo' AND e.type='LOGIN' "
                       "ORDER BY e.time_ms DESC LIMIT 1", (inv, inst_nome)).fetchone()
        d = sigilo.abrir_evento(cf, e)
        selo_antes = cx.execute("SELECT raiz FROM selo WHERE tarefa_id=%s ORDER BY versao DESC LIMIT 1",
                                (e["tarefa"],)).fetchone()["raiz"]
    b = d["bruto"]
    with psycopg.connect(kc_dsn, autocommit=True) as kc:
        if inst_nome == "kc26":
            alvo = kc.execute("SELECT id, ip_address FROM event_entity WHERE id=%s", (b["id"],)).fetchone()
        else:   # Keycloak 18: sem id na API; acha a linha pelo conteúdo
            alvo = kc.execute("SELECT id, ip_address FROM event_entity WHERE event_time=%s AND type=%s AND "
                              "user_id=%s AND session_id IS NOT DISTINCT FROM %s AND ip_address=%s LIMIT 1",
                              (b["time"], b["type"], b["userId"], b.get("sessionId"), b["ipAddress"])).fetchone()
        kc.execute("UPDATE event_entity SET ip_address='203.0.113.77' WHERE id=%s", (alvo[0],))
        try:
            rel = reler_tarefa(inv, e["tarefa"])
        finally:
            kc.execute("UPDATE event_entity SET ip_address=%s WHERE id=%s", (alvo[1], alvo[0]))
    with conectar() as cx:
        div = cx.execute("SELECT * FROM evento_divergente WHERE investigacao_id=%s AND tarefa_id=%s ORDER BY id DESC "
                         "LIMIT 1", (inv, e["tarefa"])).fetchone()
        dv = cf.decifrar("evento_divergente", "cifrado", div["id"], div["cifrado"]) if div else {}
        oficial = sigilo.abrir_evento(cf, cx.execute(
            "SELECT * FROM evento WHERE investigacao_id=%s AND instancia_id=%s AND realm=%s AND id=%s",
            (inv, e["instancia_id"], e["realm"], e["id"])).fetchone())
        tr = cx.execute("SELECT count(*) n FROM trilha_auditoria WHERE investigacao_id=%s AND acao='evento_divergente' "
                        "AND (detalhe->>'tarefa')::bigint=%s", (inv, e["tarefa"])).fetchone()["n"]
        r = custodia.conferir(cx, cf, inv)
        selo_depois = cx.execute("SELECT raiz FROM selo WHERE tarefa_id=%s ORDER BY versao DESC LIMIT 1",
                                 (e["tarefa"],)).fetchone()["raiz"]
    checar(rel == esperado, f"2 {inst_nome}: alteração na origem detectada na releitura", f"releitura={rel}")
    checar(bool(div) and dv.get("bruto", {}).get("ipAddress") == "203.0.113.77" and div["tipo"] ==
           ("conteudo" if esperado == "divergente_conteudo" else "possivel_alteracao"),
           f"2 {inst_nome}: versão relida guardada à parte (cifrada)", f"tipo={div and div['tipo']}")
    checar(oficial["ip"] == b["ipAddress"] and selo_antes == selo_depois and not r["problemas"],
           f"2 {inst_nome}: evento oficial e selo intactos; custódia confere")
    checar(tr >= 1, f"2 {inst_nome}: divergência registrada na trilha")


def main(anteriores: list[int]):
    for i in anteriores:
        conferir_inv(i, "investigação migrada")
    alvo = json.loads((RAIZ / "dados/pessoas.json").read_text())["casos"]["ALVO"]["cpf"]
    ate = date.today() - timedelta(days=1)
    inv = investigar.abrir("teste-selos", "Teste dos selos W0b", "cpf", alvo, (ate - timedelta(days=3)).isoformat(),
                           ate.isoformat())
    investigar.preparar(inv)
    coleta.executar(inv)
    from auditor import servicos
    servicos.fechar(inv)
    print(f"investigação nova {inv}", flush=True)
    conferir_inv(inv, "investigação nova")

    adulterar_na_origem(inv, "kc26", "divergente_conteudo")
    adulterar_na_origem(inv, "rhsso", "possivel_alteracao")

    # ---- 3. adulteração no banco do auditor (como DBA): folha trocada e cifrados trocados entre linhas
    from auditor.exportar import exportar
    saida = RAIZ / "saida" / "teste_selos"
    dono = psycopg.connect(os.environ["AUDITOR_DSN_DONO"], autocommit=True)
    a, b = dono.execute("SELECT instancia_id, realm, id, folha, cifrado FROM evento WHERE investigacao_id=%s "
                        "ORDER BY time_ms LIMIT 2", (inv,)).fetchall()
    for nome, sql, volta in (
            ("folha trocada", "UPDATE evento SET folha=%s WHERE investigacao_id=%s AND id=%s",
             [((b[3], inv, a[2]), (a[3], inv, a[2]))]),
            ("cifrados trocados entre linhas", "UPDATE evento SET cifrado=%s WHERE investigacao_id=%s AND id=%s",
             [((b[4], inv, a[2]), (a[4], inv, a[2])), ((a[4], inv, b[2]), (b[4], inv, b[2]))])):
        for ida, _ in volta:
            dono.execute(sql, ida)
        try:
            exportar(inv, saida, "teste-selos")
            checar(False, f"3 exportação bloqueada com {nome}")
        except Exception as e:  # noqa: BLE001
            checar(isinstance(e, custodia.CustodiaViolada),
                   f"3 exportação bloqueada com {nome}", f"{type(e).__name__}: {str(e)[:90]}")
        finally:
            for _, vem in volta:
                dono.execute(sql, vem)
    n = dono.execute("SELECT count(*) n FROM trilha_auditoria WHERE investigacao_id=%s AND "
                     "acao='exportacao_bloqueada'", (inv,)).fetchone()[0]
    checar(n >= 2, "3 os dois bloqueios registrados na trilha (e alerta no SIEM)")

    # ---- 4. pacote: fatias.json e raiz no manifesto
    r = exportar(inv, saida, "teste-selos")
    with zipfile.ZipFile(r["pacote"]) as z:
        m = json.loads(z.read("manifesto.json"))
        fatias = json.loads(z.read("fatias.json"))
    checar(merkle.raiz([f["raiz"] for f in fatias]) == m["custodia"]["raiz_merkle"] and
           sum(f["eventos"] for f in fatias) == m["custodia"]["eventos_selados"] == m["eventos"]["total"],
           "4 raiz recalculada de fatias.json confere com o manifesto",
           f"{len(fatias)} fatias, raiz {m['custodia']['raiz_merkle'][:16]}…, divergentes "
           f"{m['custodia']['versoes_divergentes']}")
    checar(all(f["conta"].startswith(("Conta ", "Tentativas")) for f in fatias),
           "4 fatias.json do pacote mascarado só com pseudônimos")
    print(f"\n{'APROVADO' if not falhas else 'REPROVADO'}: {len(falhas)} falha(s)")
    sys.exit(1 if falhas else 0)


if __name__ == "__main__":
    main([int(x) for x in sys.argv[1:]])

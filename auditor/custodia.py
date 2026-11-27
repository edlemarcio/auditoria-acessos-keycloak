"""Conferência da cadeia de custódia antes de exportar (W0b, PROPOSTA_WEB §6.1 itens 5 e 6).

Recalcula a folha de cada evento a partir do evento decifrado e do seu sal, e a raiz de cada fatia a partir das
folhas, e compara com os selos gravados na coleta. Qualquer diferença bloqueia a exportação. A raiz da investigação
é a raiz Merkle das raízes de fatia (último selo de cada tarefa), na ordem (conta, início da fatia).
"""
from __future__ import annotations

from cryptography.exceptions import InvalidTag

from . import merkle, siem, sigilo
from .db import trilha


class CustodiaViolada(RuntimeError):
    pass


def conferir(cx, cf: sigilo.Cofre, inv_id: int) -> dict:
    selos = cx.execute("SELECT DISTINCT ON (s.tarefa_id) s.*, c.incluida, c.instancia_id, c.realm FROM selo s "
                       "JOIN conta c ON c.id=s.conta_id WHERE s.investigacao_id=%s "
                       "ORDER BY s.tarefa_id, s.versao DESC", (inv_id,)).fetchall()
    selos.sort(key=lambda s: (s["conta_id"], s["inicio_ms"], s["tarefa_id"]))
    problemas, fatias, selados = [], [], 0
    for s in selos:
        folhas = []
        for e in cx.execute("SELECT id, instancia_id, realm, cifrado, folha FROM evento WHERE investigacao_id=%s "
                            "AND conta_id=%s AND time_ms>=%s AND time_ms<%s",
                            (inv_id, s["conta_id"], s["inicio_ms"], s["fim_ms"])):
            try:
                d = sigilo.abrir_evento(cf, e)
            except InvalidTag:
                problemas.append(f"fatia {s['tarefa_id']}: evento {e['id'][:12]}… não decifra com a AAD da própria "
                                 "linha (célula trocada ou alterada)")
                folhas.append(e["folha"])
                continue
            if not d.get("sal") or merkle.folha(bytes.fromhex(d["sal"]), merkle.canonico(d["bruto"])) != e["folha"]:
                problemas.append(f"fatia {s['tarefa_id']}: evento {e['id'][:12]}… não confere com a folha")
            folhas.append(e["folha"])
        raiz = merkle.raiz(sorted(f for f in folhas if f))
        if raiz != s["raiz"] or len(folhas) != s["n_eventos"]:
            problemas.append(f"fatia {s['tarefa_id']}: raiz ou contagem diferente do selo "
                             f"({len(folhas)} eventos, selo com {s['n_eventos']})")
        selados += len(folhas)
        fatias.append({"fatia": s["tarefa_id"], "conta_id": s["conta_id"], "instancia_id": s["instancia_id"],
                       "realm": s["realm"], "inicio_ms": s["inicio_ms"], "fim_ms": s["fim_ms"],
                       "eventos": s["n_eventos"], "raiz": s["raiz"], "versao": s["versao"], "origem": s["origem"],
                       "incluida": s["incluida"]})
    total = cx.execute("SELECT count(*) n FROM evento WHERE investigacao_id=%s", (inv_id,)).fetchone()["n"]
    div = {r["tipo"]: r["n"] for r in cx.execute(
        "SELECT tipo, count(*) n FROM evento_divergente WHERE investigacao_id=%s GROUP BY 1", (inv_id,))}
    return {"fatias": fatias, "raiz": merkle.raiz([f["raiz"] for f in fatias]), "problemas": problemas,
            "eventos_selados": selados, "eventos_sem_selo": max(0, total - selados), "divergencias": div}


def exigir(cx, cf: sigilo.Cofre, inv_id: int, operador: str) -> dict:
    r = conferir(cx, cf, inv_id)
    if r["problemas"]:
        trilha(cx, operador, "exportacao_bloqueada", inv_id, problemas=len(r["problemas"]))
        siem.enviar("exportacao_bloqueada_custodia", "alerta", investigacao=inv_id, quantidade=len(r["problemas"]))
        raise CustodiaViolada(f"investigação {inv_id}: {len(r['problemas'])} divergência(s) entre os dados e os "
                              f"selos; exportação bloqueada. Primeira: {r['problemas'][0]}")
    return r

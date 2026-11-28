"""Critério probatório da migração (W4, PROPOSTA_WEB §5.6 item 3): os manifestos já entregues continuam reproduzíveis.

Para cada pacote encontrado nas pastas indicadas, o manifesto é localizado na trilha pelo `sha256_manifesto` registrado
na exportação (só pacotes de fato entregues entram). Os hashes de `eventos.jsonl` e `requisicoes.jsonl` são então
recalculados a partir das tabelas cifradas de hoje, com o algoritmo da versão que gerou o manifesto:

* **v1** (coletor 0.1.x, a CLI de antes da W-0): todos os eventos, inclusive de contas excluídas, `_instancia` pelo
  nome da instância, requisições completas (`params` na ordem de chaves do jsonb, `inicio.isoformat()`);
* **atual** (0.2.0 em diante): só os eventos de contas incluídas (correção D2); requisições completas, como o hash do
  arquivo original que o manifesto guarda.

Qualquer diferença é reportada com os totais do manifesto e do recálculo. Diferença num pacote atual pode ter causa
legítima posterior à entrega (conta incluída ou excluída depois, coleta complementar); num v1, não: lá a migração
não pode mudar nada.
"""
from __future__ import annotations

import json
import zipfile
from pathlib import Path

from . import sigilo
from .manifesto import linhas_eventos, sha256
from .migrar_cifra import _eventos, _hashes, _reqs


def _versao_v1(v: str | None) -> bool:
    return bool(v) and v.split(".")[:2] == ["0", "1"]


def _recalcular(cx, inv_id: int, v1: bool, cf) -> dict:
    evs = _eventos(cx, inv_id, cf)
    reqs = _reqs(cx, inv_id, cf)
    if not v1:
        incl = {r["id"] for r in cx.execute("SELECT id FROM conta WHERE investigacao_id=%s AND incluida", (inv_id,))}
        evs = [e for e in evs if e["conta_id"] in incl]
    he, hr = _hashes(evs, reqs)
    return {"eventos": {"sha256": he, "total": len(evs)}, "requisicoes": {"sha256": hr, "total": len(reqs)}}


def conferir(cx, pastas: list[Path]) -> list[dict]:
    entregues = {}
    for r in cx.execute("SELECT investigacao_id, acao, quando, operador, detalhe->>'sha256_manifesto' AS sha FROM "
                        "trilha_auditoria WHERE acao IN ('exportar','exportar_sem_mascara') AND "
                        "detalhe ? 'sha256_manifesto'"):
        entregues.setdefault(r["sha"], r)
    out, cache, cofres = [], {}, {}
    for zp in sorted({p for d in pastas for p in Path(d).rglob("*.zip")}):
        try:
            with zipfile.ZipFile(zp) as z:
                corpo = z.read("manifesto.json")
        except (KeyError, zipfile.BadZipFile):
            continue
        m = json.loads(corpo)
        t = entregues.get(sha256(corpo))
        linha = {"pacote": str(zp), "versao": m.get("versao_coletor"), "investigacao": (m.get("investigacao") or {}).get("id"),
                 "entregue": bool(t)}
        if not t:
            out.append({**linha, "resultado": "sem_registro"})   # nenhuma exportação com este manifesto na trilha deste banco
            continue
        inv_id = t["investigacao_id"]
        v1 = _versao_v1(m.get("versao_coletor"))
        if inv_id not in cofres:
            cofres[inv_id] = sigilo.Cofre(inv_id, "exportar")
        k = (inv_id, v1)
        if k not in cache:
            cache[k] = _recalcular(cx, inv_id, v1, cofres[inv_id])
        rc = cache[k]
        me, mr = m.get("eventos") or {}, m.get("requisicoes") or {}
        ok_e, ok_r = me.get("sha256") == rc["eventos"]["sha256"], mr.get("sha256") == rc["requisicoes"]["sha256"]
        out.append({**linha, "investigacao": inv_id, "algoritmo": "v1" if v1 else "atual", "exportado_em":
                    t["quando"].isoformat(), "eventos_ok": ok_e, "requisicoes_ok": ok_r,
                    "eventos": [me.get("total"), rc["eventos"]["total"]],
                    "requisicoes": [mr.get("total"), rc["requisicoes"]["total"]],
                    "resultado": "confere" if ok_e and ok_r else "diverge"})
    return out


def resumo(linhas: list[dict]) -> dict:
    e = [x for x in linhas if x["entregue"]]
    return {"pacotes": len(linhas), "entregues": len(e),
            "v1": {"conferem": sum(x["resultado"] == "confere" for x in e if x["algoritmo"] == "v1"),
                   "divergem": sum(x["resultado"] == "diverge" for x in e if x["algoritmo"] == "v1")},
            "atual": {"conferem": sum(x["resultado"] == "confere" for x in e if x["algoritmo"] == "atual"),
                      "divergem": sum(x["resultado"] == "diverge" for x in e if x["algoritmo"] == "atual")}}

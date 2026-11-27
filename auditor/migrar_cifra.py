"""Migração das investigações anteriores à W0b para a cifra na gravação (PROPOSTA_WEB §5.6). Modo local.

Para cada investigação, numa transação: cifra eventos, contas, requisições, extras, justificativa e erros com a DEK,
calcula os pseudônimos e apaga o claro. **Critério probatório:** os `eventos.sha256` e `requisicoes.sha256` (algoritmo
v1: todos os eventos, inclusive de contas excluídas, `_instancia` pelo nome) recalculados a partir do cifrado são iguais
aos calculados do claro antes da migração; qualquer diferença desfaz a investigação inteira. Assim todo manifesto já
entregue continua reproduzível. O histórico de contas do alvo passa para K_historico. No fim, VACUUM FULL nas tabelas
(as cópias em claro que restarem em WAL e backups somem com a expiração dos backups, §5.6 item 4).
"""
from __future__ import annotations

import json
import os

from psycopg.types.json import Jsonb

from . import chaves, redigir, sigilo
from .manifesto import linhas_eventos, sha256

TABELAS = ("evento", "conta", "requisicao", "conta_extra", "investigacao", "tarefa", "historico_identidade",
           "job", "selo", "trilha_auditoria")


def _hashes(eventos: list[dict], reqs: list[dict]) -> tuple[str, str]:
    ev = linhas_eventos([{**e["bruto"], "_instancia": e["inst"], "_realm": e["realm"]} for e in eventos])
    rq = b"".join(json.dumps({**{k: r[k] for k in ("id", "caminho", "params", "status", "inicio", "ms", "sha256",
                                                   "bytes", "coletor")}, "inicio": r["inicio"].isoformat()},
                             ensure_ascii=False, default=str).encode() + b"\n" for r in reqs)
    return sha256(ev), sha256(rq)


def _eventos(cx, inv_id, cf=None):
    rs = cx.execute("SELECT e.*, i.nome AS inst FROM evento e JOIN instancia i ON i.id=e.instancia_id "
                    "WHERE e.investigacao_id=%s", (inv_id,)).fetchall()
    return [sigilo.abrir_evento(cf, r) for r in rs] if cf else rs


def _reqs(cx, inv_id, cf=None):
    out = []
    for r in cx.execute("SELECT * FROM requisicao WHERE investigacao_id=%s ORDER BY id", (inv_id,)).fetchall():
        if cf and r["cifrado"] is not None:
            r.update(cf.decifrar("requisicao", "cifrado", r["id"], r["cifrado"]))
        out.append(r)
    return out


def migrar_investigacao(cx, inv: dict) -> dict:
    inv_id = inv["id"]
    with cx.transaction():
        if not cx.execute("SELECT EXISTS (SELECT 1 FROM evento WHERE investigacao_id=%s AND cifrado IS NULL) OR "
                          "EXISTS (SELECT 1 FROM conta WHERE investigacao_id=%s AND cifrado IS NULL) OR "
                          "EXISTS (SELECT 1 FROM job WHERE investigacao_id=%s AND parametros ? 'contas') AS x",
                          (inv_id, inv_id, inv_id)).fetchone()["x"] and inv["justificativa_cifrada"] is not None:
            return {"investigacao": inv_id, "migrada": False}
        cf = sigilo.Cofre(inv_id, "migrar")
        antes = _hashes(_eventos(cx, inv_id, cf), _reqs(cx, inv_id, cf))   # linhas em claro ficam como estão
        # eventos
        for e in cx.execute("SELECT * FROM evento WHERE investigacao_id=%s AND cifrado IS NULL", (inv_id,)).fetchall():
            idg = sigilo.id_gravado(cf, e["id"])
            b = e["bruto"]
            cx.execute("UPDATE evento SET id=%s, cifrado=%s, ps_conta=%s, ps_ip=%s, ps_sessao=%s, user_id=NULL, "
                       "session_id=NULL, ip=NULL, details=NULL, bruto=NULL WHERE investigacao_id=%s AND "
                       "instancia_id=%s AND realm=%s AND id=%s",
                       (idg, sigilo.cifrar_evento(cf, e["instancia_id"], e["realm"], idg, b),
                        cf.ps("conta", b.get("userId")), cf.ps("ip", b.get("ipAddress")),
                        cf.ps("sessao", b.get("sessionId")), inv_id, e["instancia_id"], e["realm"], e["id"]))
        for c in cx.execute("SELECT * FROM conta WHERE investigacao_id=%s AND cifrado IS NULL", (inv_id,)).fetchall():
            cx.execute("UPDATE conta SET cifrado=%s, ps_conta=%s, user_id=NULL, username=NULL, email=NULL WHERE id=%s",
                       (cf.cifrar("conta", "cifrado", c["id"], {"user_id": c["user_id"], "username": c["username"],
                                                               "email": c["email"]}),
                        cf.ps("conta", c["user_id"]), c["id"]))
        for r in cx.execute("SELECT * FROM requisicao WHERE investigacao_id=%s AND cifrado IS NULL",
                            (inv_id,)).fetchall():
            p = redigir.params(r["params"])
            cx.execute("UPDATE requisicao SET cifrado=%s, caminho=%s, params=%s WHERE id=%s",
                       (cf.cifrar("requisicao", "cifrado", r["id"], {"caminho": r["caminho"], "params": r["params"]}),
                        redigir.caminho(r["caminho"]), Jsonb(p) if p else None, r["id"]))
        for x in cx.execute("SELECT * FROM conta_extra WHERE investigacao_id=%s AND cifrado IS NULL",
                            (inv_id,)).fetchall():
            cx.execute("UPDATE conta_extra SET cifrado=%s, dados=NULL WHERE id=%s",
                       (cf.cifrar("conta_extra", "dados", x["id"], x["dados"]), x["id"]))
        for t in cx.execute("SELECT id, erro FROM tarefa WHERE investigacao_id=%s AND erro IS NOT NULL AND "
                            "erro_cifrado IS NULL", (inv_id,)).fetchall():
            cx.execute("UPDATE tarefa SET erro=%s, erro_cifrado=%s WHERE id=%s",
                       (redigir.erro(t["erro"]), cf.cifrar("tarefa", "erro", t["id"], t["erro"]), t["id"]))
        for j in cx.execute("SELECT id, parametros FROM job WHERE investigacao_id=%s AND parametros ? 'contas'",
                            (inv_id,)).fetchall():
            import base64
            par = {k: v for k, v in j["parametros"].items() if k != "contas"}
            if j["parametros"]["contas"]:
                par["contas_cifradas"] = base64.b64encode(cf.cifrar("job", "contas", inv_id,
                                                                    j["parametros"]["contas"])).decode()
            cx.execute("UPDATE job SET parametros=%s WHERE id=%s", (Jsonb(par), j["id"]))
        if inv["justificativa_cifrada"] is None:
            cx.execute("UPDATE investigacao SET justificativa='', justificativa_cifrada=%s WHERE id=%s",
                       (cf.cifrar("investigacao", "justificativa", inv_id, inv["justificativa"]), inv_id))
        depois = _hashes(_eventos(cx, inv_id, cf), _reqs(cx, inv_id, cf))
        if antes != depois:
            raise RuntimeError(f"investigação {inv_id}: hashes divergem depois da cifra ({antes} ≠ {depois}); "
                               "migração desfeita")
        from .pseudonimos import atribuir
        atribuir(cx, cf)
    return {"investigacao": inv_id, "migrada": True, "eventos_sha256": antes[0], "requisicoes_sha256": antes[1]}


def migrar_selos(cx, inv: dict) -> int:
    """Folha (com sal novo) e HMAC de conteúdo nos eventos antigos; selos retroativos das fatias concluídas,
    marcados origem='migracao' (selados na migração, não na coleta; o relatório declara). Hashes v1 conferidos."""
    from . import merkle
    from .coleta import selar
    inv_id = inv["id"]
    if not cx.execute("SELECT EXISTS (SELECT 1 FROM evento WHERE investigacao_id=%s AND folha IS NULL) OR EXISTS "
                      "(SELECT 1 FROM tarefa t WHERE t.investigacao_id=%s AND t.status IN ('concluida','limite') AND "
                      "NOT EXISTS (SELECT 1 FROM selo s WHERE s.tarefa_id=t.id)) AS x", (inv_id, inv_id)).fetchone()["x"]:
        return 0
    with cx.transaction():
        cf = sigilo.Cofre(inv_id, "migrar")
        antes = _hashes(_eventos(cx, inv_id, cf), _reqs(cx, inv_id, cf))
        for e in cx.execute("SELECT * FROM evento WHERE investigacao_id=%s AND folha IS NULL", (inv_id,)).fetchall():
            d = sigilo.abrir_evento(cf, e)
            sal, canon = os.urandom(32), merkle.canonico(d["bruto"])
            cx.execute("UPDATE evento SET cifrado=%s, folha=%s, hash_conteudo=%s WHERE investigacao_id=%s AND "
                       "instancia_id=%s AND realm=%s AND id=%s",
                       (sigilo.cifrar_evento(cf, e["instancia_id"], e["realm"], e["id"], d["bruto"], sal=sal.hex()),
                        merkle.folha(sal, canon), cf.ps("conteudo", canon.decode()), inv_id, e["instancia_id"],
                        e["realm"], e["id"]))
        n = 0
        for t in cx.execute("SELECT * FROM tarefa t WHERE investigacao_id=%s AND status IN ('concluida','limite') "
                            "AND NOT EXISTS (SELECT 1 FROM selo s WHERE s.tarefa_id=t.id) ORDER BY id",
                            (inv_id,)).fetchall():
            selar(cx, inv_id, t, origem="migracao")
            n += 1
        if _hashes(_eventos(cx, inv_id, cf), _reqs(cx, inv_id, cf)) != antes:
            raise RuntimeError(f"investigação {inv_id}: hashes divergem depois das folhas; migração desfeita")
    return n


def migrar_trilha(cx) -> int:
    """Encadeia os registros anteriores à W0b (por investigação, na ordem em que foram gravados), tira os campos
    livres do detalhe (cifrados para a chave pública da investigação; no hash, só o compromisso com sal) e cria o par
    de chaves da trilha das investigações antigas. Exige o papel dono: o trigger da trilha é desligado só durante a
    conversão, dentro da transação."""
    from psycopg.types.json import Jsonb as J

    from . import cripto
    from .db import CAMPOS_LIVRES, aad_livres, compromisso_livre, genese, hash_registro
    with cx.transaction():
        for inv in cx.execute("SELECT id FROM investigacao WHERE trilha_publica IS NULL AND status <> 'abrindo'").fetchall():
            cf = sigilo.Cofre(inv["id"], "migrar")
            pub, priv = cripto.par_trilha()
            cx.execute("UPDATE investigacao SET trilha_publica=%s, trilha_privada_cifrada=%s WHERE id=%s",
                       (pub, cripto.cifrar_dek(cf.dek, priv, cripto.aad(inv["id"], "investigacao", "trilha_privada",
                                                                        inv["id"])), inv["id"]))
        cadeias = [r["c"] for r in cx.execute("SELECT DISTINCT coalesce(investigacao_id, 0) AS c FROM trilha_auditoria "
                                              "WHERE hash IS NULL")]
        if not cadeias:
            return 0
        pubs = {r["id"]: r["trilha_publica"] for r in cx.execute("SELECT id, trilha_publica FROM investigacao")}
        cx.execute("ALTER TABLE trilha_auditoria DISABLE TRIGGER trg_trilha_ro")
        n = 0
        for cad in cadeias:
            ant = genese(cad)
            for seq, r in enumerate(cx.execute("SELECT * FROM trilha_auditoria WHERE coalesce(investigacao_id, 0)=%s "
                                               "ORDER BY id", (cad,)).fetchall(), 1):
                det = dict(r["detalhe"] or {})
                livres = {k: det.pop(k) for k in CAMPOS_LIVRES if det.get(k) is not None}
                comp = cif = None
                if livres:
                    sais = {k: os.urandom(32) for k in livres}
                    comp = {k: compromisso_livre(sais[k], v) for k, v in livres.items()}
                    if pubs.get(cad):
                        cif = cripto.selar_para(bytes(pubs[cad]), json.dumps(
                            {k: {"valor": v, "sal": sais[k].hex()} for k, v in livres.items()},
                            ensure_ascii=False).encode(), aad_livres(cad, seq))
                novo = {**r, "cadeia": cad, "seq": seq, "detalhe": det, "livres_compromisso": comp,
                        "hash_anterior": ant}
                h = hash_registro(novo)
                cx.execute("UPDATE trilha_auditoria SET cadeia=%s, seq=%s, detalhe=%s, livres_compromisso=%s, "
                           "livres_cifrado=%s, hash_anterior=%s, hash=%s WHERE id=%s",
                           (cad, seq, J(det), J(comp) if comp else None, cif, ant, h, r["id"]))
                ant, n = h, n + 1
        cx.execute("ALTER TABLE trilha_auditoria ENABLE TRIGGER trg_trilha_ro")
    return n


def migrar_historico(cx) -> int:
    n = 0
    with cx.transaction():
        for h in cx.execute("SELECT h.*, (SELECT max(i.id) FROM investigacao i WHERE i.alvo_hmac=h.alvo_hmac) AS inv "
                            "FROM historico_identidade h WHERE h.cifrado IS NULL").fetchall():
            ctx = (h["inv"], h["alvo_hmac"], h["instancia_id"], h["realm"])
            cx.execute("UPDATE historico_identidade SET uid_hmac=%s, cifrado=%s, user_id=NULL, username=NULL "
                       "WHERE alvo_hmac=%s AND instancia_id=%s AND realm=%s AND user_id=%s",
                       (chaves.hmac_historico(*ctx, h["user_id"]),
                        chaves.cifrar_historico(*ctx, {"user_id": h["user_id"], "username": h["username"]}),
                        h["alvo_hmac"], h["instancia_id"], h["realm"], h["user_id"]))
            n += 1
    return n


def migrar(cx) -> dict:
    if chaves.modo() != "local":
        return {}
    feitas = [r for inv in cx.execute("SELECT * FROM investigacao WHERE status <> 'abrindo' ORDER BY id").fetchall()
              if (r := migrar_investigacao(cx, inv))["migrada"]]
    # requisições sem investigação (sondas, cadastro): só a versão redigida, sem original
    with cx.transaction():
        for r in cx.execute("SELECT id, caminho, params FROM requisicao WHERE investigacao_id IS NULL").fetchall():
            c, p = redigir.caminho(r["caminho"]), redigir.params(r["params"])
            if (c, p) != (r["caminho"], r["params"]):
                cx.execute("UPDATE requisicao SET caminho=%s, params=%s WHERE id=%s", (c, Jsonb(p) if p else None,
                                                                                     r["id"]))
    selos = sum(migrar_selos(cx, inv) for inv in cx.execute(
        "SELECT * FROM investigacao WHERE status <> 'abrindo' ORDER BY id").fetchall())
    hist = migrar_historico(cx)
    trilha_n = migrar_trilha(cx)
    if feitas or hist or selos or trilha_n:
        for t in TABELAS:
            cx.execute(f"VACUUM FULL {t}")
    return {"investigacoes": len(feitas), "historico": hist, "selos_retroativos": selos, "trilha_encadeada": trilha_n}

"""Banco do auditor (PostgreSQL)."""
from __future__ import annotations

import contextvars
import os

import psycopg
from psycopg.rows import dict_row

DSN = os.environ.get("AUDITOR_DSN", "postgresql://postgres@127.0.0.1/auditor")




# Snapshots de realm de uma investigação (parâmetro nomeado %(inv)s). Investigações anteriores à 0.2.0 não têm
# investigacao_id nos snapshots: para elas vale a janela entre a criação e a conclusão da investigação.
SNAPSHOTS_DA_INVESTIGACAO = """
  (s.investigacao_id = %(inv)s OR (s.investigacao_id IS NULL
   AND NOT EXISTS (SELECT 1 FROM realm_snapshot x WHERE x.investigacao_id = %(inv)s)
   AND s.lido_em >= (SELECT criado_em FROM investigacao WHERE id = %(inv)s)
   AND s.lido_em <= COALESCE((SELECT concluido_em FROM investigacao WHERE id = %(inv)s), now())))
"""


# identidade do usuário da requisição atual (API): vai para kc_auditor.sub em cada conexão, e a RLS da migração 0011
# (aplicada ao papel kc_api) só mostra eventos, contas e pseudônimos das investigações em que ele está designado.
sub_atual: contextvars.ContextVar[str | None] = contextvars.ContextVar("sub_atual", default=None)


import itertools as _it
_PERCURSOS = _it.count(1)


def conectar(autocommit: bool = True) -> psycopg.Connection:
    cx = psycopg.connect(DSN, autocommit=autocommit, row_factory=dict_row)
    sub = sub_atual.get()
    if sub:
        cx.execute("SELECT set_config('kc_auditor.sub', %s, false)", (sub,))
        if not autocommit:
            cx.commit()
    return cx


def percorrer(cx, sql: str, args=None, lote: int = 2000):
    """Linhas de uma consulta por cursor no servidor, em lotes: memória limitada para qualquer volume (pacote v2)."""
    with cx.transaction(), cx.cursor(name=f"percurso_{next(_PERCURSOS)}") as cur:
        cur.itersize = lote
        cur.execute(sql, args)
        yield from cur


def migrar_esquema(revisao: str = "head"):
    """Aplica as migrações do Alembic (auditor/migracoes) até a revisão pedida."""
    from pathlib import Path

    from alembic import command
    from alembic.config import Config
    cfg = Config()
    cfg.set_main_option("script_location", str(Path(__file__).parent / "migracoes"))
    command.upgrade(cfg, revisao)


def criar_esquema() -> dict | None:
    """Cria/atualiza o esquema (Alembic) e converte segredos e alvos antigos para o formato de chaves v2."""
    import os
    migrar_esquema()
    with conectar() as cx:
        if os.environ.get("AUDITOR_MODO", "local") != "local" or not os.environ.get("AUDITOR_CHAVE"):
            return None   # sem chave não há o que migrar (instalação nova ou só esquema)
        from .chaves import migrar_deks
        from .cripto import migrar_chaves
        feitos = migrar_chaves(cx)
        feitos["deks"] = migrar_deks(cx)
        from .migrar_cifra import migrar
        feitos["cifra"] = migrar(cx)
        return feitos


# ------------------------------------------------------------------ trilha encadeada (W0b, PROPOSTA_WEB §6.3)
CHAVE_TRILHA = 0x6B74                      # advisory lock por cadeia
CAMPOS_LIVRES = ("justificativa", "motivo", "alvo")


def genese(cadeia: int) -> str:
    import hashlib
    return hashlib.sha256(f"kc-auditor/trilha/v1|{cadeia}".encode()).hexdigest()


def registro_trilha(r: dict) -> dict:
    """O que o hash de um registro cobre: campos estruturados e o compromisso com sal dos campos livres (não o texto
    nem o cifrado). Assim trilha.jsonl, sem textos, recalcula a cadeia, que continua verificável depois do expurgo."""
    from datetime import timezone
    return {"cadeia": r["cadeia"], "seq": r["seq"], "quando": r["quando"].astimezone(timezone.utc).isoformat(),
            "operador": r["operador"], "acao": r["acao"], "investigacao_id": r["investigacao_id"],
            "detalhe": r["detalhe"] or {}, "livres": r["livres_compromisso"], "anterior": r["hash_anterior"]}


def hash_registro(r: dict) -> str:
    import hashlib

    import rfc8785
    return hashlib.sha256(rfc8785.dumps(registro_trilha(r))).hexdigest()


def compromisso_livre(sal: bytes, valor) -> str:
    import hashlib

    import rfc8785
    return hashlib.sha256(b"\x00" + sal + rfc8785.dumps(valor)).hexdigest()


def aad_livres(cadeia: int, seq: int) -> bytes:
    return f"kc-auditor/trilha|{cadeia}|{seq}".encode()


def trilha(cx, operador: str, acao: str, investigacao_id: int | None = None, **detalhe):
    """Acrescenta um registro à cadeia da investigação (ou à global). Campos livres (justificativa, motivo, alvo)
    saem do detalhe: ficam cifrados para a chave pública da investigação, e no hash entra só o compromisso."""
    import json
    import os as _os
    from datetime import datetime, timezone

    from psycopg.types.json import Jsonb

    from . import cripto
    livres = {k: detalhe.pop(k) for k in CAMPOS_LIVRES if detalhe.get(k) is not None}
    for k in CAMPOS_LIVRES:   # campo livre vazio não fica no detalhe (nem como null)
        detalhe.pop(k, None)
    detalhe = json.loads(json.dumps(detalhe, default=str))
    cadeia = investigacao_id or 0
    with cx.transaction():
        cx.execute("SELECT pg_advisory_xact_lock(%s, %s)", (CHAVE_TRILHA, cadeia))
        u = cx.execute("SELECT seq, hash FROM trilha_auditoria WHERE cadeia=%s ORDER BY seq DESC LIMIT 1",
                       (cadeia,)).fetchone()
        seq, anterior = (u["seq"] + 1, u["hash"]) if u else (1, genese(cadeia))
        comp = cif = None
        if livres:
            sais = {k: _os.urandom(32) for k in livres}
            comp = {k: compromisso_livre(sais[k], v) for k, v in livres.items()}
            pub = cx.execute("SELECT trilha_publica FROM investigacao WHERE id=%s",
                             (investigacao_id,)).fetchone()["trilha_publica"] if investigacao_id else None
            if pub:   # sem chave pública (cadeia global): só o compromisso; o texto não é guardado
                cif = cripto.selar_para(bytes(pub), json.dumps({k: {"valor": v, "sal": sais[k].hex()}
                                                                for k, v in livres.items()},
                                                               ensure_ascii=False).encode(), aad_livres(cadeia, seq))
        r = {"cadeia": cadeia, "seq": seq, "quando": datetime.now(timezone.utc), "operador": operador, "acao": acao,
             "investigacao_id": investigacao_id, "detalhe": detalhe, "livres_compromisso": comp,
             "hash_anterior": anterior}
        h = hash_registro(r)
        cx.execute("INSERT INTO trilha_auditoria (quando, operador, acao, investigacao_id, detalhe, cadeia, seq, "
                   "hash_anterior, hash, livres_cifrado, livres_compromisso) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)",
                   (r["quando"], operador, acao, investigacao_id, Jsonb(detalhe), cadeia, seq, anterior,
                    h, cif, Jsonb(comp) if comp else None))
    # cópia para o SIEM (§6.3): só ação, ator, horário, investigação e hashes; nada do detalhe nem texto livre
    from . import siem
    siem.enviar("trilha", ator=operador, investigacao=investigacao_id, registro=acao, cadeia=cadeia, seq=seq,
                sha256=h)


def verificar_cadeia(cx, cadeia: int | None = None) -> dict[int, list[str]]:
    """Confere continuidade (seq, hash anterior) e o hash de cada registro. Devolve problemas por cadeia."""
    out: dict[int, list[str]] = {}
    filtro = "WHERE cadeia=%s" if cadeia is not None else "WHERE cadeia IS NOT NULL"
    atual, prev, esperado = None, None, 1
    for r in cx.execute(f"SELECT * FROM trilha_auditoria {filtro} ORDER BY cadeia, seq",
                        (cadeia,) if cadeia is not None else ()):
        if r["cadeia"] != atual:
            atual, prev, esperado = r["cadeia"], genese(r["cadeia"]), 1
            out[atual] = []
        p = out[atual]
        if r["seq"] != esperado:
            p.append(f"seq {r['seq']}: esperado {esperado} (registro faltando)")
        if r["hash_anterior"] != prev:
            p.append(f"seq {r['seq']}: hash anterior não confere")
        if hash_registro(r) != r["hash"]:
            p.append(f"seq {r['seq']}: hash do registro não confere (registro alterado)")
        prev, esperado = r["hash"], r["seq"] + 1
    sem = cx.execute("SELECT count(*) n FROM trilha_auditoria WHERE hash IS NULL").fetchone()["n"]
    if sem and cadeia is None:
        out.setdefault(-1, []).append(f"{sem} registro(s) fora de cadeia (anteriores à W0b, não migrados)")
    return out

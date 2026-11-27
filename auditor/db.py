"""Banco do auditor (PostgreSQL)."""
from __future__ import annotations

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


def conectar(autocommit: bool = True) -> psycopg.Connection:
    return psycopg.connect(DSN, autocommit=autocommit, row_factory=dict_row)


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


def trilha(cx, operador: str, acao: str, investigacao_id: int | None = None, **detalhe):
    from psycopg.types.json import Jsonb
    cx.execute("INSERT INTO trilha_auditoria (operador, acao, investigacao_id, detalhe) VALUES (%s,%s,%s,%s)",
               (operador, acao, investigacao_id, Jsonb(detalhe)))

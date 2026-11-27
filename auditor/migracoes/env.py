"""Ambiente do Alembic: usa AUDITOR_DSN (o papel dono do esquema), com o driver psycopg 3."""
from alembic import context
from sqlalchemy import create_engine, pool

from auditor.db import DSN


def _url(dsn: str) -> str:
    for prefixo in ("postgresql://", "postgres://"):
        if dsn.startswith(prefixo):
            return "postgresql+psycopg://" + dsn[len(prefixo):]
    return dsn


def rodar():
    motor = create_engine(_url(DSN), poolclass=pool.NullPool)
    with motor.connect() as conexao:
        context.configure(connection=conexao, target_metadata=None, transaction_per_migration=True)
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    context.configure(url=_url(DSN), literal_binds=True)
    with context.begin_transaction():
        context.run_migrations()
else:
    rodar()

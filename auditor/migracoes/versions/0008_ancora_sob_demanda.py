"""Âncora sob demanda (W1): além da diária, uma âncora a qualquer momento (antes de gerar um pacote), na mesma
construção verificável. A diária continua uma por dia."""
from alembic import op

revision = "0008"
down_revision = "0007"
branch_labels = None
depends_on = None


def upgrade():
    op.get_bind().exec_driver_sql("""
ALTER TABLE ancora DROP CONSTRAINT IF EXISTS ancora_pkey;
ALTER TABLE ancora ADD COLUMN IF NOT EXISTS id bigserial PRIMARY KEY;
ALTER TABLE ancora ADD COLUMN IF NOT EXISTS tipo text NOT NULL DEFAULT 'diaria';      -- diaria | sob_demanda
ALTER TABLE ancora ADD COLUMN IF NOT EXISTS ate timestamptz;                          -- cabeças até este instante
-- preenche o instante das diárias já gravadas (o trigger de só inserção fica desligado só aqui, papel dono)
ALTER TABLE ancora DISABLE TRIGGER trg_ancora_ro;
UPDATE ancora SET ate = ((dia + 1)::timestamp AT TIME ZONE 'UTC') WHERE ate IS NULL AND tipo='diaria';
ALTER TABLE ancora ENABLE TRIGGER trg_ancora_ro;
CREATE UNIQUE INDEX IF NOT EXISTS ux_ancora_diaria ON ancora (dia) WHERE tipo = 'diaria';
""")


def downgrade():
    raise NotImplementedError

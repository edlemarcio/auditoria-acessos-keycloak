"""Fila única com rodízio entre investigações e jobs (preparar, fechar) para o worker contínuo (W0a)."""
from alembic import op

revision = "0002"
down_revision = "0001"
branch_labels = None
depends_on = None


def upgrade():
    op.get_bind().exec_driver_sql("""
ALTER TABLE investigacao ADD COLUMN IF NOT EXISTS prioridade int NOT NULL DEFAULT 0;
ALTER TABLE investigacao ADD COLUMN IF NOT EXISTS ultimo_atendimento timestamptz;
CREATE INDEX IF NOT EXISTS ix_tarefa_pendente ON tarefa (inicio_ms, id) WHERE status = 'pendente';

CREATE TABLE IF NOT EXISTS job (
  id bigserial PRIMARY KEY,
  tipo text NOT NULL,                -- preparar | fechar
  investigacao_id int NOT NULL REFERENCES investigacao(id),
  parametros jsonb NOT NULL DEFAULT '{}',
  status text NOT NULL DEFAULT 'pendente',   -- pendente | executando | concluido | falhou
  tentativas int NOT NULL DEFAULT 0,
  erro text,
  lease_ate timestamptz,
  criado_em timestamptz NOT NULL DEFAULT now(),
  atualizado timestamptz NOT NULL DEFAULT now()
);
-- no máximo um job ativo de cada tipo por investigação
CREATE UNIQUE INDEX IF NOT EXISTS ux_job_ativo ON job (tipo, investigacao_id)
  WHERE status IN ('pendente', 'executando');
""")


def downgrade():
    op.get_bind().exec_driver_sql("""
DROP TABLE IF EXISTS job;
DROP INDEX IF EXISTS ix_tarefa_pendente;
ALTER TABLE investigacao DROP COLUMN IF EXISTS ultimo_atendimento;
ALTER TABLE investigacao DROP COLUMN IF EXISTS prioridade;
""")

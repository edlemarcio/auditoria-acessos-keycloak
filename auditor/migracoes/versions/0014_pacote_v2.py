"""Pacote v2 (W5, PROPOSTA_WEB §6.4 a §6.7).

* `instancia.uuid`: id imutável da instância, usado em `_instancia` nos arquivos do pacote (renomear a instância não
  muda hash nenhum).
* `pacote`: formato, versão por investigação e tipo (`investigacao_12_v1`, `_v2`…), nome do arquivo, SHA-256 do
  manifesto, resultado da verificação feita pelo próprio verificador offline logo depois da geração.
* `comparacao`: cache do resultado de "Comparar execuções" entre uma investigação e a de origem (sem valores).
"""
from alembic import op

revision = "0014"
down_revision = "0013"
branch_labels = None
depends_on = None


def upgrade():
    op.execute("""
CREATE EXTENSION IF NOT EXISTS pgcrypto;
ALTER TABLE instancia ADD COLUMN IF NOT EXISTS uuid uuid NOT NULL DEFAULT gen_random_uuid();
CREATE UNIQUE INDEX IF NOT EXISTS ux_instancia_uuid ON instancia (uuid);

ALTER TABLE pacote ADD COLUMN IF NOT EXISTS formato int NOT NULL DEFAULT 1;
ALTER TABLE pacote ADD COLUMN IF NOT EXISTS versao int;
ALTER TABLE pacote ADD COLUMN IF NOT EXISTS nome text;
ALTER TABLE pacote ADD COLUMN IF NOT EXISTS manifesto_sha256 text;
ALTER TABLE pacote ADD COLUMN IF NOT EXISTS verificacao jsonb;
ALTER TABLE pacote ADD COLUMN IF NOT EXISTS eventos int;

CREATE TABLE IF NOT EXISTS comparacao (
  investigacao_id int NOT NULL REFERENCES investigacao(id),
  anterior_id int NOT NULL REFERENCES investigacao(id),
  calculado_em timestamptz NOT NULL DEFAULT now(),
  resultado jsonb NOT NULL,
  PRIMARY KEY (investigacao_id, anterior_id)
);
ALTER TABLE comparacao ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS designacao_api ON comparacao;
CREATE POLICY designacao_api ON comparacao USING (current_user <> 'kc_api' OR investigacao_id IN (
  SELECT d.investigacao_id FROM designacao d WHERE d.sub = current_setting('kc_auditor.sub', true)
  AND d.funcao = 'investigador'));
""")


def downgrade():
    raise NotImplementedError

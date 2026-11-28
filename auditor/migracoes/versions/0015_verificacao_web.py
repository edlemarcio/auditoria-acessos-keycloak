"""Verificação de pacote pela web (W5, PROPOSTA_WEB §6.5).

* `verificacao`: um pedido de verificação por upload. O arquivo vai para a área do worker de pacotes, que o verifica
  em streaming com o verificador offline (só as chaves públicas publicadas) e o apaga em seguida; fica o SHA-256, o
  tamanho e o resultado.
* `job.investigacao_id` passa a aceitar nulo (o job `verificar` não pertence a uma investigação).
"""
from alembic import op

revision = "0015"
down_revision = "0014"
branch_labels = None
depends_on = None


def upgrade():
    op.execute("""
ALTER TABLE job ALTER COLUMN investigacao_id DROP NOT NULL;
CREATE TABLE IF NOT EXISTS verificacao (
  id bigserial PRIMARY KEY,
  sub text NOT NULL,
  status text NOT NULL DEFAULT 'pendente',      -- pendente | verificando | pronta | falhou
  nome text,
  sha256 text,
  tamanho bigint,
  arquivo text,                                  -- apagado depois da verificação
  resultado jsonb,
  erro text,
  criado_em timestamptz NOT NULL DEFAULT now(),
  concluido_em timestamptz
);
CREATE INDEX IF NOT EXISTS ix_verificacao_sub ON verificacao (sub, id);
""")


def downgrade():
    raise NotImplementedError

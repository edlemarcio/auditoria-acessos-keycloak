"""Envelope de chaves por investigação (W0b, PROPOSTA_WEB §5.3): DEK principal e DEK de terceiros, envolvidas pela
KEK (Vault Transit no modo vault; chave local derivada de AUDITOR_CHAVE no modo local)."""
from alembic import op

revision = "0003"
down_revision = "0002"
branch_labels = None
depends_on = None


def upgrade():
    op.get_bind().exec_driver_sql("""
CREATE TABLE IF NOT EXISTS chave_investigacao (
  investigacao_id int NOT NULL REFERENCES investigacao(id),
  classe text NOT NULL,              -- principal | terceiros
  envelope bytea NOT NULL,           -- DEK envolvida: 'vault:vN:...' (Transit) ou 'local:v1:' + nonce + cifrado
  key_id text NOT NULL,              -- kc-auditor-kek | local
  versao int NOT NULL DEFAULT 1,
  criado_em timestamptz NOT NULL DEFAULT now(),
  destruida_em timestamptz,          -- expurgo: envelope apagado (destruição criptográfica)
  PRIMARY KEY (investigacao_id, classe)
);
""")


def downgrade():
    op.get_bind().exec_driver_sql("DROP TABLE IF EXISTS chave_investigacao")

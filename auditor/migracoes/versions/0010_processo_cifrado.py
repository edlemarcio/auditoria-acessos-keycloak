"""Nº do processo como texto livre cifrado com a DEK e busca pelo HMAC normalizado; contas informadas no pedido
(cifradas com a DEK) para o preparo (W2, decisões da coordenação registradas em docs/W2_CONTRATO.md)."""
from alembic import op

revision = "0010"
down_revision = "0009"
branch_labels = None
depends_on = None


def upgrade():
    op.get_bind().exec_driver_sql("""
ALTER TABLE investigacao ADD COLUMN IF NOT EXISTS processo_cifrado bytea;
ALTER TABLE investigacao ADD COLUMN IF NOT EXISTS processo_hmac text;          -- HMAC do nº só com letras e dígitos
ALTER TABLE investigacao ADD COLUMN IF NOT EXISTS contas_cifradas bytea;       -- [{instancia, realm, username}]
DROP INDEX IF EXISTS ix_investigacao_processo;
ALTER TABLE investigacao DROP COLUMN IF EXISTS processo;
ALTER TABLE investigacao DROP COLUMN IF EXISTS processo_busca;
CREATE INDEX IF NOT EXISTS ix_investigacao_processo_hmac ON investigacao (processo_hmac);
""")


def downgrade():
    raise NotImplementedError

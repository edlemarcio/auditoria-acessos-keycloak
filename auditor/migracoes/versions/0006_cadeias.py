"""Trilha encadeada por investigação e âncora diária (W0b, PROPOSTA_WEB §6.3)."""
from alembic import op

revision = "0006"
down_revision = "0005"
branch_labels = None
depends_on = None


def upgrade():
    op.get_bind().exec_driver_sql("""
-- cadeia = investigação (0 = cadeia global: logins, cadastros, eventos sem investigação)
ALTER TABLE trilha_auditoria ADD COLUMN IF NOT EXISTS cadeia int;
ALTER TABLE trilha_auditoria ADD COLUMN IF NOT EXISTS seq bigint;
ALTER TABLE trilha_auditoria ADD COLUMN IF NOT EXISTS hash_anterior text;
ALTER TABLE trilha_auditoria ADD COLUMN IF NOT EXISTS hash text;
-- campos livres: cifrados para a chave pública da investigação; no hash entra só o compromisso com sal
ALTER TABLE trilha_auditoria ADD COLUMN IF NOT EXISTS livres_cifrado bytea;
ALTER TABLE trilha_auditoria ADD COLUMN IF NOT EXISTS livres_compromisso jsonb;
CREATE UNIQUE INDEX IF NOT EXISTS ux_trilha_cadeia ON trilha_auditoria (cadeia, seq);

-- par X25519 da investigação para os campos livres da trilha: a pública em claro (qualquer serviço registra),
-- a privada cifrada com a DEK (só quem tem a DEK lê; morre no expurgo)
ALTER TABLE investigacao ADD COLUMN IF NOT EXISTS trilha_publica bytea;
ALTER TABLE investigacao ADD COLUMN IF NOT EXISTS trilha_privada_cifrada bytea;

-- âncora diária: raiz Merkle das cabeças de todas as cadeias e carimbo do tempo sobre ela
CREATE TABLE IF NOT EXISTS ancora (
  dia date PRIMARY KEY,
  raiz text NOT NULL,
  cabecas jsonb NOT NULL,            -- [{cadeia, seq, hash}] na ordem das folhas
  carimbo jsonb NOT NULL,            -- RFC 3161 (ACT) ou "simulado" até a ACT
  criado_em timestamptz NOT NULL DEFAULT now()
);
CREATE OR REPLACE FUNCTION ancora_somente_insercao() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN RAISE EXCEPTION 'ancora aceita somente inserção'; END $$;
DROP TRIGGER IF EXISTS trg_ancora_ro ON ancora;
CREATE TRIGGER trg_ancora_ro BEFORE UPDATE OR DELETE ON ancora FOR EACH ROW EXECUTE FUNCTION ancora_somente_insercao();
""")


def downgrade():
    raise NotImplementedError("a cadeia da trilha não tem volta")

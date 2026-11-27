"""Compromissos com sal, selos de fatia e versões divergentes (W0b, PROPOSTA_WEB §6.1)."""
from alembic import op

revision = "0005"
down_revision = "0004"
branch_labels = None
depends_on = None


def upgrade():
    op.get_bind().exec_driver_sql("""
-- folha: compromisso com sal do evento como recebido (o sal fica dentro do cifrado);
-- hash_conteudo: HMAC do conteúdo com K_pseudo, para a releitura comparar conteúdo sem oráculo
ALTER TABLE evento ADD COLUMN IF NOT EXISTS folha text;
ALTER TABLE evento ADD COLUMN IF NOT EXISTS hash_conteudo text;

-- versão relida diferente da gravada: as duas ficam guardadas; o evento oficial continua o primeiro
CREATE TABLE IF NOT EXISTS evento_divergente (
  id bigserial PRIMARY KEY,
  investigacao_id int NOT NULL REFERENCES investigacao(id),
  instancia_id int NOT NULL,
  realm text NOT NULL,
  evento_id text NOT NULL,
  conta_id int NOT NULL,
  tarefa_id bigint,
  time_ms bigint NOT NULL,
  tipo text NOT NULL,                -- conteudo (mesmo id) | possivel_alteracao (Keycloak <= 21, id pelo conteúdo)
  hash_conteudo text NOT NULL,
  cifrado bytea NOT NULL,
  detectado_em timestamptz NOT NULL DEFAULT now(),
  UNIQUE (investigacao_id, instancia_id, realm, evento_id, hash_conteudo)
);

-- selo da fatia: raiz Merkle das folhas dos eventos da conta no intervalo, no fim da tarefa
CREATE TABLE IF NOT EXISTS selo (
  id bigserial PRIMARY KEY,
  investigacao_id int NOT NULL REFERENCES investigacao(id),
  tarefa_id bigint NOT NULL REFERENCES tarefa(id),
  conta_id int NOT NULL,
  inicio_ms bigint NOT NULL,
  fim_ms bigint NOT NULL,
  n_eventos int NOT NULL,
  raiz text NOT NULL,
  versao int NOT NULL,
  origem text NOT NULL DEFAULT 'coleta',   -- coleta | migracao (selado depois, na migração)
  criado_em timestamptz NOT NULL DEFAULT now(),
  UNIQUE (tarefa_id, versao)
);
CREATE INDEX IF NOT EXISTS ix_selo_inv ON selo (investigacao_id);
CREATE OR REPLACE FUNCTION selo_somente_insercao() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN RAISE EXCEPTION 'selo aceita somente inserção'; END $$;
DROP TRIGGER IF EXISTS trg_selo_ro ON selo;
CREATE TRIGGER trg_selo_ro BEFORE UPDATE OR DELETE ON selo FOR EACH ROW EXECUTE FUNCTION selo_somente_insercao();
DROP TRIGGER IF EXISTS trg_selo_truncate ON selo;
CREATE TRIGGER trg_selo_truncate BEFORE TRUNCATE ON selo FOR EACH STATEMENT EXECUTE FUNCTION selo_somente_insercao();
""")


def downgrade():
    op.get_bind().exec_driver_sql("""
DROP TABLE IF EXISTS selo; DROP TABLE IF EXISTS evento_divergente;
ALTER TABLE evento DROP COLUMN IF EXISTS hash_conteudo; ALTER TABLE evento DROP COLUMN IF EXISTS folha;
""")

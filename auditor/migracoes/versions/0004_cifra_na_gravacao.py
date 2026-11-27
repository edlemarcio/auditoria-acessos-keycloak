"""Cifra na gravação e pseudônimos (W0b, PROPOSTA_WEB §5.1 e §5.4).

Colunas cifradas com a DEK da investigação ao lado das antigas, que passam a aceitar NULL e ficam vazias depois da
migração dos dados (auditor/migrar_cifra.py, chamada pelo `init` no modo local). Pseudônimos: HMAC-SHA-256 completo
com K_pseudo (derivada da DEK) nas colunas ps_*, e rótulos sequenciais na tabela pseudonimo.
"""
from alembic import op

revision = "0004"
down_revision = "0003"
branch_labels = None
depends_on = None


def upgrade():
    op.get_bind().exec_driver_sql("""
-- evento: o conteúdo inteiro (como recebido) cifrado; em claro só o técnico (tipo, aplicação, realm, horário, erro
-- padronizado) e os pseudônimos de conta, IP e sessão
ALTER TABLE evento ADD COLUMN IF NOT EXISTS cifrado bytea;
ALTER TABLE evento ADD COLUMN IF NOT EXISTS ps_conta text;
ALTER TABLE evento ADD COLUMN IF NOT EXISTS ps_ip text;
ALTER TABLE evento ADD COLUMN IF NOT EXISTS ps_sessao text;
ALTER TABLE evento ALTER COLUMN bruto DROP NOT NULL;
CREATE INDEX IF NOT EXISTS ix_evento_conta_tempo ON evento (investigacao_id, conta_id, time_ms);

-- conta: user_id, username e e-mail cifrados; unicidade pelo pseudônimo da conta
ALTER TABLE conta ADD COLUMN IF NOT EXISTS cifrado bytea;
ALTER TABLE conta ADD COLUMN IF NOT EXISTS ps_conta text;
CREATE UNIQUE INDEX IF NOT EXISTS ux_conta_ps ON conta (investigacao_id, instancia_id, realm, ps_conta);

-- requisicao: em claro só a versão redigida; original e corpo (minimizado) cifrados
ALTER TABLE requisicao ADD COLUMN IF NOT EXISTS cifrado bytea;
ALTER TABLE requisicao ADD COLUMN IF NOT EXISTS corpo_cifrado bytea;
ALTER TABLE requisicao ADD COLUMN IF NOT EXISTS corpo_tipo text;      -- inteiro | linhas
ALTER TABLE requisicao ALTER COLUMN caminho DROP NOT NULL;

ALTER TABLE conta_extra ADD COLUMN IF NOT EXISTS id bigserial;
ALTER TABLE conta_extra ADD COLUMN IF NOT EXISTS cifrado bytea;

ALTER TABLE investigacao ADD COLUMN IF NOT EXISTS justificativa_cifrada bytea;
ALTER TABLE tarefa ADD COLUMN IF NOT EXISTS erro_cifrado bytea;

-- histórico de contas do alvo: entre investigações, com K_historico (não com a DEK de uma investigação)
ALTER TABLE historico_identidade ADD COLUMN IF NOT EXISTS uid_hmac text;
ALTER TABLE historico_identidade ADD COLUMN IF NOT EXISTS cifrado bytea;
ALTER TABLE historico_identidade DROP CONSTRAINT IF EXISTS historico_identidade_pkey;
ALTER TABLE historico_identidade ALTER COLUMN user_id DROP NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS ux_historico ON historico_identidade (alvo_hmac, instancia_id, realm, uid_hmac);

-- rótulos dos pseudônimos: sequenciais, atribuídos no fechamento por ordem de aparição, nunca renumerados
CREATE TABLE IF NOT EXISTS pseudonimo (
  investigacao_id int NOT NULL REFERENCES investigacao(id),
  classe text NOT NULL,              -- conta | ip | sessao
  hmac text NOT NULL,
  rotulo int NOT NULL,
  primeiro_ms bigint,
  criado_em timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (investigacao_id, classe, hmac),
  UNIQUE (investigacao_id, classe, rotulo)
);
""")


def downgrade():
    raise NotImplementedError("a cifra na gravação não tem volta (os dados em claro foram apagados)")

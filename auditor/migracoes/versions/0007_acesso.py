"""Acesso (W1, PROPOSTA_WEB §4 e §8.9): usuários do realm dedicado, designação por investigação, pedidos que exigem
aprovação (quatro olhos), sessão web do BFF, pacotes e downloads."""
from alembic import op

revision = "0007"
down_revision = "0006"
branch_labels = None
depends_on = None


def upgrade():
    op.get_bind().exec_driver_sql("""
CREATE TABLE IF NOT EXISTS usuario (
  sub text PRIMARY KEY,
  username text NOT NULL,
  nome text,
  unidade text,
  papeis text[] NOT NULL DEFAULT '{}',   -- os do último login (a fonte é o realm dedicado)
  primeiro_login timestamptz NOT NULL DEFAULT now(),
  ultimo_login timestamptz NOT NULL DEFAULT now()
);

-- quem faz o quê em cada investigação; a segregação é conferida no servidor
CREATE TABLE IF NOT EXISTS designacao (
  investigacao_id int NOT NULL REFERENCES investigacao(id),
  funcao text NOT NULL,              -- solicitante | aprovador | investigador
  sub text NOT NULL,
  designado_por text,
  criado_em timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (investigacao_id, funcao, sub)
);
CREATE INDEX IF NOT EXISTS ix_designacao_sub ON designacao (sub);

ALTER TABLE investigacao ADD COLUMN IF NOT EXISTS solicitante_sub text;
ALTER TABLE investigacao ADD COLUMN IF NOT EXISTS sigilosa boolean NOT NULL DEFAULT false;
ALTER TABLE investigacao ADD COLUMN IF NOT EXISTS origem_externa boolean NOT NULL DEFAULT false;
ALTER TABLE investigacao ADD COLUMN IF NOT EXISTS origem_cifrada bytea;   -- órgão, ofício, processo, fundamento

-- decisões que exigem outra pessoa: a investigação, o pacote sem máscara
CREATE TABLE IF NOT EXISTS pedido (
  id bigserial PRIMARY KEY,
  investigacao_id int NOT NULL REFERENCES investigacao(id),
  tipo text NOT NULL,                -- investigacao | pacote_sem_mascara
  solicitante_sub text NOT NULL,
  status text NOT NULL DEFAULT 'aguardando',   -- aguardando | aprovado | devolvido | recusado | cancelado
  parametros jsonb NOT NULL DEFAULT '{}',
  decidido_por text,
  decidido_em timestamptz,
  criado_em timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS ix_pedido_status ON pedido (status, tipo);

-- sessão do BFF: o id do cookie só existe em hash; os tokens ficam cifrados com uma chave que só o cookie tem
CREATE TABLE IF NOT EXISTS sessao_web (
  id_hash text PRIMARY KEY,
  sub text NOT NULL,
  sid text,                          -- sessão no Keycloak (logout pelo canal de retorno)
  auth_time bigint NOT NULL,
  tokens_cifrados bytea NOT NULL,
  criado_em timestamptz NOT NULL DEFAULT now(),
  ultimo_uso timestamptz NOT NULL DEFAULT now(),
  encerrada_em timestamptz
);
CREATE TABLE IF NOT EXISTS login_pendente (
  estado text PRIMARY KEY,
  verificador text NOT NULL,
  nonce text NOT NULL,
  volta text NOT NULL,
  criado_em timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS pacote (
  id bigserial PRIMARY KEY,
  investigacao_id int NOT NULL REFERENCES investigacao(id),
  sem_mascara boolean NOT NULL,
  pedido_por text NOT NULL,
  pedido_id bigint REFERENCES pedido(id),
  status text NOT NULL DEFAULT 'gerando',      -- gerando | pronto | falhou | expirado
  arquivo text,
  sha256 text,
  erro text,
  criado_em timestamptz NOT NULL DEFAULT now(),
  pronto_em timestamptz,
  expira_em timestamptz
);
CREATE TABLE IF NOT EXISTS link_download (
  token_hash text PRIMARY KEY,
  pacote_id bigint NOT NULL REFERENCES pacote(id),
  sub text NOT NULL,
  expira_em timestamptz NOT NULL,
  usado_em timestamptz
);
CREATE TABLE IF NOT EXISTS download (
  id bigserial PRIMARY KEY,
  pacote_id bigint NOT NULL REFERENCES pacote(id),
  sub text NOT NULL,
  quando timestamptz NOT NULL DEFAULT now(),
  sha256 text NOT NULL
);
""")


def downgrade():
    raise NotImplementedError

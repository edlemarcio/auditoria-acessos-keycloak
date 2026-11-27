"""Gestão (W2, PROPOSTA_WEB §4 e §7; docs/W2_CONTRATO.md): rascunho, tipo de processo, documento de origem cifrado,
preservação urgente com coleta lacrada, notificações, substitutos e escalonamento, recertificação, vigia de papéis e
batimento dos workers."""
from alembic import op

revision = "0009"
down_revision = "0008"
branch_labels = None
depends_on = None


def upgrade():
    op.get_bind().exec_driver_sql("""
ALTER TABLE investigacao ADD COLUMN IF NOT EXISTS tipo_processo text;            -- base legal (§10.1)
ALTER TABLE investigacao ADD COLUMN IF NOT EXISTS processo text;                 -- nº do processo (metadado)
ALTER TABLE investigacao ADD COLUMN IF NOT EXISTS processo_busca text;           -- só letras e dígitos, minúsculas
ALTER TABLE investigacao ADD COLUMN IF NOT EXISTS preservacao_urgente boolean NOT NULL DEFAULT false;
ALTER TABLE investigacao ADD COLUMN IF NOT EXISTS lacrada boolean NOT NULL DEFAULT false;   -- coleta lacrada
ALTER TABLE investigacao ADD COLUMN IF NOT EXISTS atualizado_em timestamptz NOT NULL DEFAULT now();
CREATE INDEX IF NOT EXISTS ix_investigacao_processo ON investigacao (processo_busca);
ALTER TABLE usuario ADD COLUMN IF NOT EXISTS coordenador boolean NOT NULL DEFAULT false;   -- atributo no realm

-- documento de origem: o conteúdo e o nome cifrados com a DEK da investigação; o SHA-256 (do claro) vai à trilha
CREATE TABLE IF NOT EXISTS documento (
  investigacao_id int PRIMARY KEY REFERENCES investigacao(id),
  cifrado bytea NOT NULL,
  meta_cifrado bytea NOT NULL,       -- {"nome", "tipo"}
  sha256 text NOT NULL,
  tamanho int NOT NULL,
  enviado_por text NOT NULL,
  enviado_em timestamptz NOT NULL DEFAULT now()
);

-- preservação urgente (§4.4): prazos em dias úteis
CREATE TABLE IF NOT EXISTS preservacao (
  investigacao_id int PRIMARY KEY REFERENCES investigacao(id),
  autorizada_por text NOT NULL,
  autorizada_em timestamptz NOT NULL,
  escalona_em timestamptz NOT NULL,
  destroi_em timestamptz NOT NULL,
  escalonada_em timestamptz,
  prorrogada_por text,
  prorrogada_em timestamptz,
  encerrada_em timestamptz,
  desfecho text                      -- aprovada | recusada | expirada
);

-- central de notificações (§7.12); o e-mail só vai para logs/email.jsonl
CREATE TABLE IF NOT EXISTS notificacao (
  id bigserial PRIMARY KEY,
  sub text NOT NULL,
  tipo text NOT NULL,
  texto text NOT NULL,
  investigacao_id int,
  criado_em timestamptz NOT NULL DEFAULT now(),
  lida_em timestamptz
);
CREATE INDEX IF NOT EXISTS ix_notificacao_sub ON notificacao (sub, lida_em);

-- substituto de cada aprovador e escalonamento dos pedidos parados (§4.2)
CREATE TABLE IF NOT EXISTS substituto (
  aprovador_sub text PRIMARY KEY,
  substituto_sub text NOT NULL,
  atualizado_em timestamptz NOT NULL DEFAULT now()
);
ALTER TABLE pedido ADD COLUMN IF NOT EXISTS escalonamento int NOT NULL DEFAULT 0;   -- 0 | 1 substituto | 2 coord.
ALTER TABLE pedido ADD COLUMN IF NOT EXISTS escalonado_em timestamptz;

-- papéis vistos no realm dedicado (vigia de mudanças, inclusive feitas direto no console do Keycloak)
CREATE TABLE IF NOT EXISTS papel_visto (
  sub text PRIMARY KEY,
  username text NOT NULL,
  papeis text[] NOT NULL DEFAULT '{}',
  coordenador boolean NOT NULL DEFAULT false,
  visto_em timestamptz NOT NULL DEFAULT now(),
  recertificado_em timestamptz
);

-- recertificação (§4.3): o que não for confirmado até o prazo é revogado
CREATE TABLE IF NOT EXISTS recertificacao (
  id bigserial PRIMARY KEY,
  aberta_por text NOT NULL,
  aberta_em timestamptz NOT NULL DEFAULT now(),
  prazo timestamptz NOT NULL,
  encerrada_em timestamptz
);
CREATE TABLE IF NOT EXISTS recertificacao_item (
  recertificacao_id bigint NOT NULL REFERENCES recertificacao(id),
  sub text NOT NULL,
  username text NOT NULL,
  papeis text[] NOT NULL,
  manter boolean,
  decidido_por text,
  decidido_em timestamptz,
  PRIMARY KEY (recertificacao_id, sub)
);

-- batimento dos workers (saúde, §13 do contrato)
CREATE TABLE IF NOT EXISTS worker_visto (
  id text PRIMARY KEY,               -- papel@host:pid
  papel text NOT NULL,
  visto_em timestamptz NOT NULL DEFAULT now()
);
""")


def downgrade():
    raise NotImplementedError

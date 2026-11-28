"""Sessão de análise e revelação controlada (W4, PROPOSTA_WEB §5.5 e §7.5).

* `sessao_analise`: uma por investigador e investigação de cada vez; motivo da lista (texto livre cifrado com a DEK
  quando "outro"); expira no servidor (até 4 h, prorrogável duas vezes, teto de 8 h por usuário por dia).
* `revelacao`: cada item revelado (classe + HMAC do pseudônimo, ou referência do evento); só o rótulo vai para a trilha,
  nunca o valor. Itens acima da cota ou de terceiro só com `pedido` aprovado (quatro olhos).
* RLS para o papel kc_api: só o investigador designado.
"""
from alembic import op

revision = "0013"
down_revision = "0012"
branch_labels = None
depends_on = None


def _politica(tabela: str) -> str:
    return f"""
ALTER TABLE {tabela} ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS designacao_api ON {tabela};
CREATE POLICY designacao_api ON {tabela} USING (current_user <> 'kc_api' OR investigacao_id IN (
  SELECT d.investigacao_id FROM designacao d WHERE d.sub = current_setting('kc_auditor.sub', true)
  AND d.funcao = 'investigador')
  -- o aprovador lê os metadados para decidir pedidos de revelação (quantidade, classe, histórico; nunca valores)
  OR EXISTS (SELECT 1 FROM usuario u WHERE u.sub = current_setting('kc_auditor.sub', true)
             AND 'aprovador' = ANY(u.papeis)));
"""


def upgrade():
    op.get_bind().exec_driver_sql("""
CREATE TABLE IF NOT EXISTS sessao_analise (
  id bigserial PRIMARY KEY,
  investigacao_id integer NOT NULL REFERENCES investigacao(id),
  sub text NOT NULL,
  motivo_codigo text NOT NULL,
  motivo_cifrado bytea,
  inicio timestamptz NOT NULL DEFAULT now(),
  expira_em timestamptz NOT NULL,
  prorrogacoes integer NOT NULL DEFAULT 0,
  total boolean NOT NULL DEFAULT false,          -- revelação total aprovada
  encerrada_em timestamptz,
  encerrada_por text                             -- usuario | expiracao | logout | teto
);
CREATE UNIQUE INDEX IF NOT EXISTS ux_sessao_ativa ON sessao_analise (investigacao_id, sub) WHERE encerrada_em IS NULL;
CREATE INDEX IF NOT EXISTS ix_sessao_sub_dia ON sessao_analise (sub, inicio);
CREATE TABLE IF NOT EXISTS revelacao (
  id bigserial PRIMARY KEY,
  sessao_id bigint NOT NULL REFERENCES sessao_analise(id),
  investigacao_id integer NOT NULL REFERENCES investigacao(id),
  sub text NOT NULL,
  classe text NOT NULL,                          -- conta | ip | sessao | evento
  chave text NOT NULL,                           -- HMAC do pseudônimo ou ref do evento
  rotulo text,
  terceiro boolean NOT NULL DEFAULT false,
  pedido_id bigint,                              -- aprovação que liberou acima da cota / terceiro / lista
  quando timestamptz NOT NULL DEFAULT now(),
  UNIQUE (sessao_id, classe, chave)
);
CREATE INDEX IF NOT EXISTS ix_revelacao_inv ON revelacao (investigacao_id, classe, chave);
""" + _politica("sessao_analise") + _politica("revelacao"))


def downgrade():
    raise NotImplementedError

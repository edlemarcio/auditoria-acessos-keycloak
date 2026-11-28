"""Análise (W3, PROPOSTA_WEB §8.4 e §8.6): agregados por hora, destaques, decisões sobre contas e RLS por designação.

* `agregado_hora`: contagens por hora UTC × instância × realm × aplicação × tipo × conta (pseudônimo). Totais e séries
  com qualquer combinação de filtros saem daqui; as contagens distintas (IPs, aplicações) saem de `evento` pelos
  índices novos.
* `destaque`: rajadas, fora do expediente e IP novo, calculados sobre pseudônimos (nada em claro).
* `analise`: estado do cálculo por investigação (versão dos agregados, recálculo pendente, quando).
* `conta_decisao`: incluir/excluir conta com motivo cifrado com a DEK.
* RLS em `evento`, `pseudonimo`, `conta_extra` (só o investigador designado) e `conta` (quem tem qualquer
  designação na investigação), aplicada só ao papel `kc_api` (a API define `kc_auditor.sub` em cada conexão a partir
  da sessão OIDC validada). Os papéis de serviço (workers, chaveiro) e o dono não são afetados.
"""
from alembic import op

revision = "0011"
down_revision = "0010"
branch_labels = None
depends_on = None

_DESIGNADO = ("EXISTS (SELECT 1 FROM designacao d WHERE d.investigacao_id = {t}.investigacao_id "
              "AND d.sub = current_setting('kc_auditor.sub', true){f})")


def _politica(tabela: str, funcao: str | None) -> str:
    f = f" AND d.funcao = '{funcao}'" if funcao else ""
    cond = _DESIGNADO.format(t=tabela, f=f)
    return f"""
ALTER TABLE {tabela} ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS designacao_api ON {tabela};
CREATE POLICY designacao_api ON {tabela} USING (current_user <> 'kc_api' OR {cond});
"""


def upgrade():
    op.get_bind().exec_driver_sql("""
CREATE TABLE IF NOT EXISTS agregado_hora (
  investigacao_id integer NOT NULL REFERENCES investigacao(id),
  hora timestamptz NOT NULL,
  instancia_id integer NOT NULL,
  realm text NOT NULL,
  client_id text NOT NULL DEFAULT '',
  type text NOT NULL,
  ps_conta text NOT NULL DEFAULT '',
  n integer NOT NULL,
  PRIMARY KEY (investigacao_id, hora, instancia_id, realm, client_id, type, ps_conta)
);
CREATE TABLE IF NOT EXISTS destaque (
  id bigserial PRIMARY KEY,
  investigacao_id integer NOT NULL REFERENCES investigacao(id),
  tipo text NOT NULL,                   -- rajada | fora_expediente | ip_novo
  inicio_ms bigint NOT NULL,
  fim_ms bigint,
  instancia_id integer,
  realm text,
  ps_conta text,
  ps_ip text,
  n integer NOT NULL DEFAULT 1,
  dados jsonb                           -- só pseudônimos e dimensões técnicas
);
CREATE INDEX IF NOT EXISTS ix_destaque_inv ON destaque (investigacao_id, tipo, inicio_ms);
CREATE TABLE IF NOT EXISTS analise (
  investigacao_id integer PRIMARY KEY REFERENCES investigacao(id),
  versao integer NOT NULL DEFAULT 0,
  calculado_em timestamptz,
  eventos integer,
  recalculo_pedido_em timestamptz,      -- não nulo: há recálculo pendente (inclusão/exclusão de conta)
  motivo_recalculo text
);
CREATE TABLE IF NOT EXISTS conta_decisao (
  id bigserial PRIMARY KEY,
  investigacao_id integer NOT NULL REFERENCES investigacao(id),
  conta_id integer NOT NULL REFERENCES conta(id),
  incluida boolean NOT NULL,
  motivo_cifrado bytea NOT NULL,
  por text NOT NULL,
  quando timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS ix_conta_decisao ON conta_decisao (investigacao_id, conta_id, quando);
CREATE INDEX IF NOT EXISTS ix_evento_inv_ip ON evento (investigacao_id, ps_ip, time_ms);
CREATE INDEX IF NOT EXISTS ix_evento_inv_dim ON evento (investigacao_id, instancia_id, realm, client_id, type, time_ms);
CREATE INDEX IF NOT EXISTS ix_evento_keyset ON evento (investigacao_id, time_ms, id);
""" + _politica("evento", "investigador") + _politica("pseudonimo", "investigador")
        + _politica("conta_extra", "investigador") + _politica("conta", None))


def downgrade():
    raise NotImplementedError

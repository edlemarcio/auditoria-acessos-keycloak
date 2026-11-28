"""Agregados para o dashboard em < 2 s com 500 mil eventos (W3, PROPOSTA_WEB §8.4 e §7.11).

* `agregado_hora` ganha o primeiro e o último horário de cada célula (KPIs de primeiro e último acesso exatos).
* `agregado_ip`: contagens por IP (pseudônimo) × instância × realm × aplicação × tipo × conta, com o primeiro e o
  último horário e a marca `novo` (IP ausente do período de base). IPs distintos, ranking e "IP novo" saem daqui.
* RLS como na 0011: agregado_ip só para o investigador designado; agregado_hora para qualquer designação (a visão
  agregada do solicitante sai dele, sem IPs nem contas).
"""
from alembic import op

revision = "0012"
down_revision = "0011"
branch_labels = None
depends_on = None


def _politica(tabela: str, funcao: str | None) -> str:
    f = f" AND d.funcao = '{funcao}'" if funcao else ""
    return f"""
ALTER TABLE {tabela} ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS designacao_api ON {tabela};
CREATE POLICY designacao_api ON {tabela} USING (current_user <> 'kc_api' OR investigacao_id IN (
  SELECT d.investigacao_id FROM designacao d WHERE d.sub = current_setting('kc_auditor.sub', true){f}));
"""


def upgrade():
    op.get_bind().exec_driver_sql("""
ALTER TABLE agregado_hora ADD COLUMN IF NOT EXISTS primeiro_ms bigint;
ALTER TABLE agregado_hora ADD COLUMN IF NOT EXISTS ultimo_ms bigint;
CREATE TABLE IF NOT EXISTS agregado_ip (
  investigacao_id integer NOT NULL REFERENCES investigacao(id),
  ps_ip text NOT NULL,
  instancia_id integer NOT NULL,
  realm text NOT NULL,
  client_id text NOT NULL DEFAULT '',
  type text NOT NULL,
  ps_conta text NOT NULL DEFAULT '',
  novo boolean NOT NULL,
  n integer NOT NULL,
  primeiro_ms bigint NOT NULL,
  ultimo_ms bigint NOT NULL,
  PRIMARY KEY (investigacao_id, ps_ip, instancia_id, realm, client_id, type, ps_conta)
);
CREATE INDEX IF NOT EXISTS ix_evento_inv_tipo_tempo ON evento (investigacao_id, type, time_ms);
"""
        # a 0011 usou subconsulta correlacionada; a forma não correlacionada é avaliada uma vez por consulta
        + _politica("evento", "investigador") + _politica("pseudonimo", "investigador")
        + _politica("conta_extra", "investigador") + _politica("conta", None)
        + _politica("agregado_ip", "investigador") + _politica("agregado_hora", None))


def downgrade():
    raise NotImplementedError

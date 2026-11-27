"""Banco do auditor (PostgreSQL)."""
from __future__ import annotations

import os

import psycopg
from psycopg.rows import dict_row

DSN = os.environ.get("AUDITOR_DSN", "postgresql://postgres@127.0.0.1/auditor")

SCHEMA = """
CREATE TABLE IF NOT EXISTS instancia (
  id serial PRIMARY KEY,
  nome text UNIQUE NOT NULL,
  url text NOT NULL,                 -- ex.: https://sso.exemplo.gov.br  (KC 18 legado: inclua /auth)
  realm_auth text NOT NULL DEFAULT 'master',
  client_id text NOT NULL,
  segredo_cifrado bytea NOT NULL,
  ca_path text,
  concorrencia int NOT NULL DEFAULT 2,
  req_por_s real NOT NULL DEFAULT 5,
  versao_declarada text,
  mapeamento jsonb NOT NULL DEFAULT '{"cpf": "cpf", "titulo": "tituloEleitor"}',
  buscar_username boolean NOT NULL DEFAULT true,
  realms_esperados text[] NOT NULL DEFAULT '{}',
  realm_homologacao text,
  usuario_sonda text,
  sondas jsonb,
  sondas_em timestamptz,
  criado_em timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS realm_snapshot (
  id bigserial PRIMARY KEY,
  instancia_id int NOT NULL REFERENCES instancia(id),
  realm text NOT NULL,
  lido_em timestamptz NOT NULL DEFAULT now(),
  visivel boolean NOT NULL,
  config jsonb,
  user_profile jsonb,
  federacao jsonb,
  status text NOT NULL,
  detalhe text,
  acao text
);
CREATE TABLE IF NOT EXISTS investigacao (
  id serial PRIMARY KEY,
  criado_em timestamptz NOT NULL DEFAULT now(),
  operador text NOT NULL,
  justificativa text NOT NULL,
  tipo text NOT NULL,
  alvo_cifrado bytea NOT NULL,
  alvo_hmac text NOT NULL,
  alvo_mascarado text NOT NULL,
  inicio_ms bigint NOT NULL,
  fim_ms bigint NOT NULL,
  fuso text NOT NULL,
  granularidade text NOT NULL,
  status text NOT NULL DEFAULT 'na_fila',
  parametros jsonb NOT NULL DEFAULT '{}',
  execucao_anterior int REFERENCES investigacao(id),
  concluido_em timestamptz
);
CREATE TABLE IF NOT EXISTS conta (
  id serial PRIMARY KEY,
  investigacao_id int NOT NULL REFERENCES investigacao(id),
  instancia_id int NOT NULL REFERENCES instancia(id),
  realm text NOT NULL,
  user_id text,                      -- NULL = varredura de falhas sem userId
  username text,
  email text,
  criado_ms bigint,
  habilitada boolean,
  origem text,
  via text NOT NULL,                 -- atributo | username | historico | informada | varredura
  incluida boolean NOT NULL DEFAULT true,
  UNIQUE (investigacao_id, instancia_id, realm, user_id)
);
CREATE TABLE IF NOT EXISTS tarefa (
  id bigserial PRIMARY KEY,
  investigacao_id int NOT NULL REFERENCES investigacao(id),
  conta_id int NOT NULL REFERENCES conta(id),
  inicio_ms bigint NOT NULL,
  fim_ms bigint NOT NULL,            -- exclusivo
  modo text NOT NULL,
  status text NOT NULL DEFAULT 'pendente',
  cursor_ms bigint,
  offset_n int NOT NULL DEFAULT 0,
  eventos int NOT NULL DEFAULT 0,
  tentativas int NOT NULL DEFAULT 0,
  erro text,
  releitura text,                    -- NULL | ok | divergente | expirado
  lease_ate timestamptz,
  atualizado timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS ix_tarefa_fila ON tarefa (investigacao_id, status);
CREATE TABLE IF NOT EXISTS evento (
  investigacao_id int NOT NULL,
  instancia_id int NOT NULL,
  realm text NOT NULL,
  id text NOT NULL,
  conta_id int NOT NULL,
  time_ms bigint NOT NULL,
  type text NOT NULL,
  client_id text,
  user_id text,
  session_id text,
  ip text,
  error text,
  details jsonb,
  bruto jsonb NOT NULL,
  PRIMARY KEY (investigacao_id, instancia_id, realm, id)
);
CREATE INDEX IF NOT EXISTS ix_evento_tempo ON evento (investigacao_id, time_ms);
CREATE TABLE IF NOT EXISTS requisicao (
  id bigserial PRIMARY KEY,
  investigacao_id int,
  instancia_id int NOT NULL,
  metodo text NOT NULL,
  caminho text NOT NULL,
  params jsonb,
  status int,
  inicio timestamptz NOT NULL,
  ms real NOT NULL,
  sha256 text,
  bytes int,
  coletor text NOT NULL
);
CREATE TABLE IF NOT EXISTS cobertura (
  investigacao_id int NOT NULL,
  instancia_id int NOT NULL,
  realm text NOT NULL,
  conta_id int,
  classe text NOT NULL,              -- coberto | parcial | sem_dados
  status text NOT NULL,
  detalhe text,
  acao text,
  desde_ms bigint
);
CREATE TABLE IF NOT EXISTS historico_identidade (
  alvo_hmac text NOT NULL,
  instancia_id int NOT NULL,
  realm text NOT NULL,
  user_id text NOT NULL,
  username text,
  visto_em timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (alvo_hmac, instancia_id, realm, user_id)
);
CREATE TABLE IF NOT EXISTS trilha_auditoria (
  id bigserial PRIMARY KEY,
  quando timestamptz NOT NULL DEFAULT now(),
  operador text NOT NULL,
  acao text NOT NULL,
  investigacao_id int,
  detalhe jsonb
);
CREATE OR REPLACE FUNCTION trilha_somente_insercao() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN RAISE EXCEPTION 'trilha_auditoria aceita somente inserção'; END $$;
DROP TRIGGER IF EXISTS trg_trilha_ro ON trilha_auditoria;
CREATE TRIGGER trg_trilha_ro BEFORE UPDATE OR DELETE ON trilha_auditoria
  FOR EACH ROW EXECUTE FUNCTION trilha_somente_insercao();
"""


def conectar(autocommit: bool = True) -> psycopg.Connection:
    return psycopg.connect(DSN, autocommit=autocommit, row_factory=dict_row)


def criar_esquema():
    with conectar() as cx:
        cx.execute(SCHEMA)


def trilha(cx, operador: str, acao: str, investigacao_id: int | None = None, **detalhe):
    from psycopg.types.json import Jsonb
    cx.execute("INSERT INTO trilha_auditoria (operador, acao, investigacao_id, detalhe) VALUES (%s,%s,%s,%s)",
               (operador, acao, investigacao_id, Jsonb(detalhe)))

-- Subconjunto do esquema do Keycloak (mesmos nomes de tabela e coluna que o Liquibase cria no PostgreSQL).
-- Usado pelo simulador e pelo gerador de eventos. O gerador também funciona no banco de um Keycloak real.
CREATE TABLE IF NOT EXISTS realm (
  id varchar(36) PRIMARY KEY,
  name varchar(255) UNIQUE NOT NULL,
  enabled boolean NOT NULL DEFAULT true,
  events_enabled boolean NOT NULL DEFAULT false,
  events_expiration bigint,
  admin_events_enabled boolean NOT NULL DEFAULT false,
  admin_events_details_enabled boolean NOT NULL DEFAULT false
);
CREATE TABLE IF NOT EXISTS realm_enabled_event_types (
  realm_id varchar(36) NOT NULL REFERENCES realm(id),
  value varchar(255) NOT NULL,
  PRIMARY KEY (realm_id, value)
);
CREATE TABLE IF NOT EXISTS client (
  id varchar(36) PRIMARY KEY,
  client_id varchar(255) NOT NULL,
  realm_id varchar(36) NOT NULL REFERENCES realm(id)
);
CREATE TABLE IF NOT EXISTS user_entity (
  id varchar(36) PRIMARY KEY,
  email varchar(255),
  email_verified boolean NOT NULL DEFAULT false,
  enabled boolean NOT NULL DEFAULT true,
  federation_link varchar(255),
  first_name varchar(255),
  last_name varchar(255),
  realm_id varchar(255) NOT NULL,
  username varchar(255),
  created_timestamp bigint,
  service_account_client_link varchar(255),
  UNIQUE (realm_id, username)
);
CREATE TABLE IF NOT EXISTS user_attribute (
  name varchar(255) NOT NULL,
  value varchar(255),
  user_id varchar(36) NOT NULL REFERENCES user_entity(id) ON DELETE CASCADE,
  id varchar(36) PRIMARY KEY
);
CREATE INDEX IF NOT EXISTS idx_user_attribute_name ON user_attribute (name, value);
CREATE INDEX IF NOT EXISTS idx_user_attribute ON user_attribute (user_id);

CREATE TABLE IF NOT EXISTS event_entity (
  id varchar(36) PRIMARY KEY,
  client_id varchar(255),
  details_json varchar(2550),
  error varchar(255),
  ip_address varchar(255),
  realm_id varchar(255),
  session_id varchar(255),
  event_time bigint,
  type varchar(255),
  user_id varchar(255),
  details_json_long_value text
);
-- Índice existente desde o Keycloak 9.0.1 (presente nas duas versões)
CREATE INDEX IF NOT EXISTS idx_event_time ON event_entity (realm_id, event_time);

CREATE TABLE IF NOT EXISTS admin_event_entity (
  id varchar(36) PRIMARY KEY,
  admin_event_time bigint,
  realm_id varchar(255),
  operation_type varchar(255),
  auth_realm_id varchar(255),
  auth_client_id varchar(255),
  auth_user_id varchar(255),
  ip_address varchar(255),
  resource_path varchar(2550),
  representation text,
  error varchar(255),
  resource_type varchar(64)
);
CREATE INDEX IF NOT EXISTS idx_admin_event_time ON admin_event_entity (realm_id, admin_event_time);

-- Configuração própria do simulador (não existe no Keycloak)
CREATE SCHEMA IF NOT EXISTS sim;
CREATE TABLE IF NOT EXISTS sim.service_account (
  client_id varchar(255) PRIMARY KEY,
  secret varchar(255) NOT NULL,
  realms text[] NOT NULL            -- realms em que tem as roles de leitura
);
CREATE TABLE IF NOT EXISTS sim.user_profile (
  realm_id varchar(36) PRIMARY KEY,
  config jsonb NOT NULL
);
CREATE TABLE IF NOT EXISTS sim.component (
  id varchar(36) PRIMARY KEY,
  realm_id varchar(36) NOT NULL,
  name varchar(255),
  provider_id varchar(255),
  provider_type varchar(255),
  config jsonb NOT NULL
);

-- Papéis de banco do auditor (D5). Rodar como superusuário no banco do auditor, depois de `python -m auditor init`
-- (que cria o esquema com o papel dono). Exemplo na stack local:
--
--   psql postgresql://keycloak:keycloak@localhost:5435/auditor -v senha_app="'troque-esta-senha'" -f infra/papeis.sql
--
-- Depois disso, a aplicação usa AUDITOR_DSN com kc_auditor_app; só `init` (DDL) usa o papel dono.
--
--   kc_auditor_app  sem DDL, sem TRUNCATE; na trilha_auditoria só SELECT e INSERT
--   (o trigger da trilha também recusa UPDATE, DELETE e TRUNCATE de qualquer papel que não o desative)

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'kc_auditor_app') THEN
    CREATE ROLE kc_auditor_app LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT;
  END IF;
END $$;

ALTER ROLE kc_auditor_app PASSWORD :senha_app;

REVOKE CREATE ON SCHEMA public FROM PUBLIC;
REVOKE ALL ON ALL TABLES IN SCHEMA public FROM kc_auditor_app;
GRANT CONNECT ON DATABASE auditor TO kc_auditor_app;
GRANT USAGE ON SCHEMA public TO kc_auditor_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO kc_auditor_app;
REVOKE UPDATE, DELETE, TRUNCATE ON trilha_auditoria FROM kc_auditor_app;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO kc_auditor_app;

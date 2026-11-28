-- Papéis de banco do auditor (D5). Rodar como superusuário no banco do auditor, depois de `python -m auditor init`
-- (que cria o esquema com o papel dono). Exemplo na stack local:
--
--   psql postgresql://keycloak:keycloak@localhost:5435/auditor -v senha_app="'troque-esta-senha'" \
--        [-v senha_chaveiro="'outra-senha'"] -f infra/papeis.sql
--
-- Depois disso, a aplicação usa AUDITOR_DSN com kc_auditor_app; só `init` (DDL) usa o papel dono.
--
--   kc_auditor_app  sem DDL, sem TRUNCATE; na trilha_auditoria só SELECT e INSERT
--   (o trigger da trilha também recusa UPDATE, DELETE e TRUNCATE de qualquer papel que não o desative)
--   kc_chaveiro     (modo vault, W0b) só lê estado das investigações, jobs, DEKs envolvidas e segredos cifrados;
--                   insere DEKs envolvidas e registros na trilha. Criado só quando senha_chaveiro é informada.
--   kc_api          (W3) mesmos direitos de kc_auditor_app, mas sujeito à RLS por designação em evento, conta,
--                   pseudonimo e conta_extra (migração 0011): a API define kc_auditor.sub a cada conexão.
--                   Criado só quando senha_api é informada (-v senha_api="'...'"); a API usa AUDITOR_DSN_API.

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'kc_auditor_app') THEN
    CREATE ROLE kc_auditor_app LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT;
  END IF;
END $$;

ALTER ROLE kc_auditor_app PASSWORD :senha_app;

REVOKE CREATE ON SCHEMA public FROM PUBLIC;
REVOKE ALL ON ALL TABLES IN SCHEMA public FROM kc_auditor_app;
GRANT CONNECT ON DATABASE :"DBNAME" TO kc_auditor_app;
GRANT USAGE ON SCHEMA public TO kc_auditor_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO kc_auditor_app;
REVOKE UPDATE, DELETE, TRUNCATE ON trilha_auditoria FROM kc_auditor_app;
REVOKE UPDATE, DELETE, TRUNCATE ON selo FROM kc_auditor_app;   -- selos: só inserção (W0b)
REVOKE UPDATE, DELETE, TRUNCATE ON ancora FROM kc_auditor_app; -- âncoras: só inserção (W0b)
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO kc_auditor_app;
-- tabelas e sequências criadas depois (próximos `init`) pelo papel que roda este script já nascem com as permissões
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO kc_auditor_app;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT USAGE, SELECT ON SEQUENCES TO kc_auditor_app;

\if :{?senha_chaveiro}
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'kc_chaveiro') THEN
    CREATE ROLE kc_chaveiro LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT;
  END IF;
END $$;
ALTER ROLE kc_chaveiro PASSWORD :senha_chaveiro;
REVOKE ALL ON ALL TABLES IN SCHEMA public FROM kc_chaveiro;
GRANT CONNECT ON DATABASE :"DBNAME" TO kc_chaveiro;
GRANT USAGE ON SCHEMA public TO kc_chaveiro;
GRANT SELECT (id, status, alvo_hmac, solicitante_sub) ON investigacao TO kc_chaveiro;
GRANT SELECT (investigacao_id, funcao, sub) ON designacao TO kc_chaveiro;
GRANT SELECT (investigacao_id, status) ON pacote TO kc_chaveiro;
GRANT SELECT (investigacao_id, tipo, status) ON job TO kc_chaveiro;
GRANT SELECT (id, nome, segredo_cifrado) ON instancia TO kc_chaveiro;
GRANT SELECT, INSERT ON chave_investigacao TO kc_chaveiro;
GRANT INSERT ON trilha_auditoria TO kc_chaveiro;
GRANT SELECT (cadeia, seq, hash) ON trilha_auditoria TO kc_chaveiro;   -- encadeamento (W0b)
GRANT USAGE ON SEQUENCE trilha_auditoria_id_seq TO kc_chaveiro;
\endif

\if :{?senha_assinador}
-- assinador (W5, §6.2): lê os selos e a cabeça da trilha para conferir o manifesto e registra a assinatura
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'kc_assinador') THEN
    CREATE ROLE kc_assinador LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT;
  END IF;
END $$;
ALTER ROLE kc_assinador PASSWORD :senha_assinador;
REVOKE ALL ON ALL TABLES IN SCHEMA public FROM kc_assinador;
GRANT CONNECT ON DATABASE :"DBNAME" TO kc_assinador;
GRANT USAGE ON SCHEMA public TO kc_assinador;
GRANT SELECT (investigacao_id, tarefa_id, conta_id, inicio_ms, raiz, n_eventos, versao) ON selo TO kc_assinador;
GRANT SELECT (id, trilha_publica) ON investigacao TO kc_assinador;
GRANT INSERT ON trilha_auditoria TO kc_assinador;
GRANT SELECT (cadeia, seq, hash) ON trilha_auditoria TO kc_assinador;
GRANT USAGE ON SEQUENCE trilha_auditoria_id_seq TO kc_assinador;
\endif

\if :{?senha_api}
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'kc_api') THEN
    CREATE ROLE kc_api LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS;
  END IF;
END $$;
ALTER ROLE kc_api PASSWORD :senha_api;
REVOKE ALL ON ALL TABLES IN SCHEMA public FROM kc_api;
GRANT CONNECT ON DATABASE :"DBNAME" TO kc_api;
GRANT USAGE ON SCHEMA public TO kc_api;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO kc_api;
REVOKE UPDATE, DELETE, TRUNCATE ON trilha_auditoria FROM kc_api;
REVOKE UPDATE, DELETE, TRUNCATE ON selo FROM kc_api;
REVOKE UPDATE, DELETE, TRUNCATE ON ancora FROM kc_api;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO kc_api;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO kc_api;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT USAGE, SELECT ON SEQUENCES TO kc_api;
\endif

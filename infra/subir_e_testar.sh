#!/usr/bin/env bash
# Sobe a stack real (Keycloak 26.8.2 + Keycloak 18.0.2 legado), cria usuários aleatórios, grava 1 milhão de
# eventos em cada instância, faz logins reais de conferência e roda uma investigação com exportação.
# Requisitos: Docker com Compose, Python 3.11+, ~6 GB de RAM livres.
set -euo pipefail
cd "$(dirname "$0")/.."
pip install -q -r requirements.txt

echo "== 1. stack"
docker compose -f infra/docker-compose.yml up -d
espera(){ until curl -sf "$1" >/dev/null; do sleep 5; done; echo "  pronto: $1"; }
espera http://localhost:8080/realms/master
espera http://localhost:8081/auth/realms/master

echo "== 2. pessoas aleatórias (CPF e Título válidos) e realms/usuários pela Admin API"
python tools/pessoas.py --pessoas 6000
python infra/semear.py --url http://localhost:8080 --instancia kc26
python infra/semear.py --url http://localhost:8081/auth --instancia kc18

echo "== 3. 1.000.000 de eventos em cada instância (direto na EVENT_ENTITY)"
python tools/gerar_eventos.py --dsn postgresql://keycloak:keycloak@localhost:5433/keycloak --instancia kc26 --total 1000000
python tools/gerar_eventos.py --dsn postgresql://keycloak:keycloak@localhost:5434/keycloak --instancia kc18 --total 1000000

echo "== 4. logins reais de conferência"
python infra/logins_reais.py --url http://localhost:8080 --instancia kc26 --n 200
python infra/logins_reais.py --url http://localhost:8081/auth --instancia kc18 --n 200

echo "== 5. auditor"
export AUDITOR_DSN=postgresql://keycloak:keycloak@localhost:5435/auditor
[ -f chaves.env ] || python -m auditor chave --destino chaves > chaves.env
set -a; . ./chaves.env; set +a
python -m auditor init
python -m auditor instancia-add --nome kc26 --url http://localhost:8080 --client-id kc-auditor \
  --segredo troque-este-segredo --versao 26.8.2 --realms-esperados portal-cidadao,intranet,servicos,parceiros \
  --homologacao homologacao --sonda sonda
python -m auditor instancia-add --nome rhsso --url http://localhost:8081/auth --client-id kc-auditor \
  --segredo troque-este-segredo --versao "18.0.2 legado (base RH-SSO 7.6)" --realms-esperados portal-cidadao,legado,rh \
  --homologacao homologacao --sonda sonda

ALVO=$(python -c "import json;print(json.load(open('dados/pessoas.json'))['casos']['ALVO']['cpf'])")
python -m auditor investigar --cpf "$ALVO" --de "$(date -d '-180 days' +%F)" --ate "$(date +%F)" \
  --operador auditor --justificativa "Teste da stack real" --varredura
INV=$(psql "$AUDITOR_DSN" -Atc "select max(id) from investigacao")
python -m auditor exportar --id "$INV" --saida saida
python -m auditor verificar "saida/investigacao_${INV}.zip" --chave-publica chaves/assinatura.pub.pem

echo "== 6. testes de aceite contra a stack real"
KC_DSN_kc26=postgresql://keycloak:keycloak@localhost:5433/keycloak \
KC_DSN_kc18=postgresql://keycloak:keycloak@localhost:5434/keycloak \
python tests/contagem_real.py "$INV"

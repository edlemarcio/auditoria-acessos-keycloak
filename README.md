# kc-auditor — auditoria de acessos em várias instâncias Keycloak / RH-SSO

Localiza uma pessoa por **CPF** ou **Título de Eleitor** em todos os realms visíveis de todas as instâncias
cadastradas, coleta os eventos de acesso pela Admin REST API em etapas retomáveis e entrega relatório
consolidado por janela de tempo: planilha XLSX, CSV, dashboard HTML e manifesto assinado.

Implementa a fase F1 da proposta (coletor, banco, exportação) e parte da F2 (cobertura, releitura, manifesto).
A interface web com telas e aprovações (F3) ainda não existe: hoje o uso é pela linha de comando, e o
dashboard é um HTML gerado por investigação.

## Estrutura

| Pasta | Conteúdo |
| --- | --- |
| `auditor/` | o sistema: cliente da API, sondas, descoberta, coleta, consolidação, exportação, manifesto |
| `infra/` | `docker-compose.yml` (Keycloak 26.8.2 + Keycloak 18.0.2 legado + RH-SSO opcional), `semear.py`, `subir_e_testar.sh` |
| `tools/` | gerador de pessoas aleatórias e de 1 milhão de eventos (grava direto na `EVENT_ENTITY`) |
| `simulator/` | simulador da Admin API sobre as tabelas do Keycloak (usado quando não há como subir o Keycloak) |
| `tests/` | testes de aceite (`aceite.py`) e conferência contra a stack real (`contagem_real.py`) |

## Rodar contra a stack real (Docker)

```bash
./infra/subir_e_testar.sh
```

O script sobe as duas instâncias, cria realms, usuários aleatórios e o service account somente leitura,
grava 1.000.000 de eventos em cada instância, faz 200 logins reais de conferência em cada uma, cadastra as
instâncias no auditor, roda uma investigação de 180 dias, exporta e confere a contagem id a id contra o banco.

## Uso

```bash
python -m auditor chave > chaves.env && set -a && . ./chaves.env && set +a
python -m auditor init
python -m auditor instancia-add --nome sso-prod --url https://sso.exemplo.gov.br --client-id kc-auditor \
   --segredo '***' --realms-esperados portal,intranet --homologacao homologacao --sonda sonda
python -m auditor investigar --cpf 123.456.789-09 --de 2026-06-01 --ate 2026-11-26 \
   --operador maria --justificativa "Processo 1234/2026" [--varredura] [--base-dias 30] [--conta inst:realm:userId]
python -m auditor retomar --id 7            # depois de queda ou interrupção
python -m auditor exportar --id 7 --saida saida/ [--sem-mascara]
python -m auditor verificar saida/investigacao_7.zip --chave-publica chaves/assinatura.pub.pem
```

Para instâncias legadas (Keycloak ≤ 16, RH-SSO 7.x) inclua `/auth` na URL.

## Como a coleta funciona

* **Sondas** no realm de homologação definem o modo de cada instância:
  `epoch_asc` (26.x), `epoch_desc` (sem `direction`) ou `dia` (18.x / RH-SSO: só `yyyy-MM-dd`, no fuso da JVM, medido pela sonda S6).
* **Fatias de 1 dia**, só fatias fechadas, as mais antigas primeiro (as primeiras a expirar).
* **Cursor de tempo** como checkpoint; eventos no mesmo milissegundo são lidos por consulta pontual
  (`dateFrom=dateTo=T`), porque a API ordena só por tempo, sem desempate.
* **Releitura** das fatias no modo dia, perto da expiração e de 10% das demais; separa “expirado durante a coleta” de “divergente”.
* **Orçamento de carga** por instância (padrão 2 simultâneas, 5 req/s), compartilhado entre investigações.
* Toda requisição fica registrada com o SHA-256 do corpo; o manifesto (RFC 8785) é assinado com Ed25519.

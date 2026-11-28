# kc-auditor — auditoria de acessos em várias instâncias Keycloak / RH-SSO

Localiza uma pessoa por **CPF** ou **Título de Eleitor** em todos os realms visíveis de todas as instâncias
cadastradas, coleta os eventos de acesso pela Admin REST API em etapas retomáveis e entrega relatório
consolidado por janela de tempo: planilha XLSX, CSV, dashboard HTML e manifesto assinado.

Implementa as fases F1 e F2 da proposta e a F3 (interface web) até a etapa W5: pedidos e aprovações, análise,
revelação controlada e pacotes de evidência v2 em streaming. Os pacotes são assinados por um serviço isolado
(`assinador`), têm carimbo do tempo RFC 3161 e são conferidos por um verificador offline e independente
([`verificador/`](verificador/README.md)), com especificação pública em [docs/FORMATO_PACOTE.md](docs/FORMATO_PACOTE.md).

## Estrutura

| Pasta | Conteúdo |
| --- | --- |
| `auditor/` | o sistema: cliente da API, sondas, descoberta, coleta, consolidação, exportação, manifesto |
| `infra/` | `docker-compose.yml` (Keycloak 26.8.2 + Keycloak 18.0.2 legado + RH-SSO opcional), `semear.py`, `subir_e_testar.sh` |
| `tools/` | gerador de pessoas aleatórias e de 1 milhão de eventos (grava direto na `EVENT_ENTITY`) |
| `simulator/` | simulador da Admin API sobre as tabelas do Keycloak (usado quando não há como subir o Keycloak) |
| `web/` | interface web (React + gov.br DS), servida pela API |
| `verificador/` | `kc-verificar`: verificador offline dos pacotes v2, sem banco e sem rede |
| `chaves_publicas/` | chaves públicas de assinatura publicadas (atuais e antigas) |
| `tests/` | testes de aceite de cada etapa e conferência contra a stack real |

## Rodar contra a stack real (Docker)

Guia passo a passo, com portas, credenciais de teste e opções da investigação: [docs/STACK_E_USO.md](docs/STACK_E_USO.md).

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
python -m auditor exportar --id 7 --saida saida/ [--sem-mascara]      # pacote v2 (docs/FORMATO_PACOTE.md)
kc-verificar saida/investigacao_7.zip --recalcular                  # verificador offline (verificador/README.md)
```

Para instâncias legadas (Keycloak ≤ 16, RH-SSO 7.x) inclua `/auth` na URL.

## Como a coleta funciona

* **Sondas** no realm de homologação definem o modo de cada instância:
  `epoch_asc` (26.x), `epoch_desc` (sem `direction`) ou `dia` (18.x / RH-SSO: só `yyyy-MM-dd`, no fuso da JVM, medido pela sonda S6).
* **Fatias de 1 dia**, só fatias fechadas, as mais antigas primeiro (as primeiras a expirar).
* **Cursor de tempo** como checkpoint; eventos no mesmo milissegundo são lidos por consulta pontual
  (`dateFrom=dateTo=T`), porque a API ordena só por tempo, sem desempate.
* **Releitura** das fatias no modo dia, perto da expiração e de 10% das demais; separa “expirado durante a coleta” de “divergente”.
* **Orçamento de carga** por instância (padrão 2 simultâneas, 5 req/s), compartilhado entre investigações e entre processos (controlado no banco do auditor).
* Toda requisição fica registrada com o SHA-256 do corpo. Cada evento tem compromisso com sal (folha Merkle), cada
  fatia é selada na trilha encadeada, e o manifesto (RFC 8785) é assinado com Ed25519 e carimbado (RFC 3161).

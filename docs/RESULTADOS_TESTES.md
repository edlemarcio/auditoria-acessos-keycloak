# Resultados dos testes de aceite — 26/11/2026

**Onde rodou:** ambiente de trabalho na nuvem, sem acesso aos registros de imagens (quay.io, Docker Hub,
registry.redhat.io) nem ao Maven Central. Por isso os testes rodaram contra o **simulador da Admin API**
(`simulator/`), que reproduz o comportamento do código-fonte das tags 26.8.2 e 18.0.2 sobre as tabelas do
Keycloak num PostgreSQL 16 real. A validação contra os Keycloak reais é feita com `infra/subir_e_testar.sh`.

**Volume:** 1.000.000 de eventos em cada instância (mais 60 no realm de homologação), 6.000 pessoas aleatórias
com CPF e Título válidos, 10.483 contas distribuídas em 6 realms de produção.

| Instância | Realm | Eventos | Configuração |
| --- | --- | --- | --- |
| kc26 (26.8.2) | portal-cidadao | 246.788 | tipos padrão (sem REFRESH_TOKEN) |
| kc26 | intranet | 390.433 | todos os tipos, retenção 365 dias |
| kc26 | servicos | 362.779 | retenção 90 dias |
| kc26 | parceiros | 0 | sem roles para o service account |
| rhsso (18.0.2 legado) | portal-cidadao | 531.673 | todos os tipos |
| rhsso | legado | 468.327 | sem LOGIN_ERROR gravado, LDAP com importação |
| rhsso | rh | 0 | eventos desligados |

Casos especiais: 300 falhas no **mesmo milissegundo** (kc26) e 250 (rhsso), 30 falhas com usuário inexistente
(sem userId), conta duplicada no mesmo realm, conta excluída com eventos.

## Critérios

| # | Critério | Resultado | Medida |
| --- | --- | --- | --- |
| 1 | Contagem independente (id a id contra `EVENT_ENTITY`) | OK | 5 contas + 3 varreduras, 11.567 eventos, zero faltando, zero extra; 345 s para 180 dias em 2 instâncias a 5 req/s |
| 2 | `kill -9` no meio e retomada (realm inteiro) | OK | kc26/intranet: 390.433 de 390.433 (morto com 128.877); rhsso/legado: 468.327 de 468.327 (morto com 283.975) |
| 3 | Eventos desligados | OK | rhsso/rh avaliado; sem conta do alvo → "pesquisado, sem conta" |
| 4 | Realm esperado e invisível | OK | kc26/parceiros → "esperado_invisivel", sem dados |
| 5 | Sondas e modos | OK | 26.x → `epoch_asc`; regressão de dateTo → `epoch_asc` + sem dateTo; sem direction → `epoch_desc`; 18.0.2 → `dia` com fuso −3 h e dateTo = início do dia. Todas coletaram 100% |
| 6 | Expurgo rodando a cada 15 s durante a coleta | OK | servicos: 362.779 de 362.779 |
| 7 | Planilhas | OK | 10 abas, datas nativas, abre no LibreOffice; CSV com BOM e `;` |
| 8 | Manifesto verificável por terceiro | OK | assinatura e hashes conferem; CSV alterado e evento alterado são detectados |
| 9 | Trilha de auditoria | OK | abrir, preparar, fechar, exportar e exportar sem máscara registrados; UPDATE bloqueado |
| 10 | Orçamento de carga | OK | máximo de 5 requisições em qualquer janela de 1 s, nas duas instâncias |

## Defeitos encontrados e corrigidos durante os testes

1. **Regressão do dateTo (26.2.0):** a leitura pontual do milissegundo usava `dateTo` e perdia os 300 eventos
   empatados. Agora lê a partir de T em ordem crescente e filtra T.
2. **Orçamento de carga:** o horário registrado era anterior à espera e havia intervalos de 196–200 ms por
   resolução do relógio (6 requisições em 1 s). Registro movido para depois da espera e 1% de folga no intervalo.
3. **Releitura em varredura e realm inteiro:** comparava conjuntos diferentes e marcava "divergente" sem motivo.
4. **Exportação sem máscara** sobrescrevia o HTML mascarado na pasta de saída. Agora recebe sufixo `_SEM_MASCARA`.

## Descobertas no código-fonte do Keycloak que mudaram a implementação

* No **18.0.2** (base do RH-SSO 7.6), `dateFrom`/`dateTo` só aceitam `yyyy-MM-dd`, interpretados no **fuso da JVM**,
  e `dateTo` corta na **meia-noite do dia informado** (não no fim do dia). Não existe `direction`: a ordem é sempre
  decrescente. Medido pelas sondas S1, S3, S6 e S7.
* No **26.8.2**, datas em UTC (início e fim do dia) ou epoch ms; `direction` asc/desc; ordenação só por tempo, sem
  desempate — por isso a leitura pontual do milissegundo.
* Com `enabledEventTypes` vazio, `REFRESH_TOKEN` não é gravado (não é "salvo por padrão").
* O índice `(USER_ID, TYPE, EVENT_TIME)` só existe a partir da 26.4.0; no 18.x a consulta por usuário usa o índice
  `(REALM_ID, EVENT_TIME)`, mais cara — reforça o orçamento de carga.

Dados brutos: `docs/resultados_aceite.json`.

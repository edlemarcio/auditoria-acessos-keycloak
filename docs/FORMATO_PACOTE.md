# Formato do pacote de evidências — versão 2

Especificação pública do pacote que o kc-auditor entrega para os autos (PROPOSTA_WEB §6.4 a §6.6). Com ela, um perito
da outra parte consegue reimplementar a verificação sem o código do auditor. A implementação de referência é o
verificador offline `kc-verificar` ([`verificador/`](../verificador/README.md)). Ele não usa banco nem rede e não
importa nada do auditor.

Pacotes de formato 1 (até a versão 0.7) continuam verificáveis por `python -m auditor verificar pacote.zip
--chave-publica …`.

## 1. Convenções

* **JCS**: JSON canônico da RFC 8785 (chaves ordenadas por unidade UTF-16, sem espaços, números no formato ES6), em
  UTF-8.
* **SHA-256** em hexadecimal minúsculo. `‖` é concatenação de bytes.
* **Instância**: a instância Keycloak é identificada pelo **id imutável** (`instancia` = UUID). O nome aparece só em
  `manifesto.instancias[].nome` e nos arquivos para leitura humana. Renomear uma instância não muda nenhum hash.
* **Horários**: `time_ms`/`t` em milissegundos desde 1970 (UTC), do relógio do servidor Keycloak. Janelas e regras de
  expediente usam o fuso da investigação (`manifesto.investigacao.fuso`).
* **JSONL**: um objeto JCS por linha, terminado por `\n` (LF).
* **CSV**: UTF-8 com BOM, separador `;`, fim de linha CRLF, datas `dd/mm/aaaa hh:mm:ss`.

## 2. Arquivos

O pacote é um `.zip`. O nome segue `investigacao_<N>[_sem_mascara]_v<versão>.zip`, e cada versão é imutável.

| Arquivo | Mascarado | Sem máscara | Conteúdo |
| --- | --- | --- | --- |
| `manifesto.json` | ● | ● | JCS. Todos os hashes, contagens, raízes e compromissos (§3) |
| `manifesto.sig` | ● | ● | Assinatura Ed25519 (64 bytes) dos bytes de `manifesto.json` |
| `manifesto.tsr` | ● | ● | TimeStampResp RFC 3161 sobre SHA-256(`manifesto.json`) (§8). Ausente só se `carimbo.tipo` for `ausente` |
| `lcr/*.crl` | ● | ● | LCRs (DER) da cadeia da ACT, baixadas na exportação |
| `fatias.json` | ● | ● | Todas as fatias seladas, incluídas e excluídas (§4.2) |
| `folhas.jsonl` | ● sem sais | ● com sais | Folha de cada evento das fatias incluídas (§4.1) |
| `eventos.jsonl` | — | ● | Eventos originais das contas incluídas (§5.1) |
| `eventos_pseudonimizados.jsonl` | ● | — | Eventos com campos pessoais trocados pelos pseudônimos (§5.2) |
| `requisicoes.jsonl` | ● redigido | ● original | Requisições à Admin API, com compromisso por linha (§6) |
| `pseudonimos.csv` | — | ● | `Classe;Pseudônimo;Valor`, só do alvo e das contas incluídas |
| `compromissos.json` | — | ● | Texto e sal de cada compromisso do manifesto (§3.2) |
| `contas_excluidas.json` | ● | ● | Pseudônimo, via, motivo, quem e quando. Nunca a identificação |
| `cobertura.json` | ● | ● | Linhas de cobertura por instância × realm × conta (§9.5) |
| `resultados.json` | ● | ● | Números de onde saem a planilha, os CSVs, o dashboard e o relatório (§9) |
| `trilha.jsonl` | ● | ● | Cadeia da trilha de auditoria da investigação, sem textos livres (§7.1) |
| `ancoras/<data>.json` / `.tsr` | ● | ● | Provas de inclusão da cabeça da cadeia nas âncoras diárias (§7.2) |
| `investigacao_N.xlsx`, `eventos_N.csv`, `consolidado_N.csv`, `dashboard_N.html` | ● pseudônimos | ● valores e pseudônimos lado a lado | Derivados para leitura |
| `relatorio_N.pdf` | ● | ● | Relatório técnico, PDF/A-2b (§10) |
| `documento_origem.*` | — | ● | Anexo do pedido. No mascarado, só o hash no manifesto |

Todo arquivo do pacote, exceto `manifesto.*` e `lcr/`, consta de `manifesto.arquivos` com o seu SHA-256. Arquivo a
mais ou a menos é falha.

## 3. Manifesto

### 3.1 Campos

```text
formato: 2
pacote: {nome, mascara}
investigacao: {id, alvo (mascarado), tipo, inicio_ms, fim_ms (exclusivo), fuso, granularidade, status,
               tipo_processo, execucao_anterior, parametros: {varredura, base_dias, instancias}}
compromissos: {justificativa, processo, operador}       (§3.2)
atores: {solicitante, exportado_por}                    sub OIDC, nunca texto livre
instancias: [{id (UUID), nome, url, versao_declarada, sondas}]
eventos: {total, sha256 (de eventos.jsonl, mesmo no mascarado), excluidos, pseudonimizados, detalhados}
requisicoes: {total, raiz (§6), sha256 (do requisicoes.jsonl original), sha256_redigido}
custodia: {raiz_merkle (§4.3), fatias_seladas, fatias_excluidas, eventos_selados, eventos_sem_selo, versoes_divergentes}
cobertura: {realms: [cobertos, total], tempo: [dias, dias do período], completa}
trilha: {entradas, cabeca: {seq, hash}, ancoras: [{dia, tipo, carimbo}]}
documento_origem: {sha256, tamanho} | null
carimbo: {tipo: rfc3161 | ausente}
assinatura: {key_id, algoritmo: Ed25519, impressao_digital}
arquivos: {nome: sha256}
contagens: {nome: linhas}                                CSV: linhas sem o cabeçalho
```

`gerado_em` e `exportado_por` são campos de geração: mudam de uma exportação para outra da mesma base.

### 3.2 Compromissos com sal

```text
compromisso = SHA-256(0x00 ‖ sal ‖ JCS(valor))            sal de 256 bits
```

O manifesto não leva texto livre. Justificativa, nº do processo e operador aparecem só como compromisso. O nº do
processo CNJ tem estrutura conhecida e cairia por força bruta contra um hash sem sal. O sal vai em `compromissos.json`
(sem máscara) e no relatório técnico. Os sais do manifesto e das requisições são derivados no servidor com uma
chave da investigação. Por isso duas exportações da mesma base dão os mesmos compromissos, e sem o sal não há como
testar palpites.

### 3.3 Assinatura

A assinatura Ed25519 cobre os bytes de `manifesto.json` (JCS). A chave é procurada pelo par
`key_id` + `impressao_digital` (SHA-256 da chave pública bruta de 32 bytes) na lista publicada
(`chaves_publicas/chaves.json`, versionada no repositório e embutida no verificador):

```json
{"formato": 1, "chaves": [{"key_id": "vault:kc-auditor-assinatura:v1", "algoritmo": "Ed25519",
  "impressao_digital": "…", "chave_publica": "<base64 da chave bruta>", "publicada_em": "AAAA-MM-DD",
  "revogada_em": null}]}
```

Chave revogada vale só para manifestos com carimbo do tempo anterior à data de revogação. A assinatura é do serviço
`assinador`. Antes de assinar, ele recalcula a raiz e as contagens a partir dos selos da cadeia. A assinatura atesta
integridade. A assinatura do servidor responsável vai no relatório técnico e é feita fora do auditor.

## 4. Custódia: folhas, fatias e raiz

### 4.1 Folha

```text
folha = SHA-256(0x00 ‖ sal ‖ JCS(evento como recebido))
```

* **Sal**: 256 bits aleatórios por evento, guardados cifrados no banco. No pacote mascarado o sal não vai: a folha
  não serve de oráculo para testar IPs ou CPFs.
* **Como recebido**: o evento devolvido pela Admin API, sem o campo `id_g` e, no Keycloak ≤ 21, sem o `id` sintético
  que começa com `sha256:` (o auditor o acrescenta para dar identidade ao evento).
* `folhas.jsonl`: `{"fatia", "folha"}` (mais `"sal"` no sem máscara), ordenado pela posição da fatia em `fatias.json`
  e, dentro dela, pela folha (ordem lexicográfica do hexadecimal). Só as fatias incluídas.

### 4.2 Árvore

```text
nó     = SHA-256(0x01 ‖ esquerda ‖ direita)
ímpar  = o último nó de um nível sobe sem ser duplicado
vazia  = SHA-256("")            (uma fatia sem eventos)
```

É a separação de domínio da RFC 6962. A raiz de uma fatia é a raiz das suas folhas ordenadas.
`fatias.json` é uma lista com, para cada fatia: `fatia` (id da tarefa de coleta), `conta_id`, `conta`
(pseudônimo), `instancia`, `realm`, `inicio_ms`, `fim_ms` (exclusivo), `eventos`, `raiz`, `versao` (releitura),
`origem` e `incluida`. A ordem é (conta, início, tarefa).

### 4.3 Raiz da investigação

`custodia.raiz_merkle` é a raiz das raízes de **todas** as fatias, incluídas e excluídas, na ordem de `fatias.json`.
Contas excluídas por decisão registrada saem de todos os arquivos de eventos, mas as suas fatias continuam na raiz.
O verificador mostra "N eventos de K contas excluídas por decisão registrada" e confere que nada mais foi omitido:
cada fatia excluída tem a sua conta em `contas_excluidas.json`, com quem e quando.

### 4.4 Prova de inclusão

`[["e"|"d", irmão], …]`, da folha até a raiz. `"e"` significa que o irmão fica à esquerda
(`nó = H(0x01 ‖ irmão ‖ atual)`) e `"d"` que fica à direita. O nível em que o nó sobe sem irmão não entra. As provas
de cada evento não vão no pacote, porque são deriváveis de `folhas.jsonl`. A revelação seletiva (§11) traz a prova
explícita.

## 5. Eventos

### 5.1 `eventos.jsonl` (sem máscara)

```json
{"fatia": 2047, "conta": 54, "instancia": "<UUID>", "realm": "intranet", "evento": {…evento como gravado…}}
```

A ordem é a mesma de `folhas.jsonl`, e a linha *i* corresponde à folha *i*. Só eventos de fatias seladas e de
contas incluídas. `manifesto.eventos.sha256` é o SHA-256 deste arquivo e consta também do pacote mascarado.

### 5.2 `eventos_pseudonimizados.jsonl` (mascarado)

```json
{"t": 1764000000000, "instancia": "<UUID>", "realm": "intranet", "conta_id": 54, "conta": "Conta 1",
 "tipo": "LOGIN", "cliente": "portal", "erro": null, "ip": "IP 12", "sessao": "Sessão 41", "detalhes": {…}}
```

A ordem é por (`t`, id). Todas as contas incluídas, inclusive o período de base. `ip`/`sessao` são `null` quando o
evento não tem o campo. Nos `detalhes`, valores pessoais conhecidos (usuário, e-mail, id, IP, sessão) são trocados
pelo pseudônimo, e o identificador do alvo é mascarado. **Limitação declarada:** sem os sais, os eventos
pseudonimizados não se ligam às folhas.

Pseudônimos são rótulos sequenciais por classe (`Conta N`, `IP N`, `Sessão N`), atribuídos pela ordem do primeiro
aparecimento e imutáveis depois de atribuídos. São calculados no servidor com HMAC-SHA-256 e uma chave da
investigação, e o valor não é recuperável a partir do rótulo.

## 6. Requisições

Cada linha original é `{id, instancia, metodo, caminho, params, status, inicio, ms, sha256, bytes, coletor}`. Nela,
`sha256` e `bytes` são do corpo inteiro da resposta da Admin API.

```text
compromisso = SHA-256(0x00 ‖ sal ‖ JCS(linha original))
raiz        = raiz Merkle (§4.2) dos compromissos na ordem do arquivo (id crescente)
```

* No mascarado, cada linha é redigida: `caminho` sem o userId e `params` pessoais como `[redigido]`. A linha leva o
  `compromisso` da original e **não** leva o sal.
* No sem máscara, a linha é a original com `sal` e `compromisso`.
* **Limitação declarada:** na varredura de falhas sem conta e nas buscas de usuário, a prova é o hash do corpo
  inteiro mais as linhas aproveitadas com a posição. O corpo inteiro não é retido, por minimização, e um terceiro
  não consegue verificar que as linhas pertencem ao corpo.

## 7. Trilha e âncoras

### 7.1 `trilha.jsonl`

Cada registro traz `{cadeia, seq, quando, operador (sub), acao, investigacao_id, detalhe, livres, anterior, hash}`:

```text
hash     = SHA-256(JCS(registro sem o campo hash))
anterior = hash do registro anterior; o primeiro aponta para SHA-256("kc-auditor/trilha/v1|<cadeia>")
livres   = {campo: SHA-256(0x00 ‖ sal ‖ JCS(texto))}
```

Os campos livres (justificativa, motivo, alvo) entram só pelo compromisso. Por isso o arquivo, sem texto nenhum,
recalcula a cadeia, e a cadeia continua verificável depois do expurgo. Cada fatia de `fatias.json` tem um registro
`selar_fatia` com `detalhe.tarefa`, `detalhe.versao` e `detalhe.raiz` iguais aos da fatia. A cabeça da cadeia é
`manifesto.trilha.cabeca`.

### 7.2 Âncoras diárias

Uma vez por dia (e sob demanda, antes de um pacote), as cabeças de todas as cadeias entram numa árvore (§4.2) com:

```text
folha da cabeça = SHA-256(0x00 ‖ JCS({"cadeia", "seq", "hash"}))
```

A raiz recebe carimbo RFC 3161. O `messageImprint` (SHA-256) é a própria raiz, de 32 bytes. Cada `ancoras/*.json`
traz `{dia, tipo, ate, raiz, cabeca, folha, prova, carimbo}`, e o `.tsr` correspondente vai ao lado. A cabeça
ancorada precisa estar em `trilha.jsonl` (mesmo `seq` e `hash`). Assim um terceiro prova que a cadeia existia
naquela data sem ver as cadeias de outras investigações. Âncoras anteriores à ACT têm `carimbo.tipo = "simulado"`
(Ed25519 de uma chave local). O verificador as aceita com aviso: não atestam data perante terceiros.

## 8. Carimbo do tempo

`manifesto.tsr` é uma TimeStampResp (RFC 3161) cujo `messageImprint` é SHA-256 dos bytes de `manifesto.json`. Dá para
conferir com `openssl ts -verify -data manifesto.json -in manifesto.tsr -CAfile <raiz>`. O verificador confere, sem
rede:

1. status `granted` e conteúdo TSTInfo;
2. `messageImprint` igual;
3. atributo assinado `messageDigest` igual ao resumo do TSTInfo, `signingCertificateV2` igual ao certificado da ACT
   e assinatura do SignerInfo;
4. certificado da ACT com uso estendido exclusivo e crítico `timeStamping`, válido na data do carimbo;
5. cadeia até uma AC-Raiz confiável: as da ICP-Brasil, embutidas no verificador. A raiz de homologação fica num
   diretório separado e só é aceita com `--homologacao`;
6. revogação pelas LCRs de `lcr/`, capturadas na exportação. O resultado declara **até que data** a revogação foi
   conferida (o `thisUpdate` da LCR).

## 9. Regras publicadas (`--recalcular`)

O verificador refaz os números a partir dos eventos e destas regras. Se `resultados.json.regras` divergir delas, o
pacote é recusado.

### 9.1 Categorias e filtro

| Categoria | Tipos |
| --- | --- |
| Acesso | LOGIN, IDENTITY_PROVIDER_LOGIN, LOGIN_ERROR, IDENTITY_PROVIDER_LOGIN_ERROR, LOGOUT, LOGOUT_ERROR |
| Técnico | CODE_TO_TOKEN(_ERROR), REFRESH_TOKEN(_ERROR), TOKEN_EXCHANGE(_ERROR) |
| Conta | UPDATE_PASSWORD, RESET_PASSWORD, UPDATE_TOTP, REMOVE_TOTP, UPDATE_PROFILE, UPDATE_EMAIL |
| Outro | os demais |

Os resultados usam os eventos das contas incluídas com `inicio_ms ≤ t < fim_ms` e categoria Acesso ou Conta. Logins
são LOGIN e IDENTITY_PROVIDER_LOGIN. Falhas são LOGIN_ERROR e IDENTITY_PROVIDER_LOGIN_ERROR.

### 9.2 KPIs

* `logins` e `falhas`: contagens.
* `aplicacoes`: clientes distintos (não nulos) nos logins.
* `ips`: IPs distintos (não nulos) em logins e falhas.
* `eventos`: total filtrado, que é também o número de linhas de `eventos_N.csv`.
* `primeiro_ms` e `ultimo_ms`: mínimo e máximo de `t` nos logins.

### 9.3 Consolidado por janela

A janela é o início da hora, dia, semana (segunda-feira) ou mês, em hora local sem fuso (ISO 8601). O agrupamento é
por (janela, instância, realm, cliente, tipo), com `n` (eventos) e `ips` (IPs distintos não nulos).
`consolidado_N.csv` tem as mesmas linhas, com o nome da instância.

### 9.4 Destaques

Os destaques são indícios para análise humana, não conclusão:

* **Fora do expediente**: login em sábado, domingo ou fora de [7 h, 19 h) em hora local. A lista é de
  `[t, instância, realm]`.
* **Rajada de falhas**: 5 ou mais falhas em 10 minutos (`t_j − t_i ≤ 600 000` ms) na mesma (instância, realm, conta).
  Janelas sobrepostas são unidas: uma nova janela cujo início é ≤ o fim da rajada atual a estende. O registro é
  `[instância, realm, conta, início, fim, n]`.
* **IP novo** (só com `base_dias > 0`): IP de um evento filtrado que não aparece em nenhum evento das contas
  incluídas antes de `inicio_ms`. Conta a primeira ocorrência de cada IP, e o registro é o `t` dela. Sem base, o
  campo é `null`.

### 9.5 Cobertura

* **Realms**: pares cobertos ÷ total de linhas de `cobertura.json`.
* **Tempo**: dias do período = `round((fim − início) / 1 dia)`, com mínimo de 1. Nas linhas com conta e classe
  diferente de `sem_dados`, conta-se `round((fim − max(desde_ms, início)) / 1 dia)`, menos os dias citados no
  `detalhe` em trechos `divergente: …` ou `expirado: …`.
* **Completa**: todos os pares cobertos e tempo completo.

Os números vão também para a aba Resumo da planilha e para o relatório.

## 10. Relatório técnico

`relatorio_N.pdf` é PDF/A-2b, com fontes e perfil sRGB embutidos. Ele é gerado de `resultados.json` e declara nos
metadados a palavra-chave `resultados_sha256=<SHA-256 de resultados.json>`. O verificador confere que o relatório
foi gerado do `resultados.json` daquele pacote e, com `--recalcular`, que `resultados.json` confere com os eventos.
Assim um defeito no cálculo ou um worker de pacotes comprometido não passa despercebido.

## 11. Revelação seletiva verificável

Com o pacote mascarado já entregue, revela-se depois um único evento a um juízo. A revelação é um arquivo JSON
(`python -m auditor revelar-evento`, registrado na trilha com o motivo):

```json
{"formato": 1, "investigacao": 14, "fatia": 2047, "instancia": "<UUID>", "realm": "intranet",
 "evento": {…}, "sal": "<hex>", "folha": "<hex>", "prova": [["d", "…"], …], "raiz_fatia": "<hex>"}
```

A conferência (`kc-verificar pacote.zip --revelacao arquivo.json`) segue quatro passos:

1. A folha é recalculada a partir do evento e do sal.
2. A prova leva da folha à raiz da fatia em `fatias.json`.
3. A raiz da fatia é incluída na raiz da investigação, assinada no manifesto.
4. A folha está em `folhas.jsonl`.

## 12. Força bruta: o que o pacote mascarado não permite

Nenhum hash do pacote mascarado é função só de dado pessoal: as folhas e as linhas de requisição têm sal, e o sal
não vai no pacote. O teste de aceite (`tests/pacote_v2.py`) testa contra **todo** hash do pacote mascarado os
valores reais (IPs, CPF do alvo, usernames, e-mails, userIds, sessões), a vizinhança /24 de cada IP, 20 mil CPFs
vizinhos do alvo, os eventos e as requisições sem sal, em quatro formas de hash. O resultado exigido é nenhuma
confirmação. Testar os valores reais é mais forte que varrer todo o espaço, porque a varredura só acharia esses
mesmos valores.

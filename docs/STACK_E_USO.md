# Stack de teste e uso do auditor

Guia prático para subir a stack local, abrir uma investigação e consultar os resultados.
Para a visão geral do sistema e de como a coleta funciona, veja o [README](../README.md).

> **Somente uso local.** As credenciais abaixo são da stack de teste (`infra/docker-compose.yml`) e da massa
> sintética gerada por `tools/pessoas.py`. Nunca as use em produção.

## A stack

São 5 containers Docker (projeto `kc-auditor`), mais o auditor, que roda em Python na máquina:

```
  Keycloak 26.8.2 (kc26) ─────── :8080 ──────┐      pg-kc26  :5433
  Keycloak 18 legado (kc18) ── :8081/auth ───┤      pg-kc18  :5434
                                             │ Admin REST API
                                             ▼
                          auditor (python -m auditor)
                                             │
                                             ▼
                          pg-auditor :5435 (banco do auditor)
                                             │
                                             ▼
                saida/ → zip assinado, XLSX, CSV, dashboard HTML
```

| Componente | Papel |
| --- | --- |
| `kc26` / `pg-kc26` | SSO atual (Keycloak 26.8.2), com 1 milhão de eventos gravados na `EVENT_ENTITY` |
| `kc18` / `pg-kc18` | SSO legado (Keycloak 18.0.2, base do RH-SSO 7.6), JVM em `America/Sao_Paulo`, também com 1 milhão de eventos |
| `pg-auditor` | Banco do auditor: instâncias cadastradas, investigações, tarefas de coleta (fatias de 1 dia), eventos coletados e trilha de cada requisição |
| auditor | Consulta os Keycloaks **só pela Admin API**, com o service account somente leitura `kc-auditor`. Nunca lê o banco deles |
| `saida/` | Pacote por investigação: `.zip` com manifesto assinado (Ed25519), planilha, CSV e dashboard |

O RH-SSO 7.6 oficial é opcional (`docker compose --profile rhsso up -d`, porta 8082, exige `docker login registry.redhat.io`).

### Porta 8080 ocupada

Se a 8080 já estiver em uso na máquina, publique o kc26 em outra porta com um override, sem alterar o compose:

```yaml
# override.yml (fora do repositório)
services:
  kc26:
    ports: !override ["8090:8080"]
```

```bash
docker compose -f infra/docker-compose.yml -f override.yml up -d
```

Nesse caso, use `http://localhost:8090` no lugar de `http://localhost:8080` nos comandos (`semear.py`,
`logins_reais.py`, `instancia-add`). O `infra/subir_e_testar.sh` assume a 8080.

## Subir do zero

```bash
python3 -m venv .venv && . .venv/bin/activate
./infra/subir_e_testar.sh
```

O script sobe a stack, cria realms e usuários, grava os eventos, cadastra as instâncias `kc26` e `rhsso` no auditor,
roda uma investigação de 180 dias e confere a contagem contra o banco (`tests/contagem_real.py`).

Para derrubar: `docker compose -f infra/docker-compose.yml down` (acrescente `-v` para apagar os dados).

## Abrir uma investigação

### 1. Preparar o terminal (uma vez por sessão)

```bash
cd auditoria-acessos-keycloak
. .venv/bin/activate
export AUDITOR_DSN=postgresql://keycloak:keycloak@localhost:5435/auditor
set -a; . ./chaves.env; set +a
```

O `chaves.env` (chave de cifra e caminho da chave de assinatura) é criado por `python -m auditor chave --destino chaves`
e fica fora do Git. Se as instâncias já estiverem cadastradas, não é preciso rodar `instancia-add` de novo.

### 2. Investigar

Por CPF ou por título de eleitor:

```bash
python -m auditor investigar --cpf 770.914.534-50 \
  --de 2026-09-01 --ate 2026-11-26 \
  --operador seu.nome --justificativa "Processo 1234/2026"
```

O comando procura a pessoa em todos os realms visíveis das instâncias cadastradas, coleta os eventos de cada conta
encontrada e, no fim, mostra o número da investigação.

| Opção | Efeito |
| --- | --- |
| `--titulo 653828960493` | Busca pelo título de eleitor em vez do CPF |
| `--varredura` | Também procura eventos sem `userId` que tenham o CPF como username, como tentativas de login de conta inexistente. É mais lenta |
| `--granularidade hora\|dia\|semana\|mes` | Agrupamento do relatório |
| `--instancias kc26` | Limita a busca a uma instância |
| `--conta kc26:intranet:<userId>` | Inclui uma conta que a busca não acha, por exemplo uma conta excluída |
| `--fuso America/Sao_Paulo` | Fuso usado nas janelas do relatório |
| `--base-dias 30` | Coleta também os 30 dias anteriores ao `--de` como período de base e destaca os IPs que não aparecem nesse período ("IP novo") |
| `--threads N` | Paralelismo da coleta (o orçamento de carga por instância continua valendo) |

**Com o worker** (W0a). Em vez de coletar no próprio terminal, a investigação pode ir para a fila, atendida por um
worker contínuo que serve todas as investigações em rodízio:

```bash
python -m auditor worker --threads 4 &                       # deixe rodando
python -m auditor investigar --cpf 770.914.534-50 --de 2026-09-01 --ate 2026-11-26 \
  --operador seu.nome --justificativa "Processo 1234/2026" --fila
python -m auditor pausar --id 3 --operador seu.nome           # para no próximo checkpoint, sem perder nada
python -m auditor retomar --id 3 --operador seu.nome --fila   # volta para a fila do worker
python -m auditor cancelar --id 3 --operador seu.nome --motivo "Pedido duplicado"
```

O worker prepara, coleta e fecha a investigação sozinho; o estado aparece em `investigacao.status`. Sem `--fila`,
`investigar` e `retomar` funcionam como antes, coletando no terminal pela mesma fila.

Se a coleta for interrompida, retome pelo número:

```bash
python -m auditor retomar --id 3
```

### 3. Exportar e verificar

```bash
python -m auditor exportar --id 3 --saida saida          # --sem-mascara exporta os CPFs sem máscara
python -m auditor verificar saida/investigacao_3.zip --chave-publica chaves/assinatura.pub.pem
```

Depois abra `saida/dashboard_3.html` no navegador. É um arquivo autocontido, sem servidor.

### Status da investigação

| Status | Significado |
| --- | --- |
| `na_fila` | Contas localizadas e tarefas de coleta planejadas |
| `coletando` | Coleta em andamento |
| `coletada` | Todas as tarefas terminaram; falta fechar a investigação |
| `parcial` | Ainda há tarefas pendentes (coleta interrompida ou com falha temporária); use `retomar`. O dashboard marca como PRELIMINAR |
| `concluida` | Coleta completa, sem lacunas de cobertura |
| `concluida_com_lacunas` | Coleta completa, mas parte da janela ou dos realms não tem dados (realm sem permissão, eventos desligados ou expirados, dia ainda aberto no modo `dia`) |

## Atualização para a 0.2.0 (etapa W-0)

A 0.2.0 corrige vazamentos do pacote mascarado e muda o formato das chaves. Numa base existente:

```bash
python -m auditor init          # com AUDITOR_CHAVE carregada: converte segredos e alvos para o formato v2
```

O `init` é idempotente. Na primeira vez, mostra o que converteu (`instancias`, `investigacoes`, `historico`).
Desde a W0a, o esquema é versionado com Alembic (`auditor/migracoes/`): o `init` aplica as migrações pendentes
(`upgrade head`). Bases criadas antes ficam marcadas na revisão `0001` sem nenhuma mudança de estrutura.

**Papel de banco da aplicação.** Depois do `init` com o papel dono, crie o papel sem DDL e sem permissão de alterar
a trilha, e use-o no dia a dia:

```bash
psql postgresql://keycloak:keycloak@localhost:5435/auditor -v senha_app="'troque-esta-senha'" -f infra/papeis.sql
export AUDITOR_DSN=postgresql://kc_auditor_app:troque-esta-senha@localhost:5435/auditor
```

Só o `init` precisa do papel dono.

**Teste de aceite da W-0** (pacote mascarado sem identificador, contas excluídas, snapshots, chaves, trilha):

```bash
AUDITOR_DSN=<papel dono> AUDITOR_DSN_APP=<kc_auditor_app> python tests/w0.py <investigação>
```

**Teste do orçamento de carga entre processos** (W0a): três processos com várias threads contra a mesma
instância; nenhuma janela de 1 s passa de `req_por_s` e as simultâneas não passam de `concorrencia`:

```bash
AUDITOR_DSN=<kc_auditor_app> python tests/orcamento.py kc26 3 3 12
```

**Teste da fila e do worker** (W0a): rodízio entre duas investigações, pausa, retomada com fechamento automático e
contagem id a id, e cancelamento:

```bash
AUDITOR_DSN=<kc_auditor_app> KC_DSN_kc26=... KC_DSN_kc18=... python tests/fila.py 20
```

## Chaves por investigação e modo vault (etapa W0b)

Desde a W0b cada investigação tem duas chaves de dados próprias (DEKs): a principal e a de terceiros. Elas ficam
guardadas envolvidas na tabela `chave_investigacao`, e o alvo passa a ser cifrado com a DEK principal (formato v3,
com AAD por linha). Há dois modos, escolhidos por `AUDITOR_MODO`:

| Modo | Para quê | De onde vêm as chaves |
| --- | --- | --- |
| `local` (padrão) | Desenvolvimento e teste | De `AUDITOR_CHAVE`, como antes. A DEK é envolvida por uma KEK derivada dela. Com `AUDITOR_AMBIENTE=producao`, recusa rodar |
| `vault` | Igual à produção | Do `chaveiro`, por mTLS. O processo não tem chave nenhuma. Sem `chaveiro`, falha e nunca recorre ao modo local |

No modo local, o `init` cria as DEKs das investigações antigas e recifra o alvo (idempotente).

**Subir o modo vault na stack local.** O Vault entra no perfil `vault` do compose, e o `vault_setup.py` faz o papel
do Operador do Vault. Ele inicializa o cofre, cria a KEK e as chaves de uso no Transit, as políticas, os tokens do
`chaveiro` e do `assinador`, e os certificados mTLS no PKI. Tudo vai para `chaves/vault/` e `chaves/servicos/`, fora
do git:

```bash
docker compose -f infra/docker-compose.yml --profile vault up -d vault
python infra/vault_setup.py                    # idempotente; --certificados só reemite os certificados (7 dias)
psql <dono>/auditor -v senha_app="'...'" -v senha_chaveiro="'...'" -f infra/papeis.sql   # cria kc_chaveiro
CHAVEIRO_DSN=postgresql://kc_chaveiro:...@localhost:5435/auditor python -m auditor chaveiro &   # porta 8443
export AUDITOR_MODO=vault
```

Os segredos dos service accounts são cifrados pelo Vault, então instâncias cadastradas no modo local precisam ser
recadastradas (`instancia-add`) no modo vault. O mais simples é usar um banco separado para o modo vault.

**Quem recebe o quê.** A identidade é o CN do certificado. O `worker` recebe a DEK só para coletar uma investigação
em `coletando`, ou para preparar e fechar quando o job está em execução. `pacotes` recebe para exportar, depois da
conclusão. `operador` (a CLI, até a API da W1) só cria as DEKs na abertura, calcula o HMAC do alvo e cifra segredos.
`api` é recusado até a W1, porque exige o token OIDC. Cada entrega e cada recusa vão para a trilha e para o SIEM
(`AUDITOR_SIEM`, padrão `logs/siem.jsonl`), e volume fora do padrão gera alerta. No modo vault, `investigar` e
`retomar` vão sempre para a fila do worker. A identidade padrão é `worker` para o comando `worker`, `pacotes` para
`exportar` e `operador` para o resto. `AUDITOR_IDENTIDADE` troca essa escolha.

**Teste de aceite do chaveiro** (banco próprio, `auditor_w0b`):

```bash
AUDITOR_DSN=<kc_auditor_app>/auditor_w0b CHAVEIRO_DSN=<kc_chaveiro>/auditor_w0b KC_DSN_kc26=... KC_DSN_kc18=... \
  AUDITOR_CHAVE_ED25519=chaves/assinatura.pem python tests/chaveiro.py 10
```

O teste confere que os segredos e as DEKs só ficam envolvidos pelo Vault. Também confere a recusa ao worker fora da
coleta, com trilha e alerta, e as recusas por identidade e finalidade. Verifica que conexão sem certificado ou com
certificado de outra AC não passa, que o fluxo completo pelo worker e a exportação por `pacotes` funcionam (com
contagem id a id), que o processo falha fechado e que o SIEM não traz DEK, segredo nem alvo.

### Cifra na gravação e pseudônimos (W0b, parte 2)

Tudo o que identifica alguém é gravado cifrado com a DEK da investigação: o conteúdo dos eventos, as contas
(`userId`, username, e-mail), o caminho e os parâmetros originais das requisições, as sessões e alterações
administrativas, a justificativa, as mensagens de erro e os `userId` informados com `--conta`. Em claro ficam só o
técnico (tipo, aplicação, realm, horário, erro padronizado) e os **pseudônimos**: HMAC-SHA-256 com uma chave derivada
da DEK, por investigação. Os agregados (IPs distintos, por IP, IP novo) são calculados sobre os pseudônimos. O id
sintético do Keycloak ≤ 21, que é o hash do evento inteiro, vira HMAC. O histórico de contas do alvo usa uma chave
própria (K_historico), que no modo vault só o worker usa, no preparo e só para o alvo da investigação.

O **corpo das respostas** fica cifrado inteiro nas buscas de eventos das contas do alvo. Na varredura e nas buscas
de usuário, ficam só as linhas aproveitadas, com a posição na página (`requisicao.corpo_tipo`).

**Rótulos.** No fechamento, cada conta, IP e sessão ganha um rótulo sequencial (`Conta 1`, `IP 12`, `Sessão 41`),
por ordem de aparição. Um rótulo atribuído não muda mais. O pacote mascarado (planilha, CSV, dashboard) mostra só os
rótulos, com o identificador do alvo mascarado nos textos, e tira dos eventos administrativos a conta serializada
(`representation`). O pacote sem máscara mostra os valores reais.

**Migração.** No modo local, o `init` cifra as investigações antigas, uma por transação. O critério probatório é
que `eventos.sha256` e `requisicoes.sha256`, recalculados do cifrado pelo algoritmo v1, sejam iguais aos do claro
antes da migração. Se não forem, a investigação volta como estava. Depois o `init` roda `VACUUM FULL`. Na base
local, os pacotes exportados antes da migração têm os mesmos `eventos.sha256` e `requisicoes.sha256` dos exportados
depois.

**Teste de aceite: varredura de dado pessoal.** Procura em todas as colunas do banco e nos pacotes mascarados
indicados os CPFs, títulos, e-mails, `userId` e usernames da massa de teste, e qualquer IPv4 ou IPv6. O resultado
esperado é zero:

```bash
AUDITOR_DSN=<dono> python tests/varredura_pii.py saida/investigacao_10.zip
```

Os testes que leem eventos (`contagem_real.py`, `w0.py`) decifram com a DEK. No modo vault, eles usam a identidade
`pacotes` e só funcionam com a investigação concluída.

### Compromissos com sal, selos e releitura por conteúdo (W0b, parte 3)

Na ingestão, cada evento ganha um **sal** aleatório de 256 bits, guardado dentro do cifrado, e uma **folha**:
`SHA-256(0x00 ‖ sal ‖ RFC 8785(evento como recebido))`. No Keycloak ≤ 21, "como recebido" é sem o id sintético. Sem
o sal, a folha não serve para confirmar um palpite de IP ou CPF. Ao concluir cada fatia, o coletor grava o **selo**:
a raiz Merkle das folhas da conta no intervalo, com nós `SHA-256(0x01 ‖ e ‖ d)` e o último nó subindo quando o
número é ímpar. O selo vai para a tabela `selo`, que só aceita inserção, e para a trilha.

**Releitura por conteúdo.** A releitura compara ids e também o HMAC do conteúdo. No Keycloak 26, o mesmo id com
conteúdo diferente deixa a fatia como `divergente_conteudo`. No Keycloak 18, onde o id vem do conteúdo, um evento
alterado aparece como um par "faltando" + "extra" com o mesmo horário e tipo, e a fatia fica `possivel_alteracao`.
Nos dois casos, a versão relida vai cifrada para `evento_divergente`, e o evento oficial e o selo não mudam. O fato
vai para a trilha, e a cobertura mostra "Apurar a alteração na origem".

**Na exportação**, a folha de cada evento é recalculada do evento decifrado e do sal, e a raiz de cada fatia é
recalculada das folhas. Os resultados são comparados com os selos. Folha trocada, célula cifrada trocada entre
linhas ou contagem diferente **bloqueiam o pacote**, com registro na trilha e alerta no SIEM. O pacote passa a levar
`fatias.json` (todas as fatias seladas, com raiz e contagem, conta por pseudônimo no mascarado) e, no manifesto, o
bloco `custodia`: a raiz Merkle da investigação, sobre as raízes de fatia, mais os eventos selados e as versões
divergentes.

O `init` gera folhas e selos para as investigações antigas, com selos marcados `origem='migracao'` e hashes v1
conferidos. Rode `infra/papeis.sql` de novo depois do `init`, para tirar da aplicação o UPDATE e o DELETE em `selo`.

**Teste de aceite dos selos.** Usa adulteração de verdade: troca o IP de um evento na `EVENT_ENTITY` e relê, depois
troca a folha e os cifrados no banco do auditor e tenta exportar. As trocas são desfeitas no fim.

```bash
AUDITOR_DSN=<kc_auditor_app> AUDITOR_DSN_DONO=<dono> KC_DSN_kc26=... KC_DSN_kc18=... python tests/selos.py 1 9 10
```

### Trilha encadeada e âncora diária (W0b, parte 4)

A trilha tem **uma cadeia por investigação**, mais uma global (cadeia 0) para o que não tem investigação. Cada
registro guarda o hash do anterior, e o hash cobre os campos estruturados mais o **compromisso com sal** dos campos
livres (justificativa, motivo, alvo mascarado). O texto em si não entra no hash. Ele fica cifrado para a chave
pública X25519 da investigação: qualquer serviço consegue registrar, só quem tem a DEK lê, e o expurgo da DEK destrói
os textos sem quebrar a cadeia. Os selos de fatia e as entregas e recusas do `chaveiro` entram na cadeia da
investigação.

Uma vez por dia (o worker faz sozinho, ou `python -m auditor ancorar`), as cabeças de todas as cadeias entram numa
árvore Merkle, e a raiz recebe carimbo do tempo. Até a contratação da ACT ICP-Brasil, o carimbo é **simulado**:
Ed25519 com a chave local `chaves/act_simulada.pem`, marcado `"tipo": "simulado"`. O pacote leva o `trilha.jsonl`,
com a cadeia da investigação sem textos livres, e `ancoras/<dia>.json` com a prova de inclusão da cabeça da cadeia
naquela árvore. Um terceiro consegue recalcular a cadeia e conferir a prova só com o pacote, sem ver as outras
cadeias.

```bash
python -m auditor verificar-cadeia [--id N]   # continuidade e hash de cada registro, âncoras e carimbos
```

O `init` encadeia os registros antigos, na ordem em que foram gravados. Para isso desliga o trigger da trilha dentro
da transação, o que exige o papel dono.

**Teste de aceite da cadeia.** Ele adultera a trilha como DBA (altera e apaga um registro) e depois desfaz:

```bash
AUDITOR_DSN=<kc_auditor_app> AUDITOR_DSN_DONO=<dono> KC_DSN_kc26=... KC_DSN_kc18=... python tests/cadeia.py
```

### O que a W0b deixou para depois

| Item | Situação |
| --- | --- |
| DEK de terceiros (`DEK_t`) | Criada para toda investigação. A recifragem de uma conta excluída com a `DEK_t` (e de volta, na reinclusão) entra com a tela de inclusão e exclusão de contas (W2). Hoje nada é coletado de terceiros |
| Carimbo do tempo | Simulado até a ACT (dependência externa) |
| Vault | Um nó, abertura manual. Produção: 3 nós (Raft), auto-unseal e TLS no listener. Certificados mTLS de 7 dias, reemitidos com `vault_setup.py --certificados` (sem rotação automática ainda) |
| Identidade `api` | Recusada pelo `chaveiro` até a W1 (token OIDC do usuário designado) |
| `assinador` e pacote v2 completo | W5 (`folhas.jsonl` com sais, `eventos_pseudonimizados.jsonl`, `pseudonimos.csv`, manifesto sem texto livre) |
| Papel `kc_coleta` separado | A aplicação usa um papel só. `selo`, `ancora` e trilha aceitam só inserção (trigger e permissões) |
| Pedidos ao `chaveiro` | Com o cache de 5 min, uma investigação gera poucos pedidos (no teste: 1 por finalidade e processo). A medição sob carga fica para o teste de carga da W6 |

## Acesso: realm dedicado, API e CLI de produção (etapa W1)

**Modo obrigatório.** Desde a W1 a CLI não inicia sem `AUDITOR_MODO` explícito. Os valores são `local`
(desenvolvimento e teste, como antes), `vault` (serviços: API, workers, chaveiro) e `producao` (CLI cliente da API).
No modo local, ela recusa iniciar se o banco ou alguma instância cadastrada estiver na lista de destinos de produção
(`AUDITOR_DESTINOS_PRODUCAO` ou `/etc/kc-auditor/destinos-producao`), ou num host com `AUDITOR_AMBIENTE=producao`.
A recusa vai para o SIEM. Nos exemplos anteriores deste guia, acrescente `export AUDITOR_MODO=local`.

**Realm dedicado.** O `infra/realm_auditor.py` cria o realm `auditor` no Keycloak 26 da stack com:
- MFA obrigatório por nível de autenticação: nível 1 é a senha e nível 2 é o OTP, com `acr=mfa`. O nível 2 vale
  5 min, o que dá o step-up;
- os seis perfis: solicitante, investigador, aprovador, auditor interno, administrador técnico e gestor de acesso;
- o cliente do BFF (código + PKCE) e o da CLI (device flow com PKCE), os dois com audiência para a API e o chaveiro;
- usuários de teste de cada perfil, mais o operador do Vault (sem perfil) e um usuário com papéis conflitantes.

A senha é `senha-<usuario>`, e o OTP é configurado no primeiro login.

```bash
python infra/realm_auditor.py
export AUDITOR_OIDC_EMISSOR=http://localhost:8090/realms/auditor
AUDITOR_MODO=local AUDITOR_COOKIE_SEGURO=0 python -m auditor api &      # http://localhost:8000 (docs em /api/docs)
AUDITOR_MODO=local python -m auditor worker &
```

Na web, `http://localhost:8000/auth/entrar` faz o login e cria a sessão do BFF. O cookie é `HttpOnly` e
`SameSite=Strict`, a sessão cai com 30 min sem atividade e dura no máximo 8 h, e os tokens ficam cifrados com uma
chave que só o cookie tem. Requisições que mudam estado exigem o cabeçalho `X-Requisicao: kc-auditor`.
`AUDITOR_COOKIE_SEGURO=0` só serve para testar em http.

**O que cada perfil faz** (a regra fica em `auditor/casos.py`, e a API e a CLI passam por ela):

| Perfil | Pode |
| --- | --- |
| Solicitante | Pedir, acompanhar, reenviar o pedido devolvido, cancelar o próprio pedido |
| Aprovador | Aprovar (designa o investigador), devolver, recusar, aprovar o pacote sem máscara. Nunca decide o que ele mesmo pediu, nem se designa |
| Investigador | Registrar pedido externo (ofício, com órgão, documento e fundamento). Na investigação em que foi designado: iniciar, pausar, retomar, cancelar, gerar pacote e baixar |
| Auditor interno | Ler a trilha e os metadados de todas as investigações (sem o alvo mascarado) e verificar as cadeias |
| Administrador técnico | Instâncias, sondas, orçamento de carga, saúde dos serviços |
| Gestor de acesso | Ver quem tem qual perfil (a concessão é feita no realm) |
| Operador do Vault | Nenhum acesso ao auditor |

O pacote sem máscara passa por quatro olhos: o investigador pede, informando o destino formal, e outro aprovador
aprova. O pacote é gerado pelo worker de pacotes, sem arquivos soltos, e já sai com uma âncora sob demanda. O sem
máscara expira em 24 h. O download usa um link de uso único, válido por 10 min e só para quem pediu, e cada download
registra o SHA-256. Ações sensíveis (aprovar, pedir sem máscara, baixar sem máscara, cadastrar instância, ajustar
orçamento) exigem MFA nos últimos 5 min.

**CLI de produção.** Com `AUDITOR_MODO=producao`, a CLI é só cliente da API. Ela não aceita banco, chave nem
certificado no ambiente, e os comandos de servidor não existem nela:

```bash
export AUDITOR_MODO=producao AUDITOR_API=http://localhost:8000 AUDITOR_OIDC_EMISSOR=http://localhost:8090/realms/auditor
python -m auditor login                       # endereço e código; aprove no navegador, com MFA
python -m auditor pedir --cpf ... --de ... --ate ... --justificativa "..."
python -m auditor aprovar --id 3 --investigador investigador1 --motivo "..."
python -m auditor iniciar --id 3
python -m auditor exportar --id 3 --saida d/  # pede, espera o worker e baixa
```

**No modo vault,** a API usa o certificado `api` e repassa ao chaveiro o token do usuário. O chaveiro confere a
assinatura, o MFA e a designação antes de entregar a chave (`consulta` para quem foi designado, `decisao` para o
aprovador de um pedido pendente que não é dele). Os workers rodam separados (`worker --papel coleta` e
`worker --papel pacotes`). O worker de pacotes só recebe chave de investigação com pacote pedido.

**Trilha no SIEM.** Cada registro da trilha é copiado para o SIEM, só com ação, ator, investigação, posição na
cadeia e hash.

**Teste de aceite da W1.** Ele sobe a API e os workers, e faz login de todos os perfis pela web e pela CLI. Leva
cerca de 7 min, porque inclui esperar 5 min para testar o step-up:

```bash
AUDITOR_DSN=<kc_auditor_app> KC_DSN_kc26=... KC_DSN_kc18=... python tests/acesso.py              # modo local
AUDITOR_MODO=vault AUDITOR_DSN=<app>/auditor_w0b CHAVEIRO_DSN=<kc_chaveiro>/auditor_w0b ... python tests/acesso.py
```

O teste cobre:
- a matriz de permissões pelas duas portas;
- segregação e quatro olhos;
- papéis conflitantes recusados no login;
- step-up;
- nenhuma rota sem autorização, e POST sem o cabeçalho anti-CSRF recusado;
- a CLI de produção sem credenciais;
- o modo local recusado contra destino de produção;
- a trilha no SIEM sem texto livre.

**Ficou para depois:**
- RLS no banco por designação. A W1 não lê eventos pela API; isso entra com as telas de dados (W3).
- Escalonamento ao substituto, recertificação semestral, alerta automático de mudança de papel no realm
  (`casos.alerta_papel` já existe; falta o vigia dos eventos administrativos), documento de origem anexado e telas
  (W2).

## W2 (telas)

A interface web fica em `web/` (React 19 + TypeScript + Vite, gov.br DS, tema claro e escuro). Detalhes em
[`web/README.md`](../web/README.md); contrato com o servidor em [`W2_CONTRATO.md`](W2_CONTRATO.md).

```bash
cd web && source ~/.nvm/nvm.sh && npm ci
npm run dev:dubles     # :5173 com dublês do contrato, sem servidor (perfil pelo cookie dubles_perfil)
npm run dev            # :5173 com proxy de /api e /auth para a API em :8100 (AUDITOR_API_URL=http://localhost:5173)
npm test               # Vitest
npm run e2e            # Playwright + axe (claro e escuro) e jornadas só com teclado, contra os dublês
npm run e2e:real       # login real (senha + OTP) no realm auditor até o Início e a lista; API do W1 em :8100
npm run build          # web/dist, servido pela API na mesma origem (contrato §14)
```

Telas: Início por perfil, Investigações (visões, busca, filtros, paginação, ações só de `acoes`), Nova solicitação
(assistente de 5 passos, preservação urgente, rascunho, pedido externo), Resumo com linha do tempo e Acompanhamento ao
vivo (SSE), Aprovações e tela de decisão, Pacotes, Administração, Perfis e acessos, Trilha global, "Você não tem
acesso" e os estados de tela do §7.12. Capturas (dados dos dublês) em [`capturas/w2/`](capturas/w2/).

## Acessos da stack de teste

| O quê | Endereço | Usuário | Senha |
| --- | --- | --- | --- |
| Console admin do kc26 | http://localhost:8080/admin/ | `admin` | `admin` |
| Console admin do kc18 | http://localhost:8081/auth/admin/ | `admin` | `admin` |
| Service account do auditor | realm `master` dos dois Keycloaks | `kc-auditor` | `troque-este-segredo` |
| Bancos Postgres | portas 5433 (kc26), 5434 (kc18), 5435 (auditor) | `keycloak` | `keycloak` |
| Usuários de teste | conta do usuário em `/realms/<realm>/account` | ver abaixo | `Senha@Teste1` |

Os usuários de teste com senha são os 50 primeiros de cada realm e o alvo. Os usernames vêm de
`dados/pessoas.json`, que é gerado de novo a cada execução de `tools/pessoas.py`. O alvo da investigação de
conferência fica em `casos.ALVO`:

```bash
python -c "import json;print(json.load(open('dados/pessoas.json'))['casos']['ALVO'])"
```

Cada login de um usuário de teste gera um evento novo, que aparece na próxima investigação. No kc18 (modo `dia`),
o evento só é coletado depois que o dia termina, porque o auditor só lê fatias fechadas.

## Cenários propositais da massa de teste

Ao cadastrar as instâncias, o `instancia-add` mostra alertas que são esperados:

| Instância / realm | Alerta | Motivo |
| --- | --- | --- |
| kc26 / `parceiros` | vermelho, `esperado_invisivel` | O service account não recebe roles nesse realm |
| kc18 / `rh` | vermelho, `eventos_nao_gravados` | Eventos de usuário desligados no realm |
| kc18 / `legado` | amarelo, `falhas_nao_gravadas` | `LOGIN_ERROR` não está entre os tipos gravados |

A massa também tem contas com o mesmo e-mail no realm (caso `DUPLICADA`), por isso os realms são criados com
`duplicateEmailsAllowed`.

## Diferenças entre as versões do Keycloak

| | Keycloak 26.8 | Keycloak 18 / RH-SSO 7.x |
| --- | --- | --- |
| URL | sem `/auth` | com `/auth` |
| Modo de coleta | `epoch_asc` (filtro em milissegundos) | `dia` (só `yyyy-MM-dd`, no fuso da JVM) |
| `id` do evento na API | sim | não: o auditor gera `sha256:<hash do evento>:<ocorrência>` |
| Admin API | exige no `aud` a URL do admin: o `kc-auditor` precisa do client scope `kc-admin-api` | token comum do service account |

Por causa do id sintético, o `tests/contagem_real.py` confere o legado pelo conteúdo (hora, tipo, sessão e IP)
em vez de id a id.

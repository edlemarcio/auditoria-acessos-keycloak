# Proposta — kc-auditor Web (fase F3)

| Versão | Data | Mudança |
| --- | --- | --- |
| 1 | 27/11/2026 | Primeira versão |
| 2 | 27/11/2026 | Revisão após a banca (arquitetura 6,5 · segurança 6 · privacidade 6 · UX 6 · perícia 6,5). Corrige afirmações sobre o código, acrescenta modelo de ameaças, cadeia de custódia desde a coleta, jornadas e navegação, direitos do titular e um novo cronograma |
| 3 | 27/11/2026 | Segunda rodada (arquitetura 8 · segurança 8 · privacidade 8 · UX 8,5 · perícia 8). Custódia de chaves declarada com o risco residual real e serviço de assinatura isolado; CLI de produção como cliente da API; compromissos com sal no pacote; ancoragem dos selos verificável por terceiro; inventário pós-expurgo; minimização do corpo HTTP; DEK separada para terceiros e contas excluídas; uso compartilhado; estados de tela e notificações; W0 dividido e dependências externas nos riscos. Rastreabilidade das duas rodadas no [Anexo C](#anexo-c--rastreabilidade-da-banca) |
| 4 | 27/11/2026 | Terceira rodada (arquitetura 8,5 · segurança 8,5 · privacidade 9 · UX 9 · perícia 8,5). Serviço `chaveiro` como porteiro das DEKs; verificador que recalcula os resultados derivados; classe "tentativa com o identificador do alvo"; regra de terceiros completa no pacote e nos pseudônimos; lista para ofício com fundamento (Marco Civil) e regime de transferência a ente privado; W0b com 3 semanas (26 no total) |

**Situação:** aprovada pela banca na rodada 4 (nota 9 em arquitetura, segurança, privacidade, UX e perícia), com os
ajustes menores listados em "Pendências para a etapa D", no fim do Anexo C.

**Objetivo.** Evoluir o kc-auditor de ferramenta de linha de comando para um sistema web de gestão de
investigações, com dashboard integrado e todos os dados navegáveis no navegador, **sem perder a linha de comando**
e mantendo o pacote `.zip` assinado como entrega formal. Os dados pessoais passam a ser **pseudonimizados por
padrão** em toda a interface, com **revelação controlada** para quem tem autorização.

**Sumário.** 1 Ponto de partida · 2 Premissas · 3 Modelo de ameaças · 4 Perfis e governança · 5 Proteção dos dados ·
6 Cadeia de custódia e pacotes · 7 Interface · 8 Arquitetura · 9 Segurança · 10 LGPD · 11 Entregas · 12 Riscos ·
Anexos A (wireframes), B (decisões), C (rastreabilidade)

---

## 1. Ponto de partida

### 1.1 O que é reaproveitado, e como

| Peça atual | Destino | Grau de reaproveitamento |
| --- | --- | --- |
| `sondas.py`, `identificador.py` | Núcleo | Integral |
| `kc.py` (cliente da Admin API), `descoberta.py` | Núcleo | Algoritmo integral; persistência adaptada: `_registrar` (`kc.py:144-155`) passa a cifrar caminho, parâmetros e corpo, o segredo vem de `K_segredos`, o `Orcamento` é substituído |
| `Coletor.rodar_epoch` / `rodar_dia` (`coleta.py:126-185`) | Algoritmo de leitura de uma fatia | Integral |
| `Coletor.gravar` / `reler` (`coleta.py:87-99`, `195-222`) | Gravação e releitura | Adaptados: hash de ingestão, cifra, ids como HMAC (a releitura aplica o HMAC aos ids relidos antes de comparar) e comparação de conteúdo (§6.1) |
| `coleta.executar()` e `_pegar_tarefa()` (`coleta.py:225-303`) | **Substituídos** por um despachante contínuo (§8.2). Hoje a função é bloqueante, serve uma investigação por vez e não tem pausa nem cancelamento | Reescrita da orquestração |
| `Orcamento` (`kc.py:39-83`) | **Substituído** por um limitador entre processos (§8.3). Hoje é um semáforo em memória: o limite vale só dentro de um processo | Reescrita |
| `consolidar()` (`consolidar.py:78-170`) | **Reescrito** sobre agregados e pseudônimos (§8.4). Hoje carrega todos os eventos na memória e agrega sobre IP e username em claro | Regras de negócio mantidas (categorias, rajadas, fora do expediente, IP novo); implementação nova |
| `exportar()` e `manifesto.py` | Mesma estrutura de pacote, com **conteúdo novo** (formato v2, §6.4). Geração em streaming, sem montar tudo em memória | Parcial |
| `trilha_auditoria` (trigger contra UPDATE e DELETE) | Reforçada: encadeamento por hash, sem TRUNCATE, cópia externa (§6.3) | Parcial |
| `dashboard.py` e ECharts | Referência de conteúdo para o dashboard web (paridade no §7.6) | Conteúdo, não código |
| FastAPI e Uvicorn (hoje usados só por `simulator/app.py`) | Servidor da API | Dependência |

### 1.2 Defeitos do código atual achados na avaliação

A banca encontrou problemas que existem **hoje**, independentemente da versão web. Eles serão corrigidos na etapa W-0
(§11), antes de qualquer tela:

| # | Defeito | Onde | Correção |
| --- | --- | --- | --- |
| D1 | O pacote **mascarado** leva `requisicoes.jsonl` com o CPF/Título em claro nos parâmetros de busca (`q=cpf:<dígitos>`, `username=<dígitos>`). Confirmado: 12 ocorrências no pacote da investigação de teste | `descoberta.py:85,92`, `kc.py:144-155`, `exportar.py:182-186` | No W-0: pacote mascarado com `caminho` e `params` redigidos, **sem** hash por linha (um hash de linha com CPF cai por força bruta); o manifesto guarda só o hash do arquivo inteiro. Os compromissos com sal vêm no pacote v2 (§6.4) |
| D2 | O `eventos.jsonl` e o total do manifesto incluem eventos de contas excluídas, enquanto planilha e dashboard as filtram | `exportar.py:73-74` × `consolidar.py:86` | Mesmo conjunto em todos os arquivos; contas excluídas listadas no manifesto com a justificativa |
| D3 | O manifesto inclui snapshots de realm lidos depois da criação da investigação, inclusive os de outras investigações concorrentes | `exportar.py:78-80` | Snapshot ligado à investigação |
| D4 | A mesma chave `AUDITOR_CHAVE` serve para AES dos segredos e para HMAC do alvo, e o AAD é a constante `b"kc-auditor"` | `cripto.py:30-41` | Chaves separadas por finalidade e AAD por linha (§5.3) |
| D5 | O trigger da trilha não impede TRUNCATE nem a remoção do trigger pelo dono; o DSN padrão é superusuário | `db.py:9,156-160` | Papéis de banco separados e trilha encadeada (§6.3) |
| D6 | O orçamento de carga vale por processo: CLI e outro processo em paralelo dobram a carga no Keycloak | `kc.py:39-60` (classe) e `63-83` (dicionário por processo) | Limitador entre processos (§8.3) |
| D7 | O hash dos eventos nasce na exportação, sobre o que estiver no banco: alteração entre coleta e exportação não é detectável | `exportar.py:181,198` | Hash e selo na ingestão (§6.1) |

### 1.3 Lacunas que a versão web resolve

1. Não há interface de gestão: abrir, acompanhar, revisar e exportar exige terminal.
2. O operador é um texto livre (`--operador`); não há autenticação, perfis nem aprovação.
3. O dashboard é um HTML estático por investigação, sem exploração dos eventos individuais.
4. Os dados pessoais ficam em claro no banco: além do alvo, username, e-mail, `userId`, IP, sessão, `bruto`,
   parâmetros das requisições, histórico de identidade e textos de erro (inventário completo no §5.1).

---

## 2. Premissas sobre anonimização

O pedido ("anonimizar os dados, mas permitir que o usuário visualize abertamente") combina duas coisas que,
juridicamente, são diferentes:

* **Anonimização** é o processo pelo qual o dado perde a possibilidade de associação a uma pessoa (LGPD, art. 5º, XI),
  e o resultado é o **dado anonimizado** (art. 5º, III), que deixa de ser pessoal (art. 12). É irreversível: aplicada
  aos eventos, a investigação perderia o valor probatório.
* **Pseudonimização** substitui o dado por um código que só se desfaz com informação adicional mantida em separado.
  A LGPD só a define no art. 13, § 4º (estudos em saúde pública); a definição é usada aqui **por analogia**, e o
  guia da ANPD sobre anonimização e pseudonimização é a referência de terminologia. **Dado pseudonimizado continua
  sendo dado pessoal.**

A proposta adota **pseudonimização por padrão, com revelação controlada**:

* Toda tela, gráfico e filtro funciona sobre pseudônimos estáveis dentro da investigação (`Conta 3`, `IP 12`,
  `Sessão 41`). A análise inteira (padrões, rajadas, IPs novos, aplicações) é feita sem ver dado pessoal.
* O investigador designado vê o dado real dentro da interface, informando o motivo; a revelação é registrada e
  expira (§5.5). É isso que a proposta entende por **"visualizar abertamente"**: ver tudo em claro na tela, com
  responsabilização, sem precisar exportar o pacote sem máscara.
* Para quem só precisa do resultado (o Solicitante), existe a **visão agregada**: totais, séries e cobertura, sem
  eventos individuais. Ela **não é anônima**: são dados de uma pessoa identificada, ligados a um processo
  (art. 12, § 2º), e seguem as mesmas regras de acesso, guarda e direitos do titular.
* A palavra "anonimizado" não aparece na interface para nada que seja pseudonimizado. Só é anônima a
  **estatística institucional** que sobrevive ao expurgo (§5.7), já desvinculada do alvo e do processo.

A premissa precisa ser confirmada com o gestor do sistema e com o encarregado de dados **antes do W1** (§11). O
modelo aceita configurações mais restritivas (nunca revelar) sem mudança de código.

---

## 3. Modelo de ameaças

### 3.1 Ativos

Eventos e dados pessoais coletados · identidade do alvo · chaves (KEK, DEKs, HMAC, assinatura) · pacotes emitidos ·
trilha de auditoria · credenciais dos service accounts nos Keycloaks · disponibilidade dos Keycloaks de produção.

### 3.2 Atacantes e o que a proposta garante

| Atacante | Objetivo típico | Controles | Risco residual (declarado) |
| --- | --- | --- | --- |
| **Externo**, sem conta | Ler dados, derrubar o serviço | Só acessível pela rede interna; OIDC + MFA; ASVS L2; WAF/limite de requisições; DAST no pipeline | Vulnerabilidade desconhecida no stack (mitigada por pentest e atualização) |
| **Usuário legítimo abusivo** (investigador curioso) | Ver dados de quem não investiga; revelar além do necessário | Designação por investigação; RLS no banco; cota de revelação com bloqueio; motivo obrigatório; marca d'água; alerta ao auditor interno; recertificação semestral | Ele vê o que foi autorizado a ver: a proposta registra e limita, não impede o uso indevido do que foi legitimamente revelado |
| **Solicitante ou aprovador em conluio** | Abrir investigação sem fundamento | Segregação de funções aplicada no servidor; papéis conflitantes bloqueados; nº do processo e documento de origem obrigatórios; relatórios periódicos ao encarregado | Conluio de duas pessoas autorizadas continua possível; a trilha encadeada garante a responsabilização posterior |
| **Administrador da aplicação** | Ler investigações; agir em nome de outro | Perfil sem acesso a dados; não gere perfis (§4.3); CLI de produção é cliente da API, sem credencial de banco nem de Vault (§8.7); tokens Vault só nos hosts dos serviços, com operador do Vault distinto (§4.1) | Com root no host da API ou de um worker, ele lê a memória do processo e, com ela, as DEKs desembrulhadas no momento. Mitigação: hosts separados por função, acesso privilegiado com cofre de senhas e gravação de sessão, alertas de acesso ao host, cache de DEK com TTL de 5 min |
| **DBA / acesso ao banco ou a backups** | Ler dados em massa; alterar eventos; apagar a trilha | Colunas pessoais cifradas com chaves fora do banco; AAD por linha (impede trocar células); selos de ingestão (§6.1) detectam alteração; trilha encadeada e copiada para SIEM; papéis sem DDL | Pode apagar dados (disponibilidade); não consegue alterar sem ser detectado |
| **Administrador do SSO institucional** (onde os usuários do auditor fazem login) | Conceder-se papéis; personificar um investigador | Realm dedicado ao auditor, com administradores próprios; impersonation desligada; BFF exige `acr`/`amr` de MFA; mudanças de papel geram alerta; eventos administrativos do realm monitorados | Quem administra o realm dedicado é ponto de confiança; deve ser pessoa distinta dos usuários do auditor |
| **Administrador de um Keycloak auditado** (que pode ser o próprio alvo) | Apagar ou alterar eventos antes da coleta | Fora do alcance do auditor; mitigação: coleta o quanto antes (preservação urgente, §4.4), releitura e registro do hash de cada resposta | Eventos alterados **na origem**, antes da coleta, não são detectáveis pelo auditor; o relatório declara essa limitação |
| **Comprometimento da API ou de um worker** | Ler dados; injetar eventos falsos | Envelope local (§5.3): nenhum serviço tem permissão de desembrulhar DEKs no Vault; todos pedem ao `chaveiro`, que confere serviço (mTLS), estado e designação da investigação antes de entregar a DEK e registra cada entrega no SIEM; alerta quando o volume foge do padrão; corpo HTTP guardado e releitura com comparação de conteúdo | **Declarado:** um serviço comprometido em execução lê tudo das investigações cujas DEKs desembrulhar enquanto estiver comprometido, e o worker de coleta pode gravar o que quiser na coleta em curso. Os alertas de desembrulho e a trilha limitam a janela e garantem a apuração depois |
| **Comprometimento do `chaveiro`** | Entregar DEKs a quem não deveria | Host próprio, único com `transit/decrypt` da KEK, sem acesso a dados (só às DEKs envelopadas e aos estados), mTLS com cada serviço, cada entrega no SIEM, código mínimo e revisado | Enquanto comprometido, pode entregar DEKs de qualquer investigação a quem tiver rede até ele; é o ponto de confiança das chaves, como o `assinador` é o da assinatura |
| **Comprometimento do worker de pacotes** | Emitir pacote falso assinado | O worker de pacotes **não assina**. A assinatura é feita por um serviço isolado (`assinador`, §6.2) que recebe o manifesto, recalcula sozinho a raiz Merkle a partir dos selos da trilha encadeada, confere com a do manifesto e só então chama o Vault Transit. Só o `assinador` tem a política de assinatura. Carimbo do tempo em cada manifesto | O `assinador` garante o **conjunto de eventos** (raiz, fatias, contagens), não o conteúdo dos arquivos derivados (XLSX, CSV, HTML, PDF). Os derivados são garantidos pela **reprodutibilidade**: `kc-verificar --recalcular` refaz KPIs, consolidado e destaques a partir dos eventos e compara (§6.5). Com o `assinador` comprometido, pacotes falsos podem ser assinados enquanto durar o comprometimento; cada assinatura fica na trilha e no SIEM |

### 3.3 Fronteiras de confiança

Navegador ↔ proxy (TLS) · proxy ↔ API (rede interna) · API/workers ↔ PostgreSQL (papéis distintos, TLS) ·
API/workers ↔ `chaveiro` (mTLS; único com desembrulho da KEK) · `chaveiro` e `assinador` ↔ Vault (únicos com token
de uso de chave) · worker de pacotes ↔ `assinador` (único com política de assinatura) · CLI ↔ API (mesmo controle de acesso da web; a CLI não fala com banco nem Vault) · workers ↔ Keycloaks
auditados (service account somente leitura) · auditor ↔ SIEM (envio unidirecional, sem texto livre) · auditor ↔
carimbo do tempo (ACT ICP-Brasil).

---

## 4. Perfis, jornadas e governança

### 4.1 Perfis

Os usuários entram por OIDC num **realm dedicado ao auditor**, separado dos realms auditados, com MFA obrigatório.

| Perfil | Pode | Não pode |
| --- | --- | --- |
| **Solicitante** | Pedir investigação; acompanhar o status; ver a visão agregada (§7.3) e o relatório final | Ver eventos, contas ou pseudônimos; revelar |
| **Investigador** | Executar investigações em que foi designado; explorar eventos; incluir/excluir contas com justificativa; revelar dentro da cota; gerar pacote mascarado; registrar pedido de origem externa (ofício) | Aprovar; exportar sem máscara sem aprovação; ver investigações sem designação |
| **Aprovador** | Aprovar, recusar ou devolver pedidos; designar o investigador; aprovar revelação acima da cota, revelação total e pacote sem máscara; autorizar preservação urgente | Executar ou investigar o que aprovou; ver eventos |
| **Auditor interno** (corregedoria, controle) | Ler metadados e trilha de todas as investigações; verificar a cadeia da trilha e pacotes; receber alertas | Ver dados pessoais (vê só o nº da investigação, nunca o CPF mascarado) |
| **Administrador técnico** | Cadastrar instâncias, rodar sondas, ajustar orçamento de carga, acompanhar a saúde dos serviços | Ver investigações; gerir perfis; acessar chaves |
| **Gestor de acesso** (área de segurança da informação) | Conceder e revogar perfis no realm dedicado; conduzir a recertificação | Ter qualquer outro perfil do auditor |
| **Operador do Vault** (infraestrutura de chaves) | *Unseal*, políticas, rotação, backup das chaves; token root revogado após a instalação | Ter perfil no auditor; ver dados |

O BFF recusa no login um token que traga papéis conflitantes, mesmo que o realm os tenha concedido, e regenera o id
da sessão a cada login.

### 4.2 Regras aplicadas no servidor

* **Segregação de funções**: na mesma investigação, solicitante, aprovador e investigador são pessoas diferentes.
  A designação é feita pelo aprovador e é validada pelo servidor.
* **Pedido externo** (ofício, requisição judicial): o solicitante é o **órgão de origem**, identificado pelo documento,
  que é obrigatório. Quem registra o pedido pode ser designado investigador. A segregação mínima exigida nesse caso é
  **aprovador ≠ investigador**, e o manifesto e o relatório registram essa configuração.
* **Papéis conflitantes** no mesmo usuário são bloqueados na concessão: Aprovador com Investigador é permitido em
  geral (equipes pequenas), mas nunca na mesma investigação; Gestor de acesso e Administrador técnico não acumulam
  nenhum outro papel.
* **Necessidade de conhecer**: o investigador só acessa as investigações em que foi designado. A regra vale na API e
  também no banco (RLS por designação, §8.6).
* **Quatro olhos**: revelação acima da cota, revelação total, exportação sem máscara, mudança das regras de
  revelação e expurgo antecipado precisam de aprovação de outra pessoa.
* **Substituição**: cada aprovador tem um substituto cadastrado. Pedido parado além do prazo (padrão: 1 dia útil) é
  escalonado automaticamente para o substituto e, depois, para o coordenador.

### 4.3 Governança de acesso

* Toda concessão ou revogação de papel gera alerta para o auditor interno.
* Recertificação semestral: cada coordenador confirma os papéis da equipe; o que não for confirmado é revogado.
* Relatório mensal do auditor interno ao encarregado de dados: investigações abertas, revelações, exportações sem
  máscara, alertas e exceções.

### 4.4 Jornadas principais

**Solicitante — pedir e acompanhar.** Início → "Nova solicitação" → assistente (§7.4) → envia → acompanha na tela da
investigação, que para ele mostra só o cabeçalho, a linha do tempo de estados e, ao final, a visão agregada e o
relatório. Se o pedido for **devolvido**, recebe a notificação com o motivo, corrige e reenvia; o histórico fica
visível.

**Aprovador — decidir.** Início mostra "Aguardando minha decisão" → abre o pedido → tela de decisão com escopo
(identificador mascarado, período, instâncias, opções), justificativa, nº do processo, documento de origem,
estimativa de tarefas e tempo e **expiração dos eventos mais antigos por realm** → Aprovar (designando o
investigador), Devolver para correção ou Recusar, sempre com motivo.

* **Contas do histórico** (`historico_identidade`): contas associadas ao alvo em investigações anteriores **não entram
  por padrão**. Aparecem como sugestão ("1 conta sugerida pelo histórico") que o aprovador aceita ou não, com
  registro. A existência de investigações anteriores só é mostrada se elas não forem sigilosas (atributo
  `sigilosa` da investigação, definido pelo aprovador na aprovação e alterável só por ele, com registro) ou se o aprovador
  tiver vínculo com elas; caso contrário, aparece só a conta sugerida, sem dizer de onde veio. A compatibilidade de
  finalidade desse reuso consta do RIPD.

**Aprovador — decisões secundárias.** Na mesma fila de Aprovações, com o tipo destacado:

| Pedido | O que o aprovador vê para decidir (nunca os valores) | Meta |
| --- | --- | --- |
| Revelação acima da cota | Quantidade e classe dos itens pedidos, motivo da sessão de análise, revelações já feitas pelo investigador na investigação (quantidade, classe, motivo) | ≤ 1 min |
| Revelação de dado de terceiro | Classe, quantidade, motivo específico, por que o terceiro é relevante | ≤ 1 min |
| Revelação total | Volume da investigação, motivo, histórico de revelações | ≤ 2 min |
| Pacote sem máscara | Destinatário e destino declarados (processo, nível de sigilo), fundamento do pedido externo, conteúdo do pacote (arquivos e quantidades) | ≤ 2 min |
| Lista para ofício | Quantidade de IPs, provedor de destino, motivo, **fundamento** (ordem judicial para registros de conexão — Lei 12.965/2014, art. 10, § 1º e art. 22 — ou competência legal do requisitante), aviso de itens em rede compartilhada | ≤ 1 min |

**Investigador — enquanto espera uma decisão.** A análise pseudonimizada continua normalmente; só as novas
revelações ficam bloqueadas. O cabeçalho mostra "Pedido de revelação aguardando aprovação (enviado às 14:10)" com
link para o pedido. A decisão chega pela central de notificações e por e-mail (§7.12).

**Investigador — analisar e entregar.** Início → "Minhas investigações" → investigação aprovada → Iniciar coleta →
acompanha ao vivo → ao concluir, Dashboard → clica num destaque ou num ponto do gráfico → Eventos já filtrados →
abre o detalhe → inicia uma sessão de análise (motivo) se precisar revelar → inclui/exclui contas → gera o
pacote e o relatório → baixa e junta ao processo.

**Investigador — pedido externo (ofício).** "Registrar pedido externo" → informa órgão de origem, nº do ofício e do
processo, **fundamento legal da requisição** e destinatário dos dados, e anexa o documento (cifrado; o hash vai para o
manifesto) → segue para aprovação. O aprovador confere a competência do requisitante e o fundamento. O que for
entregue e a quem fica registrado (uso compartilhado, §10.1), e o pacote sem máscara só pode ter como destino quem
requisitou com fundamento.

**Preservação urgente.** Quando algum realm tem eventos do período que expiram antes do prazo normal de aprovação,
o assistente destaca o risco e oferece "Pedir preservação urgente". Um aprovador (ou o de plantão) autoriza só a
**coleta lacrada**: os eventos são coletados e cifrados, mas nenhuma tela de dados abre até a aprovação do pedido
completo. Se o pedido for recusado, ou se não houver decisão em **5 dias úteis**, a DEK é destruída e os dados somem
(registrado na trilha, com o fundamento). Antes disso, ao fim de 3 dias úteis, o pedido é escalonado ao coordenador;
a destruição por falta de decisão só acontece se ninguém decidir em 5 dias úteis, e o prazo pode ser prorrogado uma vez
pelo coordenador, por mais 10 dias úteis, com motivo.

**Auditor interno — fiscalizar.** Entra pela "Trilha global" e por "Verificar pacote". Vê, por investigação, os
metadados (nº, estados, datas, perfis envolvidos), as revelações (quantidade, motivo, quem) e o resultado da
verificação da cadeia. Não passa por nenhuma tela de dados.

**Administrador técnico — manter.** Entra em "Administração" → instâncias, sondas, orçamento, saúde dos workers e
das filas.

---

## 5. Proteção dos dados

### 5.1 Inventário de dado pessoal

| Tabela.coluna | Conteúdo | Tratamento |
| --- | --- | --- |
| `investigacao.alvo_cifrado` | Identificador do alvo | Cifrado (DEK da investigação) |
| `investigacao.alvo_hmac` | HMAC do identificador | HMAC com chave própria (`K_alvo`), §5.4 |
| `investigacao.alvo_mascarado` | `***.914.534-**` | Mantido só para quem já pode ver a investigação; Auditor interno não vê |
| `investigacao.justificativa`, `nº processo` | Texto livre, pode conter nomes | Cifrado |
| `conta.user_id`, `username`, `email` | Identificação da conta | Cifrados + pseudônimo `Conta N` |
| `evento.user_id`, `ip`, `session_id`, `details`, `bruto`, `error` | Conteúdo do evento | Cifrados + pseudônimos de conta, IP e sessão; `type`, `client_id`, `realm`, `time_ms` em claro |
| `evento.id` (id sintético `sha256:…` do Keycloak ≤ 21) | Hash do evento inteiro, que permite confirmar um palpite | Substituído por HMAC com chave da investigação |
| `conta_extra.dados` | Sessões ativas (com IP) e eventos administrativos | Cifrado; passa a ser tabela do esquema (hoje é criada em tempo de execução) |
| `requisicao.caminho`, `params` | `users/{userId}`, `q=cpf:<dígitos>` | Cifrados; versão redigida para exibição e pacote mascarado |
| `requisicao.corpo` (novo) | Corpo HTTP da resposta | **Minimizado** (§6.1): guardado inteiro só nas respostas de eventos das contas do alvo; na varredura de falhas sem conta e nas buscas de usuário, só o hash e o tamanho do corpo inteiro e as linhas aproveitadas com sua posição. Cifrado |
| `documento_origem` (novo) | Ofício, com nomes e dados do processo | Cifrado (DEK) |
| `sessao_analise.motivo`, `revelacao` (novos) | Motivo e itens revelados (por pseudônimo, nunca o valor) | Motivo livre cifrado |
| `pseudonimo.hmac` (novo) | Dado pessoal pseudonimizado | HMAC com `K_pseudo`; morre com a DEK |
| `contestacao` (nova) | Contestação do titular (§10.3) | Cifrada |
| `usuario` (nova) | `sub`, nome e unidade dos usuários do auditor | Em claro (necessário à fiscalização), com acesso restrito |
| `historico_identidade.user_id`, `username` | Contas já associadas ao alvo em investigações anteriores | Cifrados com chave própria (`K_historico`), §5.4 |
| `cobertura.detalhe`, `tarefa.erro` | Mensagens que podem conter o identificador ou trechos de resposta | Cifrados; mensagem genérica em claro para exibição |
| `trilha_auditoria.detalhe` | Pode conter motivos e textos livres | Campos livres cifrados; ação, ator, horário e ids em claro (fiscalização) |
| Arquivos de pacote | XLSX, CSV, HTML, JSONL | Armazenamento cifrado com expurgo (§6.4); nada solto em disco |

Critério de aceite do W0b: uma varredura automática procura, em **todas** as colunas do banco e no armazenamento
de pacotes, CPF, Título, e-mail, IPv4/IPv6 e os usernames da massa de teste; resultado esperado: zero ocorrência
em claro.

### 5.2 Classes de dado na tela

| Classe | Exemplos | Exibição padrão |
| --- | --- | --- |
| Identificador do alvo | CPF, Título | Mascarado para o investigador e o aprovador; oculto para o auditor interno |
| Pessoal direto do alvo | username, e-mail, nome, `userId` | Pseudônimo da conta (`Conta 3`) |
| Quase-identificador | IP, sessão, user agent, `details` | Pseudônimo (`IP 12`). IP privado: "rede interna", sem prefixo. IP público: país, UF e operadora (ASN) de base offline, sem prefixo de rede |
| **Tentativa com o identificador do alvo** | Eventos da varredura: falhas de login sem `userId` em que o username digitado é uma variante do CPF/Título do alvo (`coleta.py:77-85`) | São parte da apuração (tentativa de uso da identidade do alvo). Mesma DEK e mesmo prazo do alvo; IP e user agent pseudonimizados como quase-identificador; entram no pacote sem máscara por padrão quando a finalidade for apurar acesso indevido |
| **Dado de terceiro** | Contas que não são do alvo, eventos de outras pessoas que aparecem por compartilhar IP ou sessão | Sempre pseudonimizado; revelação só com aprovação e motivo específico; nunca no pacote sem máscara sem decisão expressa; aviso na tela de que IP compartilhado não identifica a pessoa; cifrado com a `DEK_t`, pseudônimos derivados da `DEK_t` (não da DEK principal) e descartados no prazo de contestação (§5.7). Terceiro incluído por decisão expressa é recifrado com a DEK principal na hora da decisão |
| Técnico | realm, aplicação, tipo, erro padronizado, horário | Em claro |

O modo "realm inteiro" (coleta de todos os eventos de um realm) existe hoje só para teste de carga
(`investigar.py:82`) e **fica desabilitado em produção**.

### 5.3 Chaves

Hierarquia, com uma chave por finalidade (corrige D4):

| Chave | Uso | Onde fica | Rotação |
| --- | --- | --- | --- |
| `KEK` | Envolver as DEKs | Vault Transit (ou HSM institucional); nunca sai do Vault | Anual, por re-envolvimento das DEKs, sem recifrar eventos |
| `DEK` por investigação | AES-256-GCM das colunas pessoais do alvo | Gerada pelo Vault (`datakey`), guardada envolvida na tabela `chave_investigacao` com `key_id` e versão | Não rota; morre no expurgo |
| `DEK_t` por investigação | AES-256-GCM dos dados de terceiros e de contas excluídas | Idem | Morre no fim do prazo de contestação (§5.7), antes da DEK principal |
| `K_pseudo` por investigação | HMAC dos pseudônimos e dos ids sintéticos | Derivada da DEK por HKDF-SHA-256 (`salt` = id da investigação, `info` = `"kc-auditor/pseudo/v1/<classe>"`) | Morre com a DEK |
| `K_alvo` | HMAC do identificador do alvo (localizar investigações do mesmo alvo) | Vault Transit (HMAC) | Bienal, com recálculo |
| `K_historico` | Cifra do `historico_identidade` | Vault Transit | Anual |
| `K_segredos` | Cifra dos segredos dos service accounts | Vault Transit | Anual |
| `K_assinatura` | Ed25519 do manifesto | Vault Transit (chave não exportável); só o `assinador` tem a política | Anual; versões antigas ficam só para verificação |

* **AAD** de cada cifra = `investigacao_id | tabela | coluna | chave da linha | key_id`. Trocar uma célula cifrada
  de linha ou de investigação faz a decifração falhar.
* **Envelope local, com porteiro de chaves.** A cifra e a decifração das colunas são feitas no próprio serviço com a
  DEK desembrulhada (cifrar valor a valor no Vault custaria milhões de chamadas por investigação). A política do Vault
  é por caminho e não conhece o estado da investigação no banco, então o controle "qual serviço recebe a DEK de qual
  investigação" fica num serviço próprio, o **`chaveiro`**:
  * o `chaveiro` é o **único** com `transit/decrypt` da KEK (e `datakey` para criar DEKs); nenhum outro serviço tem
    token de uso de chave no Vault, exceto o `assinador` (só assinatura);
  * cada serviço pede a DEK ao `chaveiro` por mTLS, informando a investigação e a finalidade; o `chaveiro` lê no banco
    (papel `kc_chaveiro`, só estado, designação e DEKs envelopadas) e aplica a regra: worker de coleta só recebe DEKs de
    investigações em `coletando`/`preservação urgente`; worker de pacotes, só as de pacotes pedidos; worker de tarefas,
    só as do job em execução; API, só as de investigações com sessão de usuário designado;
  * cada entrega é registrada (serviço, investigação, finalidade) e enviada ao SIEM; um volume fora do padrão gera
    alerta;
  * critério de aceite do W0b: o worker de coleta pedindo a DEK de uma investigação fora de coleta é recusado e gera
    alerta; um serviço sem certificado válido não recebe nada;
  * DEK desembrulhada fica em memória no máximo 5 min, nunca em disco nem em log;
  * o risco residual (serviço comprometido lê as investigações que desembrulhar) está declarado no §3.2.
* Em produção, nenhuma chave fica em variável de ambiente. Só `chaveiro` e `assinador` têm token Vault de uso de
  chave; o `chaveiro` intermedeia também `K_alvo` (HMAC ao pedir), `K_historico` (em `preparar`) e `K_segredos`
  (segredo do service account antes de cada coleta), com a mesma regra de finalidade e estado. A CLI não tem token
  nenhum (§8.7). O próprio `chaveiro` não mantém cache de DEK desembrulhada; o TTL de 5 min vale para os serviços que
  a recebem.
* **API no `chaveiro`:** a API repassa o access token OIDC do usuário (audiência `chaveiro`), e o `chaveiro` valida a
  assinatura do IdP, o `sub`, o `acr` e a designação antes de entregar a DEK. Uma API comprometida só obtém DEKs de
  investigações com usuário designado autenticado naquele momento.
* **Disponibilidade:** o `chaveiro` não tem estado e roda em pelo menos duas instâncias. Se ficar indisponível, a
  coleta pausa com o cursor salvo e as telas de dados mostram "Dados temporariamente indisponíveis"; o caso entra no
  teste de carga e de restauração do W6. Os certificados mTLS são emitidos pelo Vault PKI, com validade curta e
  rotação automática, sob responsabilidade do Operador do Vault.
* Ambiente local e de teste continuam com `AUDITOR_CHAVE`, como hoje, no modo `local`, que **falha fechado** (§8.7).

### 5.4 Pseudônimos

* Tabela `pseudonimo(investigacao_id, classe, hmac, rotulo)` com unicidade por `(investigacao_id, classe, hmac)`.
  O `hmac` é o HMAC-SHA-256 **completo** (256 bits) com `K_pseudo`; o rótulo é sequencial: `Conta 1`, `IP 12`,
  `Sessão 41`. Não há truncamento, portanto não há colisão.
* **Numeração determinística e imutável.** Os rótulos são atribuídos no fechamento da coleta, por ordem do primeiro
  `time_ms` em que o item aparece (empate pelo HMAC), o que dá o mesmo resultado qualquer que seja a ordem em que os
  workers gravaram as fatias. Durante a coleta, a tela mostra "IP (numeração no fechamento)". Depois de atribuído, um
  rótulo **nunca muda**: incluir ou excluir conta e recalcular agregados não renumeram; item novo recebe o próximo
  número. Relatórios, filtros salvos e URLs que citam `Conta 3` continuam válidos.
* **Reexecução herda os rótulos.** Numa investigação vinculada (§6.7), o servidor, que tem as duas DEKs, casa os itens
  pelo valor original e reaproveita os rótulos da investigação de origem; só itens novos ganham números novos. O
  casamento é feito no servidor e o valor nunca é exposto.
* Rótulos legíveis em voz pelo leitor de tela ("IP doze").
* Pseudônimos mudam de uma investigação para outra. A ligação entre investigações do mesmo alvo existe **de
  propósito** e só por `K_alvo`/`historico_identidade` (para reencontrar contas renomeadas ou excluídas). Essa
  exceção fica restrita ao servidor; para o investigador vale a mesma condição do aprovador (§4.4): nada é mostrado
  sobre investigações sigilosas ou sem vínculo. Consta do RIPD, assim como o casamento por valor entre investigações
  vinculadas na reexecução; se a de origem for expurgada, a herança de rótulos deixa de existir.
* Limitação declarada: quem obtiver `K_pseudo` consegue inverter pseudônimos de IPv4 por força bruta (2³²). Por isso
  a chave nunca sai do servidor e morre com a DEK.
* **Busca por valor exato** ("este IP aparece?") é uma revelação implícita: exige sessão de análise ativa, conta na
  cota e vai para a trilha com o motivo. Sem sessão ativa, o campo fica habilitado e, ao buscar, abre o diálogo
  "Iniciar sessão de análise".

### 5.5 Revelação controlada

* **Sessão de análise.** Para revelar, o investigador inicia uma sessão de análise na investigação e escolhe o motivo
  numa lista ligada às finalidades da base legal (§10.1), com texto livre obrigatório para "outro". A sessão dura
  até 4 h, com aviso 5 min antes do fim e opção de prorrogar (WCAG 2.2.1), no máximo duas vezes; o teto por usuário
  é de 8 h de sessão de análise por dia. Um motivo por sessão, não por clique.
* **Escopo.** Dentro da sessão, revela-se por item (uma conta, um IP, uma sessão, um evento). O item revelado fica
  revelado até o fim da sessão. Cada revelação vai para a trilha.
* **Cota com bloqueio.** Padrão: 30 itens por sessão e 100 por investigação. Acima disso, a interface pede aprovação
  e bloqueia até a decisão. Revelação total da investigação e revelação de dado de terceiro sempre exigem aprovação.
* **Lista para ofício.** Para oficiar provedores sobre muitos IPs, o investigador pede de uma vez a revelação de uma
  lista (IP, porta quando houver, horário em UTC), aprovada em bloco; o sistema gera a tabela do ofício e registra
  cada item revelado.
* **Step-up.** Iniciar sessão de análise, aprovar e baixar sem máscara exigem autenticação recente (`max_age` de
  5 min no OIDC).
* **Expiração no servidor.** A API só devolve o valor real enquanto a revelação estiver ativa; a interface não guarda
  nada (`Cache-Control: no-store`, sem `localStorage`, nunca em URL nem em log).
* **Marca d'água** com usuário e horário nas telas com dado revelado, como dissuasão. A proposta **não** promete
  registrar captura de tela, porque o navegador não permite.
* **Celular:** revelação desabilitada em telas menores que 768 px.

### 5.6 Migração das investigações existentes

1. Novas tabelas cifradas ao lado das atuais (nada é alterado no lugar).
2. Cópia em lotes, cifrando com a DEK de cada investigação.
3. **Critério probatório:** para toda investigação já exportada, os `eventos.sha256` e `requisicoes.sha256`
   recalculados a partir das tabelas novas são iguais aos do manifesto já entregue (localizado pelo
   `sha256_manifesto` registrado na trilha). O recálculo usa **exatamente o algoritmo v1**: inclui os eventos de
   contas excluídas (como fazia antes da correção D2), `_instancia` pelo nome vigente na exportação, `params` na ordem
   de chaves do jsonb e `inicio.isoformat()` no fuso da sessão original (`exportar.py:181-184`). Qualquer diferença
   interrompe a migração daquela investigação.
4. Remoção das tabelas antigas com `DROP TABLE` e `VACUUM FULL`. As cópias em claro que restarem em WAL e backups
   somem quando os backups antigos expirarem (retenção máxima de 35 dias, §5.7); a data efetiva fica registrada.
5. As investigações migradas ganham selos de ingestão retroativos, marcados como "selados na migração" (não na
   coleta), o que o relatório declara.

### 5.7 Guarda e expurgo

* **Prazo** por tipo de processo, a partir da tabela de temporalidade do órgão. O gatilho é o arquivamento ou o
  trânsito em julgado, informado no sistema.
* **Retenção legal** (*legal hold*): enquanto houver processo em curso ou ordem judicial, o expurgo fica suspenso.
* **Aviso** 30 dias antes ao investigador e ao aprovador; o expurgo é aprovado por quatro olhos.
* **Antes de destruir**, o sistema preserva o necessário para que o pacote já entregue continue verificável por quem
  o tem nos autos: o hash e a assinatura do manifesto, a raiz Merkle, a chave pública e os carimbos do tempo. O
  manifesto completo não é preservado: ele está no pacote, em poder do processo.
* **Destruição criptográfica:** a DEK envolvida é apagada. Os backups do banco do auditor têm retenção máxima de
  35 dias; o expurgo é considerado efetivo quando o último backup que contém a DEK expira, e essa data vai para a
  trilha.
* **Dados de terceiros e de contas excluídas** ficam cifrados com a `DEK_t`, destruída 90 dias depois da **conclusão
  da análise** (o investigador marca "análise concluída", ou automaticamente 60 dias após o fim da coleta). Se houver
  retenção legal, a contagem dos 90 dias só começa quando ela é levantada. Depois da destruição, a revelação seletiva
  desses eventos deixa de ser possível (os sais morrem com a chave), o que o relatório declara. Conta reincluída depois
  disso não tem mais os eventos: é preciso reexecutar. As raízes e contagens das fatias correspondentes permanecem, para a
  cadeia de custódia continuar verificável (§6.4).

**O que permanece depois do expurgo**

| Item | Permanece? | Fundamento e prazo |
| --- | --- | --- |
| Eventos, contas, corpos HTTP, pseudônimos, documentos | Não (destruição da DEK) | — |
| `alvo_cifrado`, `alvo_hmac`, `alvo_mascarado`, nº do processo, justificativa | **Não, apagados** | Impede confirmar, com um CPF e a `K_alvo`, que a pessoa foi investigada |
| `historico_identidade` do alvo | Não, se for a última investigação do alvo | — |
| Hash e assinatura do manifesto, raiz Merkle, carimbos, chave pública | Sim | Verificação do pacote nos autos (art. 16, I); pelo prazo da trilha |
| Trilha: ação, ator, horário, UUID da investigação, hashes | Sim; campos livres já destruídos com a DEK | Responsabilização (art. 6º, X); pelo prazo da trilha |
| Estatística institucional | Sim, **agregada entre investigações** por mês e unidade, com no mínimo 5 investigações por célula e sem `investigacao_id` | Dado anonimizado (art. 12); sem prazo |
* **Trilha:** guarda pelo maior prazo entre a temporalidade das investigações e 5 anos.
* **`historico_identidade`:** expurgado quando a última investigação do alvo for expurgada.
* **Pacotes no armazenamento:** mascarados, pelo prazo da investigação; sem máscara, 24 h.

---

## 6. Cadeia de custódia e pacotes

### 6.1 Custódia desde a coleta

1. **Corpo original, minimizado.** O SHA-256 e o tamanho de toda resposta da Admin API continuam registrados, como
   hoje (`kc.py:155`). O corpo inteiro é guardado cifrado só nas respostas de eventos das contas do alvo, de onde
   qualquer evento pode ser rederivado dos bytes que o Keycloak devolveu. Na varredura de falhas sem conta (que lê
   falhas de todo o realm e filtra no auditor, `coleta.py:69-85`) e nas buscas de usuário com
   `briefRepresentation=false` (`descoberta.py:84-92`), guardam-se só as linhas aproveitadas, com a posição na página,
   e os campos usados da conta. A prova desses casos é o hash do corpo inteiro mais as linhas com posição; o corpo
   inteiro não é retido, por minimização (decisão levada ao RIPD).
2. **Hash do evento na ingestão.** Em `Coletor.gravar`, antes de cifrar, calcula-se o compromisso do evento (§6.4)
   sobre `RFC 8785(evento como recebido)`. No Keycloak ≤ 21, "como recebido" é **sem** o id sintético que o auditor
   acrescenta em `kc.py:166-176`.
3. **Selo da fatia.** Ao concluir uma tarefa, calcula-se a raiz Merkle dos compromissos da fatia e grava-se o selo na
   cadeia da investigação (§6.3). Fatia pausada ou não concluída não é selada e não é exportável.
4. **Releitura compara conteúdo.** Hoje a releitura compara conjuntos de ids e a gravação usa `ON CONFLICT DO NOTHING`
   (`coleta.py:95`, `205-221`): um evento relido com o mesmo id e conteúdo diferente seria descartado em silêncio. Na
   v2, em conflito, compara-se o hash de ingestão; se divergir, as duas versões são guardadas, a fatia é marcada
   "divergente (conteúdo)", o fato vai para a trilha, para o painel "Saúde da prova" e para o relatório. É o único
   sinal de alteração na origem que o auditor consegue captar (entre duas leituras). No Keycloak ≤ 21, onde o id é
   derivado do conteúdo, um evento alterado aparece como par "faltando" + "extra"; a releitura casa esses pares por
   `time_ms`, tipo e conta e marca "possível alteração" em vez de classificá-los como expirados.
5. **Conferência na exportação.** O exportador recalcula os compromissos a partir dos dados decifrados e compara com
   os selos. Divergência bloqueia a exportação e alerta o auditor interno.
6. O manifesto traz a raiz Merkle da investigação, calculada sobre **todas** as raízes de fatia seladas (§6.4).

### 6.2 Assinatura e data

* O manifesto é assinado pela `K_assinatura` no Vault Transit, com `key_id` e impressão digital no próprio manifesto.
* **Serviço de assinatura isolado (`assinador`).** O Vault Transit assina o que receber de um token autorizado; ele
  não sabe o que é um selo. Por isso, o controle fica num serviço pequeno, em host próprio, único com a política de
  assinatura: recebe o manifesto do worker de pacotes, lê os selos da cadeia da investigação, recalcula a raiz e as
  contagens, confere com o manifesto, registra o pedido na trilha e só então chama o Transit. Pedido que não confere é
  recusado e gera alerta.
* As chaves públicas, atuais e antigas, são publicadas num endereço institucional e no repositório do projeto,
  versionadas. Revogação por publicação com data.
* **Carimbo do tempo** RFC 3161 de uma ACT credenciada na ICP-Brasil sobre o hash do manifesto. A data da prova passa
  a ser atestada por terceiro, e não só declarada pelo sistema.
* A assinatura do sistema atesta a integridade. A **assinatura do servidor responsável** (ICP-Brasil ou no processo
  eletrônico) vai no relatório técnico (§6.6) e é feita fora do auditor.

### 6.3 Trilha de auditoria

* **Uma cadeia por investigação** (cada registro guarda o hash do anterior da mesma investigação), mais uma cadeia
  global para os eventos sem investigação (logins, concessões de papel).
* **Âncora diária verificável por terceiro.** Uma vez por dia, as cabeças de todas as cadeias entram numa árvore Merkle
  (separação de domínio como na RFC 6962), e a raiz dessa árvore recebe carimbo do tempo RFC 3161. O pacote leva, para
  cada dia em que a investigação teve selos, a **prova de inclusão** da cabeça da sua cadeia naquela árvore e o `.tsr`
  do dia. Assim um terceiro prova que o selo de uma fatia existia na data da coleta, sem ver as cadeias de outras
  investigações, que são sigilosas.
* O hash de cada registro da cadeia cobre os campos estruturados e o **compromisso com sal** dos campos livres (não o
  texto nem o cifrado), para que `trilha.jsonl` sem textos livres permita recalcular a cadeia e a cadeia continue
  verificável depois que o expurgo destrói os campos livres.
* O ator é o `sub` OIDC (e o nome no momento da ação), nunca texto livre.
* Papéis de banco: só o papel de migração tem DDL; só `kc_coleta` insere em `selo`; a aplicação não tem TRUNCATE, DELETE nem UPDATE na trilha nem
  pode desligar o trigger.
* **Cópia para o SIEM** institucional (syslog TLS), fora do controle do administrador da aplicação, com **só** ação,
  ator, horário, UUID da investigação, ids e hashes. Texto livre e identificadores nunca saem do banco. Retenção no
  SIEM igual ao prazo da trilha.
* O auditor interno tem um botão "Verificar cadeia", que confere a cadeia inteira e os carimbos.
* O manifesto de cada pacote leva as entradas da trilha daquela investigação: pedido, aprovação, designação,
  sessões de análise, revelações (sem os valores), inclusões e exclusões de contas e exportações.

### 6.4 Pacote v2

A estrutura (`.zip` com arquivos, `manifesto.json` e `manifesto.sig`) e a verificação continuam. O **conteúdo muda**,
com campo `formato: 2` no manifesto. Pacotes v1 já emitidos continuam verificáveis pelo verificador v1.

| Arquivo | Pacote mascarado | Pacote sem máscara |
| --- | --- | --- |
| `investigacao_N.xlsx`, CSVs, `dashboard_N.html` | Com pseudônimos (os mesmos da tela) | Valores reais e pseudônimos lado a lado, **só para o alvo e para terceiros com decisão expressa de inclusão**; os demais terceiros continuam pseudonimizados |
| `eventos.jsonl` | — | Eventos originais, RFC 8785, do alvo, das tentativas com o identificador e dos terceiros incluídos; os demais terceiros ficam de fora, com as fatias listadas em `fatias.json` |
| `eventos_pseudonimizados.jsonl` | Eventos com campos pessoais trocados pelos pseudônimos | — |
| `folhas.jsonl` | Compromisso de cada evento e a prova de inclusão, **sem os sais** | Compromissos, provas **e sais** |
| `requisicoes.jsonl` | `caminho` e `params` redigidos; compromisso **com sal** da linha original, sem levar o sal | Original, com os sais |
| `pseudonimos.csv` | — | Pseudônimo → valor, só do alvo e dos terceiros incluídos |
| `contas_excluidas.json` | Pseudônimo, via, motivo, quem e quando | Idem (**sem** identificação: são pessoas que o investigador concluiu não serem o alvo) |
| `fatias.json` | Todas as raízes de fatia seladas, incluídas e excluídas, com a contagem de eventos de cada uma | Idem |
| `ancoras/` | Provas de inclusão das cabeças da cadeia nas árvores diárias e os `.tsr` diários (§6.3) | Idem |
| `trilha.jsonl` | Entradas da cadeia da investigação, sem textos livres | Idem |
| `relatorio_N.pdf` | Relatório técnico (§6.6), mascarado | Idem, sem máscara |
| `documento_origem.*` | — (só o hash no manifesto) | Anexo do pedido |
| `manifesto.json` / `.sig` / `.tsr` | Manifesto, assinatura e carimbo do tempo | Idem |

* **Compromissos com sal.** Cada folha é `SHA-256(0x00 ‖ sal ‖ RFC 8785(evento))`, com sal aleatório de 256 bits por
  evento, e cada linha de requisição tem o seu próprio compromisso. Os sais ficam cifrados no banco. Sem o sal, a folha
  não serve de oráculo: testar os 2³² IPv4 ou os ~10⁹ CPFs válidos contra ela não leva a nada. Os nós internos usam o
  prefixo `0x01`, e número ímpar de nós promove o último sem duplicar (RFC 6962).
* **Revelação seletiva verificável:** com o pacote mascarado em mãos, revelar depois um único evento a um juízo é
  entregar o evento e o seu sal; com a folha e a prova de inclusão, prova-se que ele pertence ao conjunto assinado.
* **Contas excluídas** saem de todos os arquivos de eventos de forma consistente (corrige D2), mas **não quebram o elo
  com a coleta**: `fatias.json` lista todas as raízes seladas, marcando as excluídas e a contagem de cada uma; a raiz
  da investigação é calculada sobre todas e é igual à selada na trilha. O verificador mostra "N eventos de K contas
  excluídas por decisão registrada" e confere que nada mais foi omitido.
* **Critério de aceite do W5:** um teste tenta, sobre o pacote mascarado, a força bruta de IPv4 e de CPF contra as
  folhas e as linhas de requisição. Resultado esperado: nenhuma confirmação.
* **Manifesto v2 sem texto livre:** justificativa, nº do processo e operador aparecem no manifesto só como compromisso
  com sal (o nº do processo CNJ tem estrutura conhecida e cairia por força bruta com hash simples); o sal vai no
  relatório e no pacote sem máscara. O ator é o `sub` OIDC.
* **Geração em streaming**, lendo por cursor e escrevendo direto no zip, com memória limitada (meta: até 500 mil
  eventos com menos de 1 GB de memória no worker).
* **Armazenamento:** volume cifrado ou objeto compatível com S3 com cifra no servidor, em área exclusiva do worker
  de pacotes. Nada é gravado solto em disco (hoje `exportar.py:213-217` grava XLSX e HTML soltos).
* **Download:** link de uso único válido por 10 min, amarrado à sessão e ao `sub` de quem pediu; cada download registra quem, quando e o SHA-256 do arquivo
  entregue. O pacote sem máscara fica disponível por 24 h, com destino formal declarado (juntada ao processo
  eletrônico com nível de sigilo).
* **Equivalência local × produção** (critério de aceite do W5; em produção a CLI só baixa o pacote do worker): a mesma
  base exportada pelo exportador do modo local e pelo worker de pacotes tem a
  mesma raiz Merkle, os mesmos `eventos.sha256`, `requisicoes.sha256` e `fatias.json`, e os arquivos derivados (XLSX,
  CSV, HTML, PDF) com o mesmo conteúdo depois de normalizados os campos de geração (`gerado_em`, `exportado_por`,
  "Exportado em", carimbo e assinatura).

### 6.5 Verificação independente

* **Especificação pública do formato** (`docs/FORMATO_PACOTE.md`): versão, canonicalização, algoritmo de cada hash,
  ordenação, construção da árvore Merkle, campos `_instancia`/`_realm` (que passam a usar o id imutável da instância,
  e não o nome, para que renomear não mude hashes), carimbo do tempo. Um perito da outra parte consegue reimplementar
  a verificação.
* **Verificador offline** `kc-verificar`: um pacote Python pequeno, sem banco e sem rede, publicado com o código. Usa
  `cryptography`, `rfc8785` e `asn1crypto` (validação do RFC 3161, que a `cryptography` não faz), todas fixadas por
  hash. Traz as AC-Raiz da ICP-Brasil e, para revogação sem rede, usa as LCRs que o exportador capturou e incluiu no
  pacote na hora da exportação (o relatório declara essa data). Confere assinatura, carimbos, hashes de todos os
  arquivos, folhas, provas de inclusão, `fatias.json` e âncoras diárias. Declara no resultado até que data a revogação
  foi conferida (data das LCRs embutidas).
* **`kc-verificar --recalcular`:** refaz, a partir dos eventos e das regras publicadas na especificação (categorias,
  janelas, rajadas, fora do expediente, IP novo), os KPIs, o consolidado por janela e os destaques, e compara com CSV,
  XLSX e relatório. No pacote sem máscara usa `eventos.jsonl` e confere cada evento pseudonimizado contra o original
  por `pseudonimos.csv`; no mascarado usa `eventos_pseudonimizados.jsonl` (contagens, IPs distintos por pseudônimo e
  destaques são calculáveis sem dado real). Critério de aceite do W5: o verificador recalcula e confere o relatório.
  Assim um defeito na reescrita de `consolidar()` ou um worker de pacotes comprometido não passa despercebido.
* **Limitações declaradas na nota metodológica:** no pacote mascarado, os eventos pseudonimizados não se ligam às
  folhas sem os sais; na varredura e nas buscas de usuário, a prova é o hash do corpo inteiro mais as linhas com
  posição, e um terceiro não consegue verificar que as linhas pertencem ao corpo.
* **Verificação na web:** usa só as chaves públicas institucionais publicadas, sem aceitar chave enviada pelo
  usuário. O upload tem limite de 2 GB e de taxa de compressão (proteção contra *zip bomb*), e a verificação roda em
  streaming num worker, não no processo da API. O resultado aparece em
  linguagem simples ("Pacote íntegro, assinado pela chave do auditor de 2026, carimbado em 27/11/2026 14:02"), com o
  detalhe técnico recolhível.

### 6.6 Relatório técnico para os autos

Gerado a partir do pacote, em PDF/A-2b, pronto para assinatura do servidor responsável:

1. Objeto: nº da investigação, do processo e do ofício de origem; solicitante, aprovador e investigador.
2. Metodologia: instâncias, versões, modo de coleta medido pelas sondas, fuso, fatias, releituras.
3. **Cobertura e limitações em destaque**, antes dos resultados: realms sem dados, retenção, eventos expirados,
   limitação de eventos alterados na origem (§3.2).
4. Resultados: totais, série, destaques (fora do expediente, rajadas, IPs novos), contas consideradas e excluídas.
   Os destaques são **indícios para análise humana**, calculados por regra automática, e não conclusão (art. 20); o
   relatório descreve os critérios de cada um.
5. Integridade: SHA-256 do pacote e do manifesto, `key_id`, carimbos do tempo, raiz Merkle, fatias excluídas.
6. Cadeia de custódia: quem coletou, revelou, exportou e baixou, com datas; configuração de segregação (inclusive
   pedido externo com aprovador ≠ investigador).
7. Nota metodológica: o que são os pseudônimos e como pedir a revelação seletiva verificável de um evento.

O **Solicitante** recebe um relatório diferente, o **relatório agregado**: estado, cobertura, totais e série por dia e
por aplicação, sem pseudônimos, IPs, contas ou destaques individuais. É ele que aparece na aba Pacotes para esse
perfil.

### 6.7 Reexecução e complementação

* Reexecutar ou ampliar o período gera **nova investigação vinculada** (`execucao_anterior`, já no esquema,
  `db.py:60`). A original nunca é alterada.
* Mudou o escopo (alvo, período maior, instâncias novas)? O pedido volta para aprovação. Mesmo escopo (repetir para
  confirmar)? Basta registro com motivo.
* Pacotes são imutáveis e versionados (`investigacao_12_v1`, `_v2`), cada um com seu manifesto.
* Tela **Comparar execuções**: eventos novos, eventos que deixaram de existir na origem (expirados ou apagados),
  eventos com conteúdo diferente, contas novas ou excluídas, mudança de cobertura. Os eventos são casados no servidor
  pelo id original (ou, no Keycloak ≤ 21, pelo conteúdo sem o id sintético), e os rótulos são herdados da execução de
  origem (§5.4), então `IP 12` é o mesmo IP nas duas colunas.

---

## 7. A interface

Aplicação de página única, em português, com **WCAG 2.2 AA e eMAG 3.1** como meta contínua, tema claro e escuro, e
componentes do Padrão Digital de Governo (gov.br DS) estendidos onde ele não cobre (tabela de dados densa, gráficos,
tema escuro — extensões documentadas no próprio repositório de design do projeto).

### 7.1 Navegação

**Navegação global** (barra lateral recolhível), filtrada por perfil:

| Item | Solicitante | Investigador | Aprovador | Auditor interno | Adm. técnico | Gestor de acesso |
| --- | --- | --- | --- | --- | --- | --- |
| Início | ● | ● | ● | ● | ● | ● |
| Investigações | ● (as suas) | ● (designadas) | ● (as que decidiu ou aguardam) | ● (metadados) | — | — |
| Aprovações | — | — | ● | — | — | — |
| Verificar pacote | ● | ● | ● | ● | — | — |
| Trilha global | — | — | — | ● | — | — |
| Administração | — | — | — | — | ● | — |
| Perfis e acessos | — | — | — | — | — | ● |

O Operador do Vault não tem acesso ao auditor (atua só no Vault). Itens sem permissão **não aparecem**. Link para uma investigação sem permissão leva a uma página "Você não tem acesso
a esta investigação" com o botão "Pedir acesso ao aprovador" (o pedido vai para a trilha); a página não revela se a
investigação existe para quem não tem nenhum vínculo.

**Navegação contextual da investigação** (abas), filtrada por perfil:

`Resumo` · `Dashboard` · `Eventos` · `Contas` · `Cobertura` · `Pacotes` · `Trilha` (· `Comparar`, se houver
reexecução)

O Solicitante vê `Resumo` (estado e visão agregada) e `Pacotes` (só o relatório agregado, §6.6). O Auditor interno vê
`Resumo` (metadados), `Pacotes` (verificar) e `Trilha`.

**Cabeçalho fixo da investigação:** nº, identificador mascarado (oculto para o auditor interno), período e fuso,
estado (rótulo, ícone e texto), **selo de cobertura** ("Cobertura parcial: 4 de 7 realms, 90 de 181 dias — ver
detalhes") e, quando houver, "Sessão de análise ativa até 15:42 · Prorrogar · Encerrar".

**Trilha de navegação** (breadcrumb): Investigações › nº 12 › Eventos.

### 7.2 Estados da investigação

| Estado | Indicador (cor + ícone + texto) | Ações disponíveis |
| --- | --- | --- |
| Rascunho | cinza · lápis · "Rascunho" | Solicitante: editar, enviar, descartar |
| Aguardando aprovação | âmbar · relógio · "Aguardando aprovação" | Aprovador: aprovar, devolver, recusar; Solicitante: cancelar |
| Devolvida | âmbar · seta de retorno · "Devolvida para correção" | Solicitante: corrigir e reenviar, cancelar |
| Recusada | vermelho · círculo cortado · "Recusada" | Somente leitura |
| Preservação urgente | azul · cadeado · "Coleta lacrada" | Aprovador: aprovar pedido completo, recusar (destrói dados) |
| Aprovada | azul · visto · "Aprovada" | Investigador: iniciar coleta |
| Coletando | azul · progresso · "Coletando 45%" | Investigador: pausar, cancelar |
| Pausada | cinza · pausa · "Pausada" | Investigador: retomar, cancelar |
| Concluída | verde · visto duplo · "Concluída" | Investigador: analisar, gerar pacote, reexecutar |
| Concluída com lacunas | **âmbar** · alerta · "Concluída com lacunas" (âmbar dominante, para não passar a ideia de "tudo certo"; a validar no protótipo da etapa D) | Idem, com o selo de cobertura em destaque |
| Falhou | vermelho · alerta · "Falhou" | Investigador: retomar; Adm. técnico: ver diagnóstico |
| Cancelada | cinza · x · "Cancelada" | Somente leitura |
| Retenção legal | roxo · balança · "Em retenção legal" | Expurgo bloqueado |
| Expurgada | cinza · lixeira · "Expurgada" | Só metadados (UUID, estados, datas, perfis), hash e assinatura do manifesto e verificação |

### 7.3 Telas

| Tela | Conteúdo |
| --- | --- |
| **Início** | Por perfil: "Aguardando minha decisão", "Minhas investigações" por estado, alertas (instância fora do ar, coleta com falha, revelação acima da cota), atalhos |
| **Investigações** | Lista com visões salvas ("minhas", "aguardando minha aprovação", "com lacunas", "em retenção legal"), busca por nº e processo (tolerante a formatação), filtros por estado, período e responsável, progresso, ações por linha conforme o §7.2 |
| **Aprovações** | Fila com prazo restante e risco de expiração; tela de decisão descrita no §4.4 |
| **Nova solicitação** | Assistente (§7.4) |
| **Resumo** | Linha do tempo de estados; para o Solicitante, a visão agregada: totais de logins e falhas, série por dia, aplicações por quantidade e cobertura — sem IPs, contas ou pseudônimos |
| **Acompanhamento** (dentro do Resumo durante a coleta) | Tarefas por instância, eventos coletados, requisições/s contra o orçamento, falhas e retentativas, estimativa de término; pausar, retomar, cancelar |
| **Dashboard** | Ver §7.6 e Anexo A |
| **Eventos** | Ver §7.7 e Anexo A |
| **Contas** | Contas por instância e realm, como foram achadas, duplicidades, situação (incluída, excluída e por quê); incluir/excluir com justificativa; "Sessões ativas" e "Alterações na conta" (dados de `extras_conta`) |
| **Cobertura** | Matriz realm × período com classe (coberto, parcial, sem dados) por **ícone, padrão e texto**, motivo e ação recomendada; versão em tabela |
| **Pacotes** | Gerar mascarado; pedir sem máscara; relatório; histórico com versões, downloads e hashes; verificar |
| **Trilha** | Linha do tempo da investigação, filtrável por tipo (revelação, exportação, download, decisão); revelações em massa destacadas |
| **Comparar** | Diferenças entre execuções (§6.7) |
| **Lista para ofício** | Montada a partir do ranking de IPs do Dashboard ou da seleção de linhas em Eventos ("Adicionar à lista para ofício"). Revisão antes do envio: IP (pseudônimo), horários em UTC, porta quando houver, provedor (ASN) e quantidade; remover itens; motivo. Após aprovação em bloco (§4.4), gera a tabela do ofício em XLSX e PDF, com os valores revelados e registro de cada item na trilha |
| **Trilha global** | Para o auditor interno: todas as investigações, filtros por ator, ação e período, "Verificar cadeia" |
| **Administração** | Instâncias (cadastro, testar conexão, sondas, realms esperados, orçamento), saúde dos workers e filas |
| **Perfis e acessos** | Concessões, revogações e recertificação |

### 7.4 Assistente de nova solicitação

1. **Quem.** CPF ou Título, aceitando colagem com ou sem pontuação; validação do dígito verificador ao sair do campo;
   depois de validado, o campo passa a mostrar o valor mascarado. O valor completo não reaparece em nenhum passo.
2. **Quando.** Período, fuso e granularidade. Para cada realm, mostra até quando os eventos mais antigos do período
   existem na origem (pela `eventsExpiration` lida nas sondas). Se algum expira antes do prazo de aprovação, aparece o
   alerta e a opção "Pedir preservação urgente".
3. **Onde e como.** Instâncias, varredura de falhas sem conta, período de base para "IP novo", contas informadas
   (ex.: conta excluída).
4. **Por quê.** Tipo de processo (que define a base legal, §10.1), nº do processo, justificativa e documento de
   origem.
5. **Revisão.** Resumo do pedido, estimativa de tarefas e tempo, e aviso de que os dados serão tratados conforme o
   aviso de privacidade.

Foco vai para o título de cada passo; erros ficam ligados ao campo (`aria-describedby`) e resumidos no topo.

### 7.5 Revelação na tela

* O controle "Revelar" fica no painel de detalhe do evento, no cabeçalho da conta (aba Contas) e no menu de cada
  célula de pseudônimo.
* Sem sessão de análise ativa, o clique abre o diálogo "Iniciar sessão de análise" (motivo, step-up).
* O valor revelado aparece **ao lado** do pseudônimo, nunca no lugar: `IP 12 · 200.155.34.8 [olho aberto] Revelado`.
  Assim a referência mental da análise não se perde. Na tabela de Eventos, para não perder densidade, os valores
  revelados vão numa coluna "Valor revelado" que só aparece com sessão de análise ativa.
* O cabeçalho mostra o tempo restante da sessão e o contador de cota ("12 de 30 revelados").
* Ao expirar, os valores voltam a pseudônimos e um aviso (`aria-live="polite"`) informa o que aconteceu.
* A marca d'água é uma camada com `aria-hidden="true"`, opacidade baixa, que não reduz o contraste do texto abaixo
  do mínimo exigido, testada também com alto contraste do sistema (`forced-colors`).

### 7.6 Dashboard: paridade com o HTML atual

| Elemento | Situação |
| --- | --- |
| KPIs (logins, falhas, aplicações, IPs, primeiro e último acesso) com selo de cobertura | Mantém |
| Série por janela, com "Ver como tabela" | Mantém |
| Filtros globais (instância, realm, aplicação, eventos técnicos) com chips e "Limpar" | Mantém |
| Tabela por instância, realm e aplicação | Mantém |
| Destaques (fora do expediente, rajadas, IP novo) | Muda: passam a ser **clicáveis** e abrem Eventos filtrado |
| Diálogo de detalhe do evento | Muda: vira painel lateral em Eventos, com hash, folha Merkle e requisição de origem |
| Abas "Sessões ativas" e "Alterações na conta" | Muda: vão para a aba Contas |
| Mapa de calor dia × hora | Novo, com tabela equivalente navegável por teclado |
| Ranking de IPs e aplicações | Novo (pseudônimos para IPs) |
| Painel "Saúde da prova" (releituras, tarefas em limite, selos conferidos, última verificação) | Novo |

**Interação entre telas:** clicar num ponto do gráfico, numa barra, num destaque, num IP ou numa conta abre Eventos
com o filtro correspondente.

**Estado na URL:** filtros técnicos (instância, realm, aplicação, tipo, período) e **pseudônimos** podem ir na URL,
para compartilhar uma visão; valores reais nunca vão. O identificador externo da investigação é um UUID, não o id
sequencial.

### 7.7 Tabela de eventos

* Paginação no servidor (keyset), contagem total e com filtro sempre visíveis.
* Colunas padrão: horário, instância, realm, aplicação, tipo, conta, IP, resultado. Seletor de colunas, densidade
  compacta ou confortável, filtros salvos por usuário.
* Campo "Buscar valor exato (IP, e-mail, username)", com a explicação "busca só por correspondência exata; conta como
  revelação".
* Painel lateral de detalhe: campos, JSON (pseudonimizado até revelar), hash de ingestão, selo da fatia e link para a
  requisição de origem.
* No celular, a tabela vira lista de cartões, só para consulta.

### 7.8 Responsividade

| Largura | Uso |
| --- | --- |
| ≥ 1280 px | Experiência completa (análise, cobertura, comparação) |
| 768–1279 px | Completa, com barra lateral recolhida e painéis sobrepostos |
| < 768 px | Acompanhar estado, **aprovar ou devolver pedidos**, ver Resumo e notificações. Eventos em cartões, sem revelação nem exportação; cobertura e comparação mostram "disponível em tela maior" |

### 7.9 Acessibilidade contínua

* `axe-core` em todo PR (zero violação crítica ou séria) e checklist manual WCAG 2.2 AA/eMAG por tela a cada etapa,
  a partir do W2.
* Todo gráfico tem tabela equivalente e descrição textual dos destaques; cobertura e estados nunca só por cor;
  contraste verificado nos dois temas.
* Progresso ao vivo anunciado com `aria-live="polite"`, no máximo uma vez a cada 10 s.
* Gestão de foco em diálogos, painéis e assistente; foco visível não encoberto (2.4.11); alvos de toque de pelo menos
  24 × 24 px (2.5.8); autenticação sem teste cognitivo (3.3.8); refluxo com zoom de 400% (1.4.10) e espaçamento de
  texto (1.4.12), críticos para a tabela densa.
* Avisos de tempo com opção de prorrogar: sessão de análise (5 min antes) e sessão de uso (2 min antes dos 30 min sem
  atividade). Rolagem, teclado e foco contam como atividade, e o aviso aparece em todas as abas abertas do sistema.
* Testes com NVDA (Firefox e Chrome) no ambiente institucional e com VoiceOver no celular.

### 7.10 Pesquisa e validação com usuários

* **Descoberta** (etapa D, §11): entrevistas e observação com pelo menos 2 pessoas por perfil (investigadores e
  aprovadores reais, corregedoria, TI), mapeamento da rotina atual e dos documentos que chegam (ofícios).
* **Protótipo navegável** das jornadas do §4.4, testado com 5 participantes antes do W2.
* **Segundo teste** com 5 participantes sobre a versão funcional antes do MVP (fim do W3).
* **Teste com pessoas com deficiência** (pelo menos uma usuária de leitor de tela) no W3 e no W6.
* Microtexto e ajuda contextual com uma fonte única: o `GLOSSARIO` e as mensagens de `ERROS` atuais, revisados em
  linguagem simples.

### 7.11 Critérios de aceite de UX

| Critério | Meta | Quando e como se mede |
| --- | --- | --- |
| Sucesso sem ajuda nas tarefas-chave (pedir, aprovar, achar acessos fora do expediente, revelar um IP, montar a lista para ofício, gerar pacote e relatório), com SEQ após cada tarefa | ≥ 90% dos participantes | Protótipo (D, meta ≥ 80%), MVP (W3) e W6; designer, teste moderado |
| Solicitante entende o estado e a cobertura parcial sem ajuda | ≥ 90% | MVP (W3) e W6 |
| Tempo para um pedido completo | ≤ 3 min | MVP e W6 |
| Tempo para uma decisão de aprovação (principal e secundárias, §4.4) | ≤ 1 min (≤ 2 min para revelação total e sem máscara) | MVP e W6, inclusive no celular com step-up |
| SUS com usuários reais | ≥ 75 | W6, com pelo menos 12 participantes somando as rodadas (5 dão só indicação) |
| Violações axe-core críticas/sérias | 0 | Todo PR, no pipeline |
| Jornadas completas só com teclado | 100% | Checklist por etapa a partir do W2 |
| Primeira tela do dashboard com 500 mil eventos | < 2 s (p95) | Teste de carga no W3 |
| Resposta dos filtros (INP) | < 200 ms (p75) | Medição em campo no MVP e no W6 |

### 7.12 Estados de tela e notificações

| Situação | O que a tela mostra |
| --- | --- |
| Carregando | Esqueleto da tela (*skeleton*) no lugar dos cartões e tabelas; no dashboard de investigação grande, "Calculando os números desta investigação…" com os KPIs já prontos aparecendo primeiro |
| Recalculando após incluir/excluir conta | Faixa "Os números estão sendo recalculados por causa da exclusão de Conta 4. Isso leva cerca de 1 min." com os números antigos marcados como desatualizados |
| Investigação sem eventos no período | "Nenhum acesso encontrado no período em nenhum realm pesquisado." com o selo de cobertura (sem eventos ≠ sem cobertura) |
| Realm sem dados | Na Cobertura: "Sem dados: eventos não são gravados neste realm" com a ação recomendada |
| Filtro sem resultado | "Nenhum evento com estes filtros." com "Limpar filtros" |
| Fila de aprovações vazia | "Nada aguardando sua decisão." |
| Instância fora do ar durante a coleta | Faixa no Acompanhamento: "kc18 não responde desde 14:02; a coleta dessa instância está em espera e será retomada sozinha." |
| Coleta com falha parcial | Estado "Concluída com lacunas" e, na Cobertura, as fatias com falha e "Retomar estas fatias" |
| Pacote ou link expirado | "Este link expirou (válido por 10 min). Gere um novo em Pacotes." / "O pacote sem máscara ficou disponível por 24 h e foi apagado. Peça novamente." |
| Conexão ao vivo perdida | "Reconectando…" discreto no Acompanhamento; os números param de piscar, sem perder o que já está na tela |
| Sessão expirada | Página de login que volta à mesma tela depois; avisa que as revelações foram encerradas |
| Investigação expurgada | "Esta investigação foi expurgada em 10/03/2031. Restam os metadados, o hash e a assinatura do manifesto e a verificação de pacotes." |
| Sem permissão | Ver §7.1 |
| Cota de revelação atingida | "Você atingiu 30 revelações nesta sessão. Para continuar, peça aprovação." com o botão "Pedir aprovação" |
| Pedido recusado (Solicitante) | "Seu pedido foi recusado em 27/11 por Ana P.: <motivo>. Você pode abrir um novo pedido corrigido." |
| Erro inesperado do servidor | "Algo deu errado do nosso lado. Informe ao suporte o código 7F2A-91C0." (código de correlação, sem dado pessoal) |
| Coleta em andamento (Dashboard e Eventos) | Faixa "PRELIMINAR — a coleta ainda não terminou; números e rótulos podem mudar." Rótulos aparecem como "IP (numeração no fechamento)" e filtros por pseudônimo só ficam disponíveis depois do fechamento |

**Notificações.** Central de notificações dentro do sistema (sino no cabeçalho) e e-mail institucional. O e-mail
nunca leva dado pessoal nem o identificador mascarado: só o tipo do evento e o link ("Há uma decisão pendente na
investigação 3f9a…"). Geram notificação:
- pedido recebido, devolvido, aprovado ou recusado;
- decisão de revelação ou de pacote sem máscara;
- escalonamento por prazo (§4.2);
- coleta concluída ou com falha;
- aviso de expurgo em 30 dias (§5.7);
- alertas do auditor interno.

**Primeiro acesso.** Apresentação curta por perfil (3 telas, dispensável) e página de Ajuda com o glossário, voltada
ao Solicitante e ao Aprovador, que usam o sistema de vez em quando.

---

## 8. Arquitetura

```
 navegador ──HTTPS──► proxy (TLS, CSP, limite de requisições, SSE sem buffer)
                         │
            ┌────────────┴─────────────┐
            ▼                          ▼
      web (SPA estática)        api (FastAPI, BFF) ─── OIDC ──► realm dedicado do auditor
                                       │
                 ┌──────────┬──────────┼────────────┬───────────────┐
                 ▼          ▼          ▼            ▼               ▼
            PostgreSQL    Vault    workers de    worker-pacotes   worker-tarefas
            (papéis por   (KEK,    coleta        (pacote, PDF,    (preparar, fechar,
             serviço,     HMAC,    (fila com      carimbo)         agregados, extras,
             RLS)         assin.)   rodízio)          │            expurgo, migração)
                             ▲          │             ▼
                             ├──── chaveiro (host próprio; confere estado e designação e entrega DEKs por mTLS)
                             └──── assinador (host próprio; confere selos e assina)
                                        ▼
                         Keycloak / RH-SSO (Admin API, só leitura, orçamento global)

 CLI produção (python -m auditor) ──HTTPS + OIDC──► api   (sem banco, sem Vault)
 CLI local    (python -m auditor) ──► núcleo + banco local (só ambiente de teste; falha fechado em produção)
 SIEM ◄── cópia da trilha (sem texto livre)        ACT ICP-Brasil ◄── carimbo do tempo
```

### 8.1 Camadas

* **Núcleo** (`auditor/`, atual): cliente KC, sondas, descoberta, algoritmo de fatia.
* **Serviços** (`auditor/servicos/`, novo): casos de uso (pedir, aprovar, designar, coletar, pausar, revelar, incluir
  conta, exportar, verificar, expurgar). Toda regra de autorização e de quatro olhos fica aqui. Em produção os serviços
  rodam só no servidor (API e workers); a CLI de produção chega a eles pela API (§8.7), então as regras valem num
  único ponto.
* **API** (FastAPI + Pydantic): rotas finas sobre os serviços; OpenAPI publicada.
* **Web**: React 19 + TypeScript + Vite, TanStack Query e Table, ECharts e gov.br DS (pacote `@govbr-ds/core`, que
  independe de framework). A decisão e a alternativa descartada (Angular) estão no ADR-01 (Anexo B).

### 8.2 Despachante e workers de coleta

* Não há processo despachante central nem eleição de líder: cada worker escolhe a próxima tarefa numa única consulta
  (`FOR UPDATE SKIP LOCKED`) que ordena por prioridade da investigação (preservação urgente primeiro) e, dentro da
  mesma prioridade, pela investigação atendida há mais tempo (`ultimo_atendimento`), o que dá rodízio justo.
* `preparar` (descoberta e localização, chamadas longas ao Keycloak) roda como job no `worker-tarefas` quando a
  investigação é aprovada; ao terminar, as tarefas de coleta entram na fila.
* **Pausar e cancelar:** o worker checa o estado da investigação ao pegar cada tarefa e a cada página lida; pausa
  devolve a tarefa à fila com o cursor salvo; cancelar marca as pendentes como canceladas.
* **Corrida entre CLI e worker:** o fechamento da investigação (`fechar`, `extras_conta`, cálculo de agregados) é um
  job único por investigação, protegido por *advisory lock*; a CLI chama o mesmo serviço e entra na mesma fila.
* Retomada após queda continua pelo lease atual.

### 8.3 Orçamento de carga entre processos

* Tabela `orcamento_instancia` com balde de fichas (taxa e capacidade por instância), consumido numa transação curta
  (`SELECT … FOR UPDATE`, atualiza, *commit*) antes de cada requisição, sem segurar a transação durante o HTTP.
* Concorrência limitada por N *advisory locks* **de sessão** por instância (`pg_try_advisory_lock(inst, slot)`),
  tomados numa conexão dedicada do worker, fora do pool, e liberados ao fim da requisição ou com a queda da conexão.
* Com o balde vazio, o processo dorme o tempo calculado até a próxima ficha, em vez de consultar em laço.
* Vale para todos os processos que falam com os Keycloaks (workers e API ao testar conexão); a CLI de produção não
  fala com os Keycloaks. O teste de conexão passa a registrar suas requisições (hoje usa `registrar=False`,
  `__main__.py:57`), para o critério de aceite enxergá-las.
* Critério de aceite: três processos coletando ao mesmo tempo, em investigações diferentes, contra a mesma instância
  nunca passam de 5 req/s em nenhuma janela de 1 s. A medição reaproveita `max_req_por_s` de `tests/aceite.py`,
  agrupando só por `instancia_id` (hoje ela filtra por investigação).

### 8.4 Dados para o dashboard

* `consolidar()` é reescrito. As regras de negócio (categorias, rajadas, fora do expediente, IP novo) viram funções
  puras testadas contra o resultado atual com a mesma massa.
* **Agregados** gravados pelo worker ao fim de cada fatia: `agregado_hora(investigacao, hora, instancia, realm,
  aplicacao, tipo, conta_pseudo, n)`, com a hora em UTC. Os totais e séries, com qualquer combinação de filtros, saem
  dessa tabela. Limitação declarada: fusos com deslocamento de meia hora exigiriam agregados de 15 min (nenhum fuso
  brasileiro tem esse caso).
* **Contagens distintas** (IPs, aplicações) não são somáveis entre horas: saem de consulta direta sobre
  `evento(investigacao_id, ip_pseudo)` com índice composto pelas dimensões de filtro. A meta de 2 s vale para 500 mil
  eventos e é medida no W3.
* **Destaques** (rajadas, fora do expediente, IP novo) são calculados no fechamento e guardados em `destaque`.
* Incluir ou excluir conta dispara recálculo de agregados e destaques daquela investigação (job, com aviso na tela
  até terminar).

### 8.5 Banco e migrações

* **Alembic** para migração de esquema (hoje só existe `CREATE TABLE IF NOT EXISTS`). `conta_extra` entra no esquema.
* Pool de conexões (`psycopg-pool`, já nas dependências): API 20, cada worker 4.
* Tabelas novas: `usuario`, `papel`, `designacao`, `aprovacao`, `sessao_analise`, `revelacao`, `pseudonimo`,
  `chave_investigacao`, `pacote`, `download`, `job`, `orcamento_instancia`, `agregado_hora`, `destaque`, `selo`,
  `cadeia`, `ancora_diaria`, `retencao_legal`, `sessao_web`, `documento_origem`, `compartilhamento`, `contestacao`,
  `notificacao`.

### 8.6 Papéis de banco e RLS

* `kc_owner` (só migrações, DDL), `kc_api`, `kc_coleta`, `kc_pacotes`, `kc_tarefas`, `kc_assinador` (só leitura da
  trilha e dos selos), `kc_chaveiro` (só estado, designação e DEKs envelopadas). Nenhum é superusuário. **Não existe papel de banco para a CLI de produção.**
* RLS em `evento`, `conta`, `pseudonimo`, `revelacao`, como defesa em profundidade dos papéis de serviço: a API define
  a identidade da sessão (`SET LOCAL`) a partir da sessão OIDC já validada e só enxerga investigações designadas.

### 8.7 Linha de comando

* No modo `local`, todos os comandos atuais continuam com a mesma sintaxe e a mesma saída; no modo `producao`, a
  correspondência está na tabela abaixo.
* **Modo `producao`: a CLI é um cliente fino da API.** A identidade vem de login OIDC por *device flow*
  (`python -m auditor login`), não de `--operador`. Cada comando vira uma chamada à API, com o mesmo token, o mesmo
  controle de acesso, a mesma segregação e as mesmas aprovações da web. A CLI de produção **não tem DSN do banco nem
  token Vault**; quem tem shell no posto de trabalho não ganha nenhum acesso que não teria pelo navegador. O comando
  `exportar` baixa o pacote gerado pelo worker, como na web. No *device flow*, o código vale 5 min, o token exige `acr`
  com MFA como na web, e a tela de aprovação avisa que o login vale só para aquele dispositivo (contra *phishing* de
  código).

| Comando | Modo `producao` | Modo `local` |
| --- | --- | --- |
| `chave`, `init` | Não existem (chaves no Vault, esquema por Alembic) | Como hoje |
| `instancia-add`, `sondas` | Chamadas administrativas à API (Administrador técnico) | Como hoje |
| `investigar`, `retomar` | Viram `pedir` e ações sobre a investigação na API, sujeitas a aprovação | Como hoje |
| `exportar` | Pede o pacote à API e baixa | Como hoje (com o formato v2) |
| `verificar` | Offline, igual nos dois modos (`kc-verificar`) | Idem |
| `migrar-cifra`, `expurgar` | Pedem jobs à API (com quatro olhos) | Executam localmente |
* **Modo `local`:** comportamento de hoje, com núcleo, banco e `AUDITOR_CHAVE` locais, só para desenvolvimento e teste.
  **Falha fechado:** só funciona com `AUDITOR_MODO=local` explícito, recusa iniciar se o DSN ou alguma URL de
  instância cadastrada estiver na lista de destinos de produção (configurada na instalação) e, se iniciado num host
  marcado como produção, recusa e envia alerta ao SIEM. Sem `AUDITOR_MODO`, a CLI não inicia. Desenvolvimento e
  homologação usam só massa sintética (como `tools/pessoas.py`); cópia de dado real fora da produção é proibida e
  consta do RIPD.
* Comandos novos: `login`, `pedir`, `aprovar`, `designar`, `revelar`, `migrar-cifra`, `expurgar`, `verificar-trilha`.
* Os testes de aceite passam a rodar **pelas duas portas**: `tests/aceite.py` (CLI) e um equivalente pela API.

### 8.8 Tempo real

* Server-Sent Events autenticados, com checagem de designação ao abrir o stream e limite de 3 conexões por usuário.
* A fonte é a própria tabela `tarefa`, lida a cada 1 s por **um único leitor por investigação** em cada instância da
  API, compartilhado entre todas as conexões abertas para ela. `NOTIFY` serve só como aviso para antecipar a leitura e
  não leva dado pessoal. Se a API reiniciar, nada se perde.
* Heartbeat a cada 15 s; o cliente reconecta com `Last-Event-ID`; buffering desligado no proxy.

### 8.9 Sessão web

* Sessão no PostgreSQL (`sessao_web`), cookie `HttpOnly`/`Secure`/`SameSite=Strict`, 30 min sem atividade e no
  máximo 8 h; logout pelo canal de retorno do OIDC (*back-channel logout*) encerra a sessão e as revelações ativas.

---

## 9. Segurança

* Verificação pelo **OWASP ASVS 4.0 nível 2**, com a matriz de requisitos versionada no repositório.
* **Realm dedicado** para os usuários do auditor; impersonation desligada; o BFF exige `acr`/`amr` indicando MFA;
  step-up com `max_age` para operações sensíveis (§5.5); eventos administrativos do realm enviados ao SIEM.
* Autorização no servidor em todo endpoint (perfil + designação + estado). Testes automatizados de acesso indevido
  para cada perfil e de IDOR em todas as rotas com id.
* CSP sem `unsafe-inline`, `X-Frame-Options: DENY`, CSRF com token, limite de requisições por usuário (inclusive em
  verificação e geração de pacotes).
* Identificador do alvo e dados pessoais nunca vão em URL, query string ou log. O log de acesso do proxy e da API não
  registra corpo nem query string (que pode ter pseudônimos de filtros compartilhados); exceções passam por filtro de
  dados pessoais; APM sem captura de payload.
* Step-up valida o `auth_time` do token, não só a idade da sessão.
* **Limitação conhecida:** a busca de usuário na Admin API do Keycloak manda o CPF em query string
  (`q=cpf:<dígitos>`), que pode ficar nos logs de acesso das instâncias auditadas. Isso é combinado com os donos das
  instâncias (retenção desses logs) e registrado no RIPD.
* Service accounts dos Keycloaks só com `view-events`, `view-users`, `query-users` e `view-realm`, com segredo
  rotacionado anualmente.
* **Cadeia de suprimentos:** dependências com hash fixo (`pip --require-hashes`, `npm ci`), SBOM CycloneDX, imagens
  base fixadas por digest e assinadas (cosign), nenhum recurso de CDN em execução (gov.br DS e ECharts servidos
  localmente), Renovate com revisão, pip-audit, npm audit, Trivy e ZAP no pipeline.
* **Resposta a incidente:** plano próprio, integrado ao da instituição, com comunicação ao encarregado e, quando
  couber, à ANPD e aos titulares (art. 48; Resolução CD/ANPD nº 15/2024).
* Pentest externo antes da produção.

---

## 10. Conformidade (LGPD)

### 10.1 Base legal por finalidade

O campo "tipo de processo" do assistente define a base legal registrada na investigação:

| Finalidade | Base legal |
| --- | --- |
| Apuração administrativa ou disciplinar, controle interno | Art. 7º, II (obrigação legal ou regulatória) e art. 23, *caput* (competências legais do serviço público), com a norma de competência específica |
| Instrução de processo judicial ou administrativo em que o órgão é parte | Art. 7º, VI (exercício regular de direitos em processo), como complemento |
| Atendimento a requisição externa (juízo, Ministério Público, polícia, outro órgão) | Art. 7º, II (cumprimento de requisição ou ordem com fundamento legal) e art. 23, *caput*, sob o regime de **uso compartilhado**: art. 26, *caput*, entre entes públicos; art. 26, § 1º e art. 27 quando o destinatário for privado, com registro do destinatário e do que foi entregue para o art. 18, VII. O órgão continua sob a LGPD; o art. 4º, III, "d" descreve só o regime do **destinatário** quando ele conduz investigação penal |
| Requisição a provedor de internet (lista para ofício) | Transferência a ente privado: art. 26, § 1º (exceções) e art. 27 (comunicação à ANPD, salvo as exceções dos incisos), com fundamento na ordem judicial para registros de conexão (Lei 12.965/2014, art. 10, § 1º e art. 22) ou na competência legal do requisitante; registro em `compartilhamento`; só itens com vínculo ao alvo; aviso de rede compartilhada |
| Dados de terceiros que aparecem nos eventos | Mesma base da finalidade, com minimização reforçada, DEK própria e descarte no prazo de contestação (§5.2, §5.7) |
| Dados dos próprios usuários do auditor (trilha, alertas) | Art. 7º, II e art. 23, *caput*, ligados às normas de segurança da informação e de controle aplicáveis; o dever de segurança do art. 46 é a finalidade, não a base. Aviso interno |

A tabela deve ser validada pelo encarregado e pela assessoria jurídica antes do W1.

### 10.2 Princípios e registros

* **Segurança e responsabilização** (art. 6º, VII e X; art. 46): trilha encadeada, revelação registrada, cifra.
* **Inventário de operações** (art. 37): o kc-auditor entra no inventário de tratamento do órgão.
* **Transparência** (art. 9º; art. 23, I): aviso de privacidade publicado sobre a auditoria de acessos aos sistemas,
  e aviso interno para os usuários do auditor sobre o monitoramento das suas ações.
* **Minimização:** só os eventos das contas do alvo; "realm inteiro" desabilitado em produção; terceiros sempre
  pseudonimizados.
* **Eliminação** (art. 16): expurgo ao fim do prazo, com as exceções do próprio artigo (cumprimento de obrigação
  legal, uso exclusivo do controlador anonimizado).

### 10.3 Direitos do titular (arts. 18 e 19)

* **Localizar** todos os dados de um titular: a partir do identificador, o sistema encontra as investigações
  (`K_alvo`) e o `historico_identidade`. Operação do encarregado, registrada na trilha.
* **Acesso:** resposta no prazo do art. 19, salvo quando o sigilo justificar o adiamento ou a recusa, com fundamento
  registrado: segredo de justiça (CPC, art. 189), sigilo do processo disciplinar (Lei 8.112/1990, art. 150) e
  informação pessoal ou sigilosa na LAI (art. 31), a confirmar com a assessoria jurídica.
* **Localização a pedido do titular** exige protocolo do pedido, não só o registro da operação.
* **Terceiros** (donos de IPs e usernames que aparecem nos eventos) não podem ser localizados por identificador; o
  encarregado responde a eles pelo que for possível localizar (por exemplo, pelo username informado) e declara essa
  limitação.
* **Revisão de decisão automatizada** (art. 20): os destaques são indícios para análise humana. O titular pode pedir
  a explicação dos critérios (art. 20, § 1º), que estão no relatório, e a revisão da análise.
* **Correção:** eventos de acesso não se retificam, porque são registro de fato. Anota-se a contestação na
  investigação, e ela aparece no relatório.
* **Informação sobre compartilhamento** (art. 18, VII): os destinatários são os do processo; os downloads ficam
  registrados.
* **Oposição e eliminação:** avaliadas pelo encarregado frente à base legal; a eliminação antecipada passa por quatro
  olhos.
* O encarregado (art. 41) é o canal; o sistema dá a ele um relatório por titular, sem dar acesso aos eventos.

### 10.4 RIPD

Relatório de Impacto (art. 5º, XVII; art. 32; art. 38) elaborado **antes do W1**, com o encarregado, a partir desta
proposta. Revisado no W4 e no W6. A aprovação do RIPD é critério de entrada do W1 e do W4, e as decisões de coleta
que o W0b implementa (minimização do corpo HTTP, reuso do histórico, descarte de terceiros) dependem do RIPD inicial.

### 10.5 Normas de referência a confirmar

Resolução CNJ nº 363/2021 (LGPD no Judiciário), Resolução CNJ nº 396/2021 (segurança da informação no Judiciário:
trilha, SIEM, incidentes), o guia orientativo da ANPD sobre anonimização e pseudonimização (versão vigente na etapa D)
e a política de privacidade e proteção de dados da Justiça Eleitoral, a serem confirmadas com a assessoria jurídica.

---

## 11. Entregas

| Etapa | Semanas | Entrega | Critério de aceite |
| --- | --- | --- | --- |
| **W-0 · Correções imediatas** | 1 | D1 a D5 do §1.2 corrigidos na CLI atual | Pacote mascarado sem nenhum identificador em claro (varredura); `eventos.jsonl` coerente com as contas excluídas; testes atuais verdes |
| **D · Descoberta, RIPD e decisões** (semanas 2–4, em paralelo com W0a) | 3 | Entrevistas, protótipo navegável, teste com 5 usuários, RIPD inicial, validação da premissa do §2 e da base legal, ADRs | RIPD e premissa aprovados pelo encarregado; protótipo com ≥ 80% de sucesso nas tarefas-chave |
| **W0a · Fundação e orquestração** | 3 | Alembic, papéis de banco, camada de serviços, fila com rodízio, `preparar`/`fechar` como jobs, orçamento entre processos, pool | Teste de orçamento com 3 processos; pausar e retomar sem perda; `contagem_real.py` e `aceite.py` verdes |
| **W0b · Cifra e custódia** | 3 | Vault (com o Operador do Vault), `chaveiro`, envelope e DEKs, cifra na gravação, pseudônimos, compromissos com sal, corpo minimizado, selos, releitura por conteúdo, cadeias e âncora diária (carimbo pode ser simulado até a ACT) | Varredura de dado pessoal = 0; selos conferem em 100% das fatias; alteração de conteúdo relido detectada; `chaveiro` recusa DEK fora de estado |
| **W1 · Acesso** | 2 | Realm dedicado, BFF, MFA e step-up, perfis, designação, aprovação, trilha no SIEM, CLI de produção como cliente da API, modo local que falha fechado | Matriz de permissões testada para os 7 perfis e pelas duas portas; nenhuma rota sem autorização; CLI de produção sem credencial de banco/Vault; modo local recusado contra destino de produção |
| **W2 · Gestão** | 3 | Início, Investigações, Aprovações, assistente, preservação urgente, Acompanhamento, Administração | Pedir, aprovar, coletar, pausar, retomar e concluir uma investigação de 180 dias só pela web; axe-core 0 |
| **W3 · Análise — MVP** | 4 | Dashboard, Eventos, Contas, Cobertura, visão agregada, agregados e destaques | Números iguais aos do XLSX; dashboard < 2 s com 500 mil eventos; segundo teste com usuários; **MVP em homologação para uso assistido** |
| **W4 · Revelação e migração** | 2 | Sessão de análise, cotas, aprovações de revelação, migração das investigações existentes | Revelação registrada, expira no servidor e bloqueia acima da cota; migração com hashes iguais aos manifestos entregues |
| **W5 · Pacotes e prova** | 3 | Pacote v2 em streaming, `assinador`, carimbo do tempo real, verificador offline, especificação do formato, relatório técnico e agregado em PDF/A, reexecução e comparação | Equivalência local × produção; verificador offline aprova os pacotes e `--recalcular` confere relatório, consolidado, destaques e cobertura; revelação seletiva verificada; força bruta de IPv4 e CPF sobre o pacote mascarado sem nenhuma confirmação |
| **W6 · Homologação** | 2 | Acessibilidade com usuários, testes ponta a ponta (Playwright), carga, pentest, revisão do RIPD, teste de restauração de backup e de rotação de chaves | Zero achado crítico/alto no pentest; WCAG 2.2 AA sem pendência bloqueante; SUS ≥ 75 |
| **Reserva** | 3 | Contingência (~12% do total) | — |

**Total: 26 semanas** (23 de trabalho e 3 de reserva, ~12% do total), com MVP utilizável ao fim da semana 16. A etapa D corre nas semanas 2 a 4, em paralelo com o
W0a, e termina antes do W0b, que depende das decisões do RIPD inicial.

**Dependências externas** (caminho crítico)

| Dependência | Responsável | Necessária em | Plano B |
| --- | --- | --- | --- |
| Aprovação do RIPD inicial e da premissa do §2 | Encarregado de dados | Fim da semana 4 (antes do W0b e do W1) | W0b começa pelas partes que não dependem do RIPD (Vault, envelope, selos); as decisões de minimização entram por configuração |
| Vault ou HSM institucional em alta disponibilidade | Infraestrutura | Semana 5 (W0b) | Vault operado pela própria equipe em cluster de 3 nós, com o Operador do Vault designado, até a migração para o serviço institucional |
| Realm dedicado com administradores próprios | Segurança da informação | Semana 8 (W1) | Realm no SSO de homologação para o desenvolvimento; produção só com o realm dedicado |
| SIEM institucional recebendo syslog | Segurança da informação | Semana 8 (W1) | Servidor de log de escrita única (WORM) da infraestrutura, com migração para o SIEM depois |
| Contratação da ACT ICP-Brasil (carimbo do tempo) | Administração e contratos | Semana 19 (W5) | Em homologação, uma TSA RFC 3161 qualquer, fora da ICP-Brasil, com o verificador configurado para uma raiz de teste separada; produção espera a contratação. O MVP (semana 16) não depende dela |

**Equipe:** 2 desenvolvedores full stack, 1 desenvolvedor backend com foco em segurança e infraestrutura, 1 designer
(integral até o W3, meio período depois), e apoio do encarregado de dados (D, W1, W4, W6), da segurança da informação
(W0b, W1, W6) e da assessoria jurídica (D).

---

## 12. Riscos

| Risco | Mitigação |
| --- | --- |
| A premissa de "visualizar abertamente" não ser a esperada | Validada na etapa D, antes de qualquer código de revelação; o modelo aceita configurações mais restritivas |
| Perda de chave torna investigações ilegíveis | KEK no Vault/HSM com backup e cerimônia de recuperação; teste de restauração no W6 |
| Comprometimento do Vault expõe todas as chaves | Vault em alta disponibilidade, auditoria própria enviada ao SIEM, políticas mínimas por serviço, *unseal* com chaves divididas |
| Reidentificação por pseudônimos e atributos de rede | Chave por investigação, rótulos sequenciais, IP privado como "rede interna", sem prefixo de rede; análise no RIPD |
| Aprovação lenta faz eventos expirarem | Expiração mostrada no pedido; preservação urgente com coleta lacrada; escalonamento automático |
| Desempenho do dashboard em investigações grandes | Agregados por hora e consulta indexada por pseudônimo; meta medida no W3 |
| Divergência entre CLI e web | Uma única camada de serviços; testes de aceite pelas duas portas; teste de equivalência de pacotes |
| Uso abusivo da revelação | Motivo por sessão, cota com bloqueio, step-up, marca d'água, alertas e recertificação |
| Equipe de manutenção não dominar React | ADR-01 revisto no fim da etapa D, antes do W2 |
| Prazo | Reserva de 3 semanas (~12% do total); MVP na semana 16 permite reordenar W4 a W6 sem perder valor |
| Dependências externas atrasarem (RIPD, Vault, realm, SIEM, ACT) | Tabela de dependências do §11, com responsável, data e plano B para cada uma |
| Serviço comprometido ler investigações que desembrulhar | Risco residual declarado (§3.2); hosts separados, alertas de desembrulho, TTL de 5 min da DEK em memória |
| Configuração esquecida reativar o modo local em produção | Modo local falha fechado e alerta o SIEM (§8.7) |

---

## Anexo A — Wireframes de referência

**Dashboard (≥ 1280 px)**

```
┌───────────────────────────────────────────────────────────────────────────────────────────┐
│ ☰  kc-auditor        Investigações › nº 12 › Dashboard                    Maria S. ▾  ◐   │
├───────────────────────────────────────────────────────────────────────────────────────────┤
│ Investigação 12 · ***.914.534-** · 30/05–26/11/2026 (America/Bahia)   ⚠ Concluída com lacunas │
│ ⚠ Cobertura parcial: 4 de 7 realms · 90 de 181 dias — ver detalhes                         │
├───────────────────────────────────────────────────────────────────────────────────────────┤
│ Resumo  [Dashboard]  Eventos  Contas  Cobertura  Pacotes  Trilha                           │
├───────────────────────────────────────────────────────────────────────────────────────────┤
│ Filtros: [Instância ▾] [Realm ▾] [Aplicação ▾] [☐ eventos técnicos]   chips: realm=intranet ✕  Limpar │
│ ┌────────┐ ┌────────┐ ┌────────┐ ┌────────┐ ┌──────────────┐ ┌──────────────┐               │
│ │Logins  │ │Falhas  │ │Aplic.  │ │IPs     │ │1º acesso     │ │Último acesso │               │
│ │ 3.149  │ │ 1.108  │ │  12    │ │  301   │ │31/05 07:19   │ │26/11 23:38   │               │
│ └────────┘ └────────┘ └────────┘ └────────┘ └──────────────┘ └──────────────┘               │
│ Logins e falhas por dia                                  [Ver como tabela]                 │
│ ▁▂▃▂▅▃▂▁▂▃▄▃▂▃▅▆▃▂▁ ...                                                                   │
│ ┌ Destaques ───────────────────────┐ ┌ Mapa de calor dia × hora ──┐ ┌ Top IPs ──────────┐  │
│ │ ▸ 47 logins fora do expediente → │ │      0h ... 12h ... 23h     │ │ IP 3   rede interna│  │
│ │ ▸ 3 rajadas de falha        →    │ │ seg  ░░▒▓▓▒░                │ │ IP 12  BR-DF · ASN │  │
│ │ ▸ 5 IPs novos               →    │ │ ...         [Ver tabela]    │ │ ...       →        │  │
│ └──────────────────────────────────┘ └─────────────────────────────┘ └────────────────────┘  │
│ Saúde da prova: releituras 817 ok · 0 divergentes · selos 1.635/1.635 conferidos             │
└───────────────────────────────────────────────────────────────────────────────────────────┘
```

**Eventos com painel de detalhe e sessão de análise ativa**

```
┌───────────────────────────────────────────────────────────────────────────────────────────┐
│ Investigação 12 · …   🔓 Sessão de análise até 15:42 · 12 de 30 revelados · Prorrogar · Encerrar │
│ Resumo  Dashboard  [Eventos]  Contas  Cobertura  Pacotes  Trilha                           │
├───────────────────────────────────────────────────────────────────────────────────────────┤
│ 1.108 de 11.946 eventos · filtro: tipo=Falha de login, IP 12 ✕     [Colunas] [Compacta ▾]  │
│ [Buscar valor exato (conta como revelação) ______________]                                 │
│ ┌──────────────┬──────┬────────┬─────────┬──────┬───────┬──────┬───────────────────┐ ┌─ Detalhe ───┐│
│ │Horário       │Inst. │Realm   │Aplicação│Tipo  │Conta  │IP    │Valor revelado     │ │Falha de login││
│ ├──────────────┼──────┼────────┼─────────┼──────┼───────┼──────┼───────────────────┤ │Conta 3       ││
│ │26/11 23:38:03│kc26  │intranet│app-teste│Falha │Conta 3│IP 12 │👁 200.155.34.8    │ │IP 12 ·       ││
│ │26/11 23:37:59│kc26  │intranet│app-teste│Falha │Conta 3│IP 12 │👁 200.155.34.8    │ │200.155.34.8 ││
│ │26/11 23:35:41│kc26  │intranet│portal   │Login │Conta 3│IP 3  │—                  │ │👁 Revelado   ││
│ │ ...          │      │        │         │      │       │      │                   │ │Erro: senha   ││
│ └──────────────┴──────┴────────┴─────────┴──────┴───────┴──────┴───────────────────┘ │inválida      ││
│ (a coluna "Valor revelado" só existe com sessão de análise ativa)                    │Hash: 9f2c…   ││
│ ◀ anteriores   próximos ▶                                                    │Selo: fatia   ││
│                                                                              │26/11 ✔       ││
│                                                                              │Requisição #… ││
│                                                                              │[Revelar conta]││
│                                                                              └──────────────┘│
└───────────────────────────────────────────────────────────────────────────────────────────┘
```

**Início de sessão de análise**

```
┌ Iniciar sessão de análise ───────────────────────────────────────┐
│ Para ver dados reais nesta investigação, informe o motivo.        │
│ Motivo *  ( ) Identificar o responsável por acesso indevido      │
│           ( ) Confirmar autoria de acessos para o processo        │
│           ( ) Responder a ofício/requisição judicial              │
│           ( ) Outro: [_____________________________]              │
│ Duração: até 4 h · Cota: 30 itens · Tudo fica registrado na trilha│
│ Você vai confirmar sua identidade de novo.                        │
│                                 [Cancelar]  [Confirmar e iniciar] │
└───────────────────────────────────────────────────────────────────┘
```

---

## Anexo B — Decisões de arquitetura (ADRs a escrever na etapa D)

| ADR | Decisão proposta | Alternativa descartada |
| --- | --- | --- |
| 01 Frontend | React 19 + TS + gov.br DS core | Angular 20 (revisto se a equipe de manutenção exigir) |
| 02 Chaves | Envelope local com DEK por investigação; `chaveiro` como único porteiro do desembrulho | Cifra valor a valor no Vault Transit (milhões de chamadas); chave mestra em variável de ambiente |
| 03 Pseudônimos | Tabela sequencial + HMAC completo | HMAC truncado (colide) |
| 04 Orçamento | Balde de fichas no PostgreSQL + advisory locks | Redis (mais um serviço para operar) |
| 05 Agregados | `agregado_hora` + distintos por consulta indexada | Recalcular tudo em memória (atual) |
| 06 Tempo real | SSE com leitura da tabela `tarefa` | WebSocket; NOTIFY como única fonte |
| 07 Custódia | Compromisso com sal na ingestão + selos Merkle + cadeia por investigação + âncora diária carimbada | Hash só na exportação (atual) |
| 09 Assinatura | `assinador` isolado que reconfere selos antes do Transit | Worker de pacotes assinando direto |
| 10 CLI | Produção como cliente da API; local que falha fechado | CLI com acesso direto a banco e Vault |
| 08 Pacote v2 | Pseudonimizado + folhas Merkle; v1 continua verificável | Manter o conteúdo atual |

---

## Anexo C — Rastreabilidade da banca

Arquitetura (A), Segurança (S), Privacidade (L), UX (U), Perícia (P), na ordem dos bloqueantes de cada relatório.

| Ponto | Onde foi tratado |
| --- | --- |
| A1 orçamento entre processos | §1.2 D6, §8.3 |
| A2 despachante, pausar/cancelar, corrida CLI × worker, `extras_conta`/`fechar` | §8.2 |
| A3 `consolidar()` não escala nem funciona cifrado | §1.1, §8.4 |
| A4 inventário de dado pessoal incompleto; `historico_identidade` | §5.1, §5.4 |
| A5 CLI contorna as regras | §8.7, §3.2 |
| A6 ordem W3/W4, Alembic, corte da migração | §11 (cifra no W0b, antes das telas), §8.5, §5.6 |
| A7 armazenamento e memória dos pacotes; conteúdo muda | §6.4 |
| A8 prazo sem folga; MVP | §11 (26 semanas na v4, reserva, MVP na semana 16) |
| S1 modelo de ameaças | §3 |
| S2 administrador contorna a segregação | §3.2, §4.1 (Gestor de acesso), §8.7 |
| S3 ameaça do IdP | §3.2, §4.1, §9 |
| S4 gestão de chaves, AAD, separação por finalidade | §5.3, §1.2 D4 |
| S5 pseudônimos curtos colidem; busca como oráculo | §5.4 |
| S6 inventário incompleto | §5.1 |
| S7 pacote mascarado vaza o alvo | §1.2 D1, §6.4, W-0 |
| S8 chave Ed25519, carimbo, verificação por upload, zip bomb | §6.2, §6.5 |
| S9 trilha inviolável, papéis de banco, RLS, `sub` | §6.3, §8.6 |
| S10 destruição criptográfica e cópias em claro | §5.6, §5.7 |
| S11 cota com bloqueio; captura de tela | §5.5 |
| S12 "visão anonimizada" não é anônima | §2, §7.3 |
| L1 visão agregada; o que sobrevive ao expurgo | §2, §5.7 |
| L2 inventário; `requisicoes.jsonl` | §5.1, §1.2 D1, §6.4 |
| L3 reidentificação (histórico, chave do pseudônimo, colisão, rede, oráculo) | §5.2, §5.3, §5.4 |
| L4 dados de terceiros; realm inteiro | §5.2 |
| L5 direitos do titular | §10.3 |
| L6 prazo de guarda, retenção legal, backups, art. 16 | §5.7, §10.2 |
| L7 RIPD antes do W1 | §10.4, §11 (etapa D) |
| L8 base legal | §10.1 |
| L9 governança (CLI, mudança de configuração, transparência, destino do sem máscara, incidente) | §8.7, §4.2, §10.2, §6.4, §9 |
| Citações legais | §2 (art. 5º III e XI, 12 § 2º, 13 § 4º por analogia), §10.1 (7º II e 23), §10.2 (37 separado de 6º/46) |
| U1 jornadas por perfil, aprovações, devolução | §4.4, §7.3 |
| U2 arquitetura de informação e navegação | §7.1 |
| U3 estados da investigação | §7.2 |
| U4 revelação na tela, tempo ajustável, motivo por sessão, pseudônimo pronunciável | §5.5, §7.5, §5.4, §7.9 |
| U5 paridade com o dashboard; interações; URL | §7.6 |
| U6 tabela de eventos | §7.7 |
| U7 pesquisa com usuários | §7.10, §11 (etapa D) |
| U8 critérios de UX mensuráveis | §7.11 |
| U9 acessibilidade contínua, WCAG 2.2 | §7.9 |
| U10 responsividade | §7.8 |
| P1 hash na ingestão, selos, AAD | §6.1, §5.3 |
| P2 critério probatório da migração | §5.6 |
| P3 pacote mascarado verificável; revelação seletiva; equivalência | §6.4 |
| P4 inventário; `requisicoes.jsonl` | §5.1, §6.4 |
| P5 chave de assinatura, `key_id`, publicação, carimbo, assinatura do servidor | §6.2 |
| P6 verificador independente e especificação | §6.5 |
| P7 relatório para os autos | §6.6 |
| P8 reexecução, versões, comparação | §6.7 |
| P9 aprovação × retenção; preservação urgente; substituto; ofício externo | §4.2, §4.4, §7.4 |
| P10 contas excluídas no pacote | §1.2 D2, §6.4 |
| P11 expurgo × processo em curso | §5.7 |
| P12 trilha encadeada e no manifesto | §6.3 |

**Segunda rodada**

| Ponto | Onde foi tratado |
| --- | --- |
| A1/S2 (rodada 2) custódia de chaves incoerente com o envelope | §5.3 (envelope local, controle nos serviços, política de desembrulho por estado, alertas, TTL), §3.2 (risco residual declarado) |
| A2/S3 (rodada 2) CLI contorna as regras; modo local | §8.7 (CLI de produção como cliente da API, sem banco nem Vault; modo local falha fechado), §8.6 (sem papel de banco para a CLI) |
| A3 (rodada 2) W0 sobrecarregado; dependências externas | §11 (W0a + W0b, 25 semanas, tabela de dependências com responsável e plano B), §12 |
| S1/P1 (rodada 2) hashes sem sal no pacote mascarado | §1.2 D1 (W-0 sem hash por linha), §6.4 (compromissos com sal, RFC 6962, teste de força bruta no W5) |
| S4/P6 (rodada 2) Vault Transit não valida selos | §6.2 (`assinador` isolado), §3.2 |
| P2 (rodada 2) exclusão quebra o elo com a coleta | §6.4 (`fatias.json`, raiz sobre todas as fatias) |
| P3 (rodada 2) selo não provável por terceiro | §6.3 (cadeia por investigação, âncora diária com prova de inclusão no pacote) |
| P4 (rodada 2) releitura só por ids | §6.1 item 4 |
| P5 (rodada 2) segregação no pedido externo | §4.2 |
| L1 (rodada 2) o que sobra depois do expurgo | §5.7 (tabela), §6.4 (manifesto sem texto livre) |
| L2 (rodada 2) corpo HTTP amplia dados de terceiros | §5.1, §6.1 item 1 |
| L3 (rodada 2) terceiros e contas excluídas no pacote sem máscara | §6.4, §5.2, §5.3 (`DEK_t`), §5.7 |
| L4 (rodada 2) apoio penal e uso compartilhado | §10.1, §4.4 (pedido externo) |
| L5 (rodada 2) reuso do `historico_identidade` | §4.4 (sugestão aceita pelo aprovador, aviso condicionado) |
| L6 (rodada 2) SIEM e modo local | §6.3 (SIEM sem texto livre), §8.7 |
| Citações (rodada 2): art. 46 como base; art. 4º, III, "d"; arts. 26, 27 e 20 | §10.1, §10.3, §6.6 |
| U1 (rodada 2) estados de tela e notificações | §7.12 |
| U2 (rodada 2) estabilidade dos pseudônimos; visão do Solicitante | §5.4 (numeração determinística e imutável, herança na reexecução), §6.6 (relatório agregado), §7.1 |
| U3 (rodada 2) decisões secundárias e espera | §4.4, §5.4 (busca sem sessão) |
| Afirmações sobre o código (rodada 2) | §1.1 (kc.py, `gravar` e `reler` adaptados), §1.2 D2 (`consolidar.py:86`), D6 (`kc.py:39-60`), §6.1 (id sintético) |

**Terceira rodada**

| Ponto | Onde foi tratado |
| --- | --- |
| Arquitetura e segurança: desembrulho por estado não é política do Vault | §5.3 (`chaveiro`, aceite no W0b), §3.2, §3.3, ADR-02 |
| Arquitetura: W0b com 2 semanas | §11 (W0b com 3 semanas, total 26, MVP na semana 16) |
| Perícia: derivados não protegidos pelo `assinador` | §6.5 (`--recalcular`, aceite no W5), §3.2 |
| Perícia: varredura tratada como terceiro | §5.2 (classe "tentativa com o identificador do alvo"), §5.7 (marco dos 90 dias e retenção legal) |
| Perícia: redação de `requisicoes.jsonl` | §6.4 |
| LGPD: lista para ofício a provedor privado | §4.4, §10.1 (art. 26, § 1º, art. 27, Marco Civil art. 10, § 1º e art. 22) |
| LGPD: terceiros em `eventos.jsonl` e nos pseudônimos | §6.4, §5.2 |
| LGPD: estado Expurgada; investigador e investigações anteriores; atributo sigilosa | §7.2, §7.12, §5.4, §4.4 |
| LGPD: citação do art. 26, § 1º | §10.1 |
| UX: wireframes, "a validar", lista para ofício, estados de cota/recusa/erro/preliminar | Anexo A, §7.2, §7.3, §7.12 |

**Pendências para a etapa D** (ajustes menores da rodada 4, sem bloqueio)

* Classe "tentativa com o identificador do alvo": criar o campo "papel do alvo" na aprovação (titular cuja identidade
  teria sido usada / autor suspeito / outro), definido pelo aprovador; inclusão automática no pacote sem máscara só com
  "identidade usada" ou decisão expressa. Mostrar ao aprovador quantidade de tentativas e de IPs distintos, permitir
  incluir só um recorte e registrar no RIPD o tratamento dos IPs de terceiros (LGPD).
* Interface da classe nova: etiqueta, filtro e destaque próprios em Eventos e no Dashboard (UX).
* Preservação urgente: contagem regressiva na tela e nas notificações ("os dados serão destruídos em 2 dias úteis se
  ninguém decidir"), escalonamento e aviso de destruição iminente no §7.12 (UX).
* Pedido recusado: confirmar com o encarregado se o Solicitante vê o nome do aprovador ou só "a área de aprovação" (UX).
* `fatias.json` com status, releitura e motivo de cada fatia, e cobertura incluída no `--recalcular`; eventos do
  período de base marcados como "base" no pacote; `folhas.jsonl` com o compromisso também dos eventos de terceiros
  omitidos, marcados (perícia).
* Nota metodológica: no pacote mascarado, o `--recalcular` prova a coerência entre eventos pseudonimizados e
  derivados, não a correspondência com os originais (perícia).
* Medir no W0b latência e taxa de pedidos ao `chaveiro` e definir o cache por processo (arquitetura).
* Citar o Marco Civil, art. 10, § 3º (dados cadastrais por autoridade administrativa), deixando claro que registros de
  conexão exigem ordem judicial (LGPD).

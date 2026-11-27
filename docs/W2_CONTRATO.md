# W2 · Contrato entre as telas (frente A) e o servidor (frente B)

Fonte das regras: `docs/PROPOSTA_WEB.md` §4 (perfis, regras, jornadas), §7 (interface), §8.8 (tempo real) e §11 (aceite
do W2: *pedir, aprovar, coletar, pausar, retomar e concluir uma investigação de 180 dias só pela web; axe-core 0*).

As rotas do W1 continuam como estão (`/api/docs` lista todas). Este documento fixa **só o que o W2 acrescenta ou muda**.
A frente A programa contra este contrato (com dublês nas rotas novas enquanto B não termina); a frente B implementa
exatamente isto. Mudança de contrato: registrar aqui, no mesmo commit, com o motivo.

## Convenções (valem para todas as rotas)

* JSON em `snake_case`, datas em ISO 8601 com fuso (UTC no servidor; a tela converte para o fuso da investigação).
* Erro: `{"erro": "...", "mensagem": "..."}` com o status HTTP (formato do W1, mantido: a CLI e os testes dependem
  dele). Novo: erro 500 devolve `{"erro": "interno", "mensagem": "...", "correlacao": "7F2A-91C0"}` e o mesmo
  código vai para o log, sem dado pessoal.
* `401 {"erro": "step_up"}` → a tela manda para `/auth/entrar?step_up=1&volta=<tela atual>` e repete a ação.
* `401` sem sessão → `/auth/entrar?volta=<tela atual>`.
* `403/404` em investigação: **mesma resposta** `404 {"erro":"sem_acesso"}` para "não existe" e "sem vínculo" (§7.1).
* POST/PUT/DELETE com cookie exigem o cabeçalho `X-Requisicao: kc-auditor` (W1).
* **`acoes`**: toda investigação (lista e detalhe) traz `acoes: [str]`, calculado no servidor para o usuário atual,
  com os nomes do §7.2: `enviar, editar, descartar, aprovar, devolver, recusar, cancelar, reenviar, autorizar_preservacao,
  prorrogar_preservacao, iniciar, pausar, retomar, gerar_pacote, pedir_sem_mascara, enviar_documento, baixar_documento`.
  A tela **só mostra botões que estejam em `acoes`**; não reimplementa regra de permissão.
* Nenhuma resposta leva CPF/título em claro. O alvo vem como `alvo_mascarado` (ex.: `***.456.789-**`) e não vem para
  o auditor interno.

## Estados (`status`) que a tela precisa conhecer

`rascunho, aguardando_aprovacao, devolvida, recusada, preservacao_urgente, aprovada, coletando, pausada, concluida,
concluida_com_lacunas, falhou, cancelada` (+ `retencao_legal, expurgada`, só exibição). Estados internos de passagem
(`abrindo`, `preparando`, `fechando`) aparecem como "Preparando…" (cinza, progresso). Cor + ícone + texto do §7.2.

## Rotas novas ou alteradas

### 1. Início
`GET /api/inicio` → por perfil:
```json
{"perfil": ["aprovador"],
 "aguardando_minha_decisao": [{"tipo": "investigacao|pacote_sem_mascara|preservacao_urgente", "pedido": 12,
                               "investigacao": 7, "desde": "...", "prazo": "...", "escalonado": false}],
 "minhas_por_estado": {"coletando": 2, "concluida": 5},
 "alertas": [{"tipo": "instancia_fora|coleta_falhou|papel_alterado|escalonamento|preservacao_expira",
              "texto": "...", "investigacao": 7, "quando": "..."}],
 "nao_lidas": 3}
```

### 2. Lista de investigações (alterada)
`GET /api/investigacoes?visao=minhas|aguardando|lacunas|retencao&estado=a,b&q=<nº ou processo>&de=&ate=&pagina=1`
→ `{"itens": [Investigacao], "total": 41, "pagina": 1, "por_pagina": 25}`.
Busca `q` tolerante a formatação (ignora pontos, barras, traços e espaços). **Mudança:** o W1 devolvia lista pura;
a CLI de produção (`auditor/cliente.py`) passa a ler `itens`.

`Investigacao` (lista): `id, status, alvo_mascarado?, de, ate, fuso, processo?, solicitante, investigador?, criado_em,
atualizado_em, progresso_pct?, origem_externa: bool, sigilosa: bool, acoes`.

### 3. Detalhe (alterado)
`GET /api/investigacoes/{id}` acrescenta ao que já existe:
* `linha_do_tempo: [{"status", "quando", "por", "motivo"?}]` (motivo só para quem pode ler, §4.4);
* `expiracao: [{"instancia", "realm", "eventos_desde", "expira_antes_da_aprovacao": bool}]`;
* `estimativa: {"tarefas", "segundos"}`; `documento: {"nome", "sha256", "tamanho"} | null`;
* `preservacao: {"autorizada_em", "escalona_em", "destroi_em", "prorrogada": bool} | null`;
* `acoes`.

### 4. Estimativa (assistente, passos 2 e 5)
`POST /api/estimativas` com `{"de", "ate", "fuso", "granularidade", "instancias": [..], "varredura": bool, "base_dias": int}`
(sem o identificador) → `{"tarefas", "segundos", "expiracao": [...como no detalhe], "preservacao_recomendada": bool}`.
Não grava nada e não vai para a trilha.

### 5. Pedido (alterado)
`POST /api/investigacoes` aceita também `"rascunho": bool` (grava como `rascunho`, sem enviar),
`"preservacao_urgente": bool` e `"tipo_processo": str` (base legal, §10.1). Rascunho:
`PUT /api/investigacoes/{id}` (mesmo corpo; só no estado `rascunho` ou `devolvida`, só o solicitante),
`POST /api/investigacoes/{id}/enviar`, `DELETE /api/investigacoes/{id}` (descartar rascunho).
O CPF/título vai só no POST/PUT; a resposta nunca o devolve.

### 6. Documento de origem
`POST /api/investigacoes/{id}/documento` (multipart, campo `arquivo`, PDF ou imagem, ≤ 10 MB) — cifrado com a DEK
da investigação; o SHA-256 vai para a trilha e depois para o manifesto. `GET .../documento` baixa (aprovador da
fila, investigador designado; nunca o auditor interno). Obrigatório para pedido externo antes de `enviar`.

### 7. Preservação urgente (§4.4)
* Pedido com `preservacao_urgente: true` fica `aguardando_aprovacao` com `tipo=preservacao_urgente` na fila.
* `POST /api/investigacoes/{id}/autorizar-preservacao` `{"investigador", "motivo"}` (aprovador, step-up) → estado
  `preservacao_urgente`; a coleta roda **lacrada**: nenhuma rota de dados/pacote da investigação responde até a
  aprovação do pedido completo (`409 {"erro":"lacrada"}`).
* Aprovar o pedido completo: o `aprovar` do W1, aceito também a partir de `preservacao_urgente`.
* Recusar a partir de `preservacao_urgente` destrói a DEK (registro na trilha com o fundamento).
* Prazos em dias úteis: escalonamento ao coordenador em 3, destruição em 5 sem decisão;
  `POST .../prorrogar-preservacao` `{"motivo"}` (coordenador, uma vez, +10 dias úteis).

### 8. Acompanhamento ao vivo (§8.8)
`GET /api/investigacoes/{id}/acompanhamento` (JSON, mesma forma de um evento SSE) e
`GET /api/investigacoes/{id}/acompanhamento/stream` (`text/event-stream`). Evento `progresso` a cada mudança,
`heartbeat` a cada 15 s, `id:` crescente para `Last-Event-ID`, no máximo 3 conexões por usuário (`429` na quarta):
```json
{"status": "coletando", "progresso_pct": 45, "eventos": 12034,
 "instancias": [{"nome": "kc26", "tarefas": {"pendente": 3, "executando": 2, "concluida": 40, "falhou": 1},
                 "req_por_s": 4.2, "orcamento_req_por_s": 5, "fora_do_ar_desde": null}],
 "falhas": 1, "retentativas": 4, "termino_estimado": "..."}
```

### 9. Notificações (§7.12)
`GET /api/notificacoes?nao_lidas=1` → `[{"id", "tipo", "texto", "investigacao"?, "quando", "lida"}]`;
`POST /api/notificacoes/{id}/lida`; `POST /api/notificacoes/lidas` (todas). E-mail: só gravado em
`logs/email.jsonl` (sem dado pessoal nem alvo mascarado), até haver SMTP institucional.

### 10. Sem acesso
`POST /api/investigacoes/{id}/pedir-acesso` `{"motivo"}` → `202` sempre (exista ou não); vai para a trilha global.

### 11. Substitutos e escalonamento (§4.2)
`GET /api/substitutos` e `PUT /api/substitutos/eu` `{"substituto": "<username>"}` (aprovador define o seu; precisa
ser aprovador). Pedido parado há mais de 1 dia útil escalona ao substituto e depois ao coordenador (papel
`coordenador`? — **não existe no realm**: B usa o atributo `coordenador=true` no usuário do realm; registrar aqui se
mudar). Escalonamento roda no laço de limpeza do worker.

### 12. Perfis e acessos (gestor de acesso, §4.3)
* `GET /api/perfis` → `[{"username", "nome", "unidade", "papeis", "ultimo_login", "recertificado_em"}]`;
* `POST /api/perfis/{username}/papeis` `{"conceder": [..], "revogar": [..], "motivo"}` (step-up) — pelo Keycloak
  Admin do realm `auditor` com conta de serviço própria (`kc-auditor-gestao`, só `manage-users`/`view-users` do realm);
  a API recusa combinações proibidas (§4.2) **antes** de chamar o Keycloak;
* `GET/POST /api/recertificacoes`, `POST /api/recertificacoes/{id}/confirmar` `{"username", "manter": bool}`;
* toda concessão/revogação, inclusive feita direto no console do Keycloak (vigia que compara os papéis a cada minuto),
  gera alerta ao auditor interno (notificação + SIEM).

### 13. Administração (alterada)
`GET /api/servicos/saude` acrescenta `filas: {"tarefas": {"pendente", "executando", "falhou"}, "jobs": {...}}` e
`workers: [{"papel", "visto_em"}]`. `POST /api/instancias/{nome}/testar` (teste de conexão sem sondas).

### 14. Telas servidas pela API
`GET /` e qualquer caminho que não comece com `/api` ou `/auth` servem `web/dist/index.html` (SPA), com os
arquivos de `web/dist/assets/` com cache longo. CSP do W1 mantida (sem `unsafe-inline` em script). Se `web/dist` não
existir, `/` responde 503 com texto "Interface não compilada (npm run build em web/)".

## Decisões e mudanças registradas na implementação (frente B, com a coordenação)

Cada item diz o que vale a partir de agora e por quê.

1. **Corpo de erro** (decisão da coordenação): fica o do W1, `{"erro", "mensagem"}` (texto corrigido acima). Erro
   de validação (422): `{"erro": "validacao", "mensagem", "campos": [{"campo", "erro"}]}`, **sem eco do valor
   recebido** (o padrão do FastAPI devolvia o corpo, que pode trazer o CPF). Link ou pacote expirado:
   `410 {"erro": "expirado"}` (link usado, de outra pessoa ou inexistente continua 404).
2. **Estados.** `na_fila` (W1) e `abrindo` aparecem como `preparando`; `coletada` como `fechando`; `parcial` (coleta
   interrompida com fatias pendentes; o investigador retoma) como `falhou`. O valor cru vem em `status_interno`.
   Rascunho descartado fica `descartada` e some das listas (404 como inexistente).
3. **Pedido externo direto.** `POST /api/investigacoes` com `origem` e sem `"rascunho": true` responde
   `422 {"erro": "documento"}`: o documento só pode ser anexado a uma investigação que já existe, e o §6 o exige
   antes do envio. Fluxo: POST com `rascunho` → `POST .../documento` → `POST .../enviar` (a CLI faz isso com
   `pedir --orgao ... --arquivo oficio.pdf`).
4. **Corpo do pedido (POST/PUT)** (decisão da coordenação) aceita também `"processo": str` (nº do processo, até 80
   caracteres; sem ele vale `origem.processo`) e `"contas_informadas": [{"instancia", "realm", "username"}]` (até
   50). O `processo` é texto livre: fica **cifrado com a DEK**, e a busca `q` compara o **HMAC do número
   normalizado** (só letras e dígitos), portanto casa o número inteiro com qualquer pontuação, não um trecho. As
   contas informadas ficam cifradas com a DEK e entram no preparo (busca exata do username no realm). O detalhe
   devolve só a quantidade (`contas_informadas: n`), porque o username é dado pessoal.
5. **PUT do rascunho**: sem `cpf`/`titulo`, mantém o identificador já gravado. Não muda um pedido entre interno e
   externo (422 `origem`).
6. **`enviar` × `reenviar`.** `enviar` só existe em `rascunho`; na `devolvida` a ação é `reenviar` (`{"motivo"}` =
   o que foi corrigido). As `acoes` já vêm assim: rascunho `[enviar, editar, descartar, enviar_documento?]`;
   devolvida `[editar, cancelar, reenviar, enviar_documento?]`.
7. **`Investigacao`** (lista e detalhe) traz também `status_interno`, `preservacao_urgente`, `tipo_processo`,
   `minhas_funcoes`. O `alvo` do W1 passou a ser só `alvo_mascarado`. `de`/`ate` em ISO (UTC); `inicio_ms`/`fim_ms`
   continuam. `processo` só para quem lê (designados e o aprovador que decide); para os outros, `null`.
8. **Detalhe** acrescenta `tipo_processo`, `instancias`, `varredura`, `base_dias`, `processo` (só para quem lê) e
   `contas_informadas` (quantidade). `documento.nome` vem `null` para quem não decifra (auditor interno);
   `preservacao` traz também `encerrada_em` e `desfecho` (`aprovada | recusada | expirada`). A `linha_do_tempo`
   substitui a do W1 (`{quando, acao}`).
9. **Lista.** `de`/`ate` filtram pela data de criação (AAAA-MM-DD); `por_pagina` (padrão 25, máximo 100). O auditor
   interno sem vínculo só acha pelo nº da investigação.
10. **`GET /api/aprovacoes`** (decisão da coordenação): cada item traz `pedido, tipo, investigacao, desde,
    criado_em, prazo, escalonado, lacrada, risco_expiracao: bool, realm_critico: {"instancia", "realm",
    "eventos_desde", "expira_antes_da_aprovacao"} | null` (o realm cujos eventos mais antigos somem primeiro) e, no
    pacote sem máscara, `parametros`. Os itens de `aguardando_minha_decisao` do início têm a mesma forma.
11. **`GET /api/investigacoes/{id}/investigadores-elegiveis`** (nova; só o aprovador que decide, senão 404
    `sem_acesso`) → `[{"username", "nome", "unidade"}]`: quem tem o perfil investigador e já entrou no auditor,
    menos o próprio aprovador e o solicitante. **Diferença:** no pedido externo o solicitante (quem registrou) é
    elegível, porque o §4.2 permite que ele investigue.
12. **`GET /api/instancias/disponiveis`** (nova; solicitante, investigador, aprovador) → `[{"nome", "realms": [..]}]`
    com os realms visíveis na última descoberta; sem URL, segredo nem orçamento.
13. **Coordenação.** Atributo `coordenador=true` no usuário do realm (`infra/realm_auditor.py` cria `coordenador1`,
    aprovador), exposto no token como claim `coordenador` e em `/api/eu`. A prorrogação exige aprovador + coordenador.
14. **Escalonamento.** Os pedidos não têm aprovador atribuído (qualquer aprovador elegível decide). Parado há mais de
    1 dia útil, o pedido é escalonado aos **substitutos cadastrados** (notificação `escalonamento`); há mais de 2, aos
    coordenadores; `escalonado` fica `true`.
15. **`GET /api/substitutos`** (aprovador, gestor de acesso, auditor interno) → `[{"aprovador", "substituto" | null,
    "atualizado_em" | null}]`, um por aprovador. `PUT /api/substitutos/eu` → `{"aprovador", "substituto"}`.
16. **Recertificação.** `GET /api/recertificacoes` → `[Recertificacao]` e `POST /api/recertificacoes` (corpo
    opcional `{"usuarios": [..]?, "prazo_dias": 30}`) → `Recertificacao`, com `Recertificacao = {"id", "criada_em",
    "prazo", "concluida_em" | null, "pendentes": [{"username", "papeis"}], "itens": [{"username", "papeis",
    "manter" | null, "decidido_em"}]}`. `POST .../{id}/confirmar` `{"username", "manter"}` → `{"id", "username",
    "manter"}`; quem confirma é o gestor de acesso (`manter: false` revoga na hora, com step-up). Vencido o prazo, o
    laço do worker revoga o que não foi confirmado.
17. **`POST /api/instancias/{nome}/testar`** → `{"instancia", "ok", "ms", "erro" | null, "texto"}` (`texto` é a frase
    para a tela).
18. **Quem vê.** `GET .../documento`: também o aprovador designado (quem aprovou). `POST .../pedir-acesso` exige
    ter algum perfil (sem perfil: 403), para que nenhuma rota sirva a quem não tem perfil (aceite do W1).
19. **Notificações (`tipo`).** `pedido_recebido, preservacao_urgente, pedido_devolvido, pedido_aprovado,
    pedido_recusado, designacao, preservacao_autorizada, preservacao_expira, escalonamento, pacote_sem_mascara,
    decisao_pacote, coleta_concluida, coleta_falhou, papel_alterado, dek_destruida, recertificacao`. O alerta
    `instancia_fora` do início é calculado (última requisição à instância nos últimos 10 min falhou), só para o
    administrador técnico.
20. **Acompanhamento.** Tarefas por instância: `limite` conta como `concluida`; `sem_permissao` e `cancelada` como
    `falhou`. O evento SSE `heartbeat` não tem `id`.
21. **Ficam para o W3** (decisão da coordenação): contas do histórico como sugestão ao aprovador (§4.4) e o selo de
    cobertura.

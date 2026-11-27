# W2 · Contrato entre as telas (frente A) e o servidor (frente B)

Fonte das regras: `docs/PROPOSTA_WEB.md` §4 (perfis, regras, jornadas), §7 (interface), §8.8 (tempo real) e §11 (aceite
do W2: *pedir, aprovar, coletar, pausar, retomar e concluir uma investigação de 180 dias só pela web; axe-core 0*).

As rotas do W1 continuam como estão (`/api/docs` lista todas). Este documento fixa **só o que o W2 acrescenta ou muda**.
A frente A programa contra este contrato (com dublês nas rotas novas enquanto B não termina); a frente B implementa
exatamente isto. Mudança de contrato: registrar aqui, no mesmo commit, com o motivo.

## Convenções (valem para todas as rotas)

* JSON em `snake_case`, datas em ISO 8601 com fuso (UTC no servidor; a tela converte para o fuso da investigação).
* Erro: `{"codigo": "...", "texto": "..."}` com o status HTTP (já é assim no W1). Novo: erro 500 devolve
  `{"codigo": "interno", "texto": "...", "correlacao": "7F2A-91C0"}` e o mesmo código vai para o log, sem dado pessoal.
* `401 {"codigo": "step_up"}` → a tela manda para `/auth/entrar?step_up=1&volta=<tela atual>` e repete a ação.
* `401` sem sessão → `/auth/entrar?volta=<tela atual>`.
* `403/404` em investigação: **mesma resposta** `404 {"codigo":"sem_acesso"}` para "não existe" e "sem vínculo" (§7.1).
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
  aprovação do pedido completo (`409 {"codigo":"lacrada"}`).
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

## Mudanças registradas pela frente B (servidor), com o motivo

1. **Corpo de erro.** O W1 respondia `{"erro", "mensagem"}`; agora é `{"codigo", "texto"}` como este contrato fixa
   (a CLI de produção lê os dois). Erro de validação (422): `{"codigo": "validacao", "texto", "campos": [{"campo",
   "erro"}]}`, **sem eco do valor recebido** (o padrão do FastAPI devolvia o corpo, que pode trazer o CPF).
2. **Pedido externo direto.** `POST /api/investigacoes` com `origem` e sem `"rascunho": true` responde
   `422 {"codigo": "documento"}`: o documento só pode ser anexado a uma investigação que já existe, e o §6 o exige
   antes do envio. Fluxo: POST com `rascunho` → `POST .../documento` → `POST .../enviar` (a CLI faz isso com
   `pedir --orgao ... --arquivo oficio.pdf`).
3. **`processo`.** O POST/PUT aceita `"processo": str` (nº do processo, até 80 caracteres; sem ele vale
   `origem.processo`). É o que a busca `q` encontra, ignorando pontuação e espaços; não aparece ao auditor interno
   sem vínculo (para ele, `q` só casa o nº da investigação).
4. **Campos a mais em `Investigacao`** (lista e detalhe): `status_interno`, `preservacao_urgente`, `tipo_processo`,
   `minhas_funcoes`. O campo `alvo` do W1 passou a se chamar só `alvo_mascarado`. `de`/`ate` em ISO (UTC);
   `inicio_ms`/`fim_ms` continuam. Estados de passagem: `abrindo`/`na_fila` → `preparando`, `coletada` → `fechando`,
   `parcial` (coleta interrompida com fatias pendentes) → `falhou`. Rascunho descartado fica `descartada` e some das
   listas (404 como inexistente).
5. **Lista.** `de`/`ate` filtram pela data de criação (AAAA-MM-DD); `por_pagina` (padrão 25, máximo 100).
6. **Detalhe.** `documento.nome` vem `null` para quem não decifra (auditor interno); `preservacao` traz também
   `encerrada_em` e `desfecho` (`aprovada | recusada | expirada`). A `linha_do_tempo` substitui a do W1
   (`{quando, acao}`).
7. **Coordenação.** Atributo `coordenador=true` no usuário do realm (`infra/realm_auditor.py` cria `coordenador1`,
   aprovador), exposto no token como claim `coordenador` e em `/api/eu`. A prorrogação exige aprovador + coordenador.
8. **Escalonamento.** Os pedidos não têm aprovador atribuído (qualquer aprovador elegível decide). Parado há mais de
   1 dia útil, o pedido é escalonado aos **substitutos cadastrados** (notificação `escalonamento`); há mais de 2, aos
   coordenadores. `aguardando_minha_decisao[].escalonado` fica `true`. Os itens trazem também `lacrada`.
9. **Quem vê.** `GET /api/substitutos`: aprovador, gestor de acesso e auditor interno. `GET .../documento`: também o
   aprovador designado (quem aprovou). `POST .../pedir-acesso` exige ter algum perfil (sem perfil: 403), para que
   nenhuma rota sirva a quem não tem perfil (aceite do W1).
10. **Recertificação.** `POST /api/recertificacoes` aceita `{"usuarios": [..]?, "prazo_dias": 30}`; quem confirma é
    o gestor de acesso (`manter: false` revoga na hora, com step-up). Vencido o prazo, o laço do worker revoga o que
    não foi confirmado.
11. **Notificações (`tipo`).** `pedido_recebido, preservacao_urgente, pedido_devolvido, pedido_aprovado,
    pedido_recusado, designacao, preservacao_autorizada, preservacao_expira, escalonamento, pacote_sem_mascara,
    decisao_pacote, coleta_concluida, coleta_falhou, papel_alterado, dek_destruida, recertificacao`. O alerta
    `instancia_fora` do início é calculado (última requisição à instância nos últimos 10 min falhou), só para o
    administrador técnico.
12. **Acompanhamento.** Contagem de tarefas por instância: `limite` conta como `concluida`; `sem_permissao` e
    `cancelada` como `falhou`. O evento SSE `heartbeat` não tem `id`.

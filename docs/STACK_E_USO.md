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

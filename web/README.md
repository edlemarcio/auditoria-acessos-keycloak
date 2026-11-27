# kc-auditor · telas (W2)

SPA em **React 19 + TypeScript + Vite** com os componentes do **gov.br DS** (`@govbr-ds/core`, classes CSS; o
comportamento é dos componentes React daqui), em português, tema claro e escuro, meta WCAG 2.2 AA / eMAG.
Consome a API do contrato `docs/W2_CONTRATO.md` (e as rotas do W1, `/api/docs`).

Node 22 (`source ~/.nvm/nvm.sh`). Instalar: `npm ci` dentro de `web/`.

## Rodar em desenvolvimento

| Comando | O que faz |
| --- | --- |
| `npm run dev:dubles` | `vite dev` em :5173 com **dublês do contrato** (MSW). Nenhum servidor necessário. |
| `npm run dev` | `vite dev` em :5173 com proxy de `/api` e `/auth` para a API (`AUDITOR_API`, padrão `http://localhost:8100`). |

**Dublês** (`src/dubles/`): seguem o contrato à risca (URLs, corpos, `acoes` calculadas no "servidor", erros
`{codigo, texto}`, `404 sem_acesso`, `401 step_up`, SSE com `id:` e `Last-Event-ID`). Só existem no `vite dev` com
`VITE_DUBLES=1` e nos testes; o build de produção não leva o MSW nem o service worker (`dev-public/` só é servido no dev).
O perfil é escolhido pelo cookie `dubles_perfil` (no console do navegador):

```js
document.cookie = 'dubles_perfil=aprovador; path=/'   // solicitante | investigador | aprovador | auditor_interno
                                                      // admin_tecnico | gestor_acesso | aprovinvest
```

O `/auth/entrar` de mentira (plugin do `vite.config.ts`, só com dublês) grava a sessão e, com `step_up=1`, o
horário do step-up (vale 5 min) e volta para `volta=`. Estados especiais: investigação **999** responde 500 com
código de correlação; qualquer nº inexistente responde `404 sem_acesso`; o pacote 6 da investigação 33 está expirado;
o stream de acompanhamento cai a cada 6 eventos (para exercitar "Reconectando…").

### Contra a API do W1 (ponta a ponta real)

Na raiz do worktree, em outro terminal (porta 8100; o retorno do login é a origem do Vite, já aceita no realm):

```bash
source chaves.env
export AUDITOR_MODO=local AUDITOR_DSN=postgresql://kc_auditor_app:senha-app-teste@localhost:5435/auditor \
  AUDITOR_OIDC_EMISSOR=http://localhost:8090/realms/auditor AUDITOR_API_URL=http://localhost:5173 \
  KC_DSN_kc26=postgresql://keycloak:keycloak@localhost:5433/keycloak KC_DSN_kc18=postgresql://keycloak:keycloak@localhost:5434/keycloak
.venv/bin/python -m auditor api --porta 8100
```

Depois `npm run dev` e abra http://localhost:5173 (login no realm `auditor` com senha e OTP).
As rotas que só o W2 terá (`/api/inicio`, notificações etc.) respondem 404 no W1: o Início cai para um resumo
montado a partir da lista; o resto mostra o erro da tela.

## Testes

| Comando | O que roda |
| --- | --- |
| `npm test` | Vitest + Testing Library (jsdom, MSW em Node): CPF/título (DV e máscara), assistente, ações, lista, cliente da API, SSE, armazenamento |
| `npm run e2e` | Playwright contra o `vite dev` com dublês: **axe-core** (WCAG 2.0/2.1/2.2 A/AA + boas práticas) em todas as telas, nos temas claro e escuro, e jornadas só com teclado |
| `npm run e2e:aceite` | **Aceite do W2**: investigação de 180 dias do pedido à conclusão só pela web, com login real de solicitante1, aprovador1 e investigador1, contra a API integrada em :8000 servindo `web/dist` (com worker). ~12 min |
| `npm run e2e:real` | Playwright ponta a ponta **real**: login no Keycloak :8090 (senha + OTP de `chaves/totp_teste.json`) até o Início e a lista. Precisa da API em :8100 (acima) e da porta 5173 livre |
| `npm run e2e:build` | `npm run build` e o build servido com a CSP da API (`default-src 'self'`): sem violação, sem dublês, fontes e ícones locais |
| `npm run capturas` | Gera as capturas de `docs/capturas/w2/` (só dados dos dublês) |
| `npm run lint` / `npm run typecheck` | ESLint e `tsc --noEmit` |

Navegador do Playwright: `npx playwright install chromium`.

## Build

`npm run build` → `web/dist/` (a API serve na mesma origem, contrato §14). Sem script ou estilo inline, sem CDN:
fontes (Raleway, no lugar da Rawline do DS) e ícones (Font Awesome) vão empacotados em `dist/assets/`.

## Regras que a tela segue

* Botões de ação **só** a partir de `acoes` da investigação; o menu só esconde o que o perfil não usa (§7.1). Nenhuma
  regra de permissão é reimplementada: quem decide é o servidor.
* Todo POST/PUT/DELETE leva `X-Requisicao: kc-auditor`; sessão só pelo cookie HttpOnly do BFF.
* `401 {"codigo":"step_up"}` → `/auth/entrar?step_up=1&volta=<tela>`; na volta, a mesma ação reabre para confirmar
  (só o nome da ação fica no `sessionStorage`, nunca o que foi digitado). `401` sem sessão → "Sua sessão expirou".
* CPF/título: validação do DV ao sair do campo; depois disso o campo mostra só a máscara e o valor completo fica só na
  memória do assistente até o POST/PUT. Nunca vai para URL, `localStorage` ou `sessionStorage` (há teste para isso).
  A busca da lista recusa um CPF/título digitado em vez de mandá-lo na query string.
* Acompanhamento ao vivo por SSE lido com `fetch` (para mandar `Last-Event-ID` nas reconexões); anúncio
  `aria-live` no máximo a cada 10 s; `429` cai para consulta a cada 15 s.

## Estrutura

```
src/api/          cliente (erros, CSRF, step-up), rotas (normaliza W1 → contrato), SSE, tipos do contrato
src/componentes/  estrutura (cabeçalho, sino, barra lateral, trilha), ações por investigação, diálogos, campos, estados de tela
src/telas/        Início, Investigações, Nova solicitação, Investigação (Resumo/Pacotes/Trilha), Aprovações, Decisão,
                  Administração, Perfis e acessos, Trilha global, Sem acesso, Sessão expirada
src/dominio/      CPF/título, estados (§7.2), perfis e menu (§7.1), formatação
src/dubles/       dublês do contrato (MSW) — só dev e testes
e2e/              Playwright (axe, jornadas, real, build, capturas)
```

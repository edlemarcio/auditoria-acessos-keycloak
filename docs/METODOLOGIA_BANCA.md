# Metodologia de avaliação por banca

Como a proposta da versão web (`docs/PROPOSTA_WEB.md`) foi construída e avaliada até a nota 9. O método serve para
qualquer proposta técnica que precise de aprovação multidisciplinar.

## 1. Visão geral

```
 levantamento do código ─► proposta v1 ─► banca (5 avaliadores em paralelo) ─► consolidação
                                ▲                                                  │
                                │                                                  ▼
                       revisão pontual ◄── conferência no código ◄── bloqueantes por avaliador
                                │
                                └──► nova rodada (até todos ≥ 9)
```

1. **Levantar o ponto de partida no código** antes de escrever: módulos, esquema, o que já existe e o que falta.
2. **Escrever a proposta** (v1) com objetivo, premissas, desenho, entregas e riscos.
3. **Submeter a uma banca de especialistas independentes**, cada um com um ângulo diferente, em paralelo.
4. **Consolidar** os relatórios: notas, bloqueantes, convergências entre avaliadores.
5. **Conferir no código** cada afirmação contestada antes de reescrever.
6. **Revisar** a proposta e registrar, numa matriz de rastreabilidade, onde cada bloqueante foi tratado.
7. **Nova rodada** com os mesmos avaliadores (que mantêm o contexto) até todos darem nota ≥ 9.

## 2. A banca

| Avaliador | Ângulo | O que cobra |
| --- | --- | --- |
| Arquitetura de software | Viabilidade e manutenção | Reaproveitamento real do código, orquestração, escalabilidade, migração, prazo |
| Segurança da informação | Ameaças e controles | Modelo de ameaças, autenticação, autorização, chaves, trilha, cadeia de suprimentos |
| Privacidade e LGPD | Conformidade | Interpretação jurídica, citações legais, minimização, guarda, direitos do titular, RIPD |
| UX e acessibilidade | Uso | Jornadas, navegação, estados, acessibilidade (WCAG/eMAG), validação com usuários, critérios mensuráveis |
| Perícia e auditoria | Usuário final e prova | Cadeia de custódia, valor probatório, verificação por terceiro, rotina real |

Regras dadas a todos:

* **Independência:** cada avaliador lê a proposta e o código sozinho; não vê os outros relatórios.
* **Somente leitura:** não edita arquivos nem altera estado (sem subir containers, sem gravar no banco).
* **Conferir contra o código:** apontar com `arquivo:linha` qualquer afirmação da proposta que não confira.
* **Régua comum:** *9 = aprovaria para execução com ajustes menores.*
* **Formato fixo de resposta**, para consolidar rápido:

```
NOTA: <0 a 10, meio ponto>
RESUMO: <2 a 3 frases>
PONTOS FORTES:
BLOQUEANTES PARA CHEGAR A 9 (concreto, acionável, com a seção da proposta):
MELHORIAS OPCIONAIS:
AFIRMAÇÕES INCORRETAS SOBRE O CÓDIGO (ou CITAÇÕES LEGAIS INCORRETAS, para LGPD):
BLOQUEANTES ANTERIORES: resolvido / parcial / não resolvido   (a partir da 2ª rodada)
```

## 3. Modelo de pedido ao avaliador

```
Você é avaliador independente numa banca que revisa uma proposta técnica.
Sua especialidade: <área> (<o que ela cobre>).

Contexto: <o que o projeto faz, onde está, o que existe hoje>.
A proposta a avaliar é <caminho>. O pedido original do cliente foi: "<texto literal>".

Leia a proposta inteira e o código que precisar (<arquivos relevantes>).
Não edite nenhum arquivo e não rode nada que altere estado.

Avalie do seu ponto de vista: <lista de critérios da área>.
Seja exigente: 9 significa "eu aprovaria para execução com ajustes menores".

Responda em português, neste formato exato: <formato da seção 2>.
```

Nas rodadas seguintes, o mesmo avaliador recebe só: "a proposta foi revisada (versão N); a tabela da rodada
anterior no Anexo C mapeia seus bloqueantes; releia a proposta inteira, avalie com o mesmo rigor e diga o status de
cada bloqueante anterior". Avaliador que já deu 9 recebe um pedido curto de **confirmação**, porque a revisão pode ter
mexido na área dele.

## 4. Consolidação e revisão

* **Esperar todos os relatórios** antes de editar. Editar enquanto a banca lê confunde a avaliação.
* **Convergência é sinal forte:** quando dois ou três avaliadores independentes apontam o mesmo problema (aqui:
  custódia de chaves, CLI contornando regras, hashes sem sal), ele é tratado primeiro.
* **Conferir no código** antes de aceitar ou rebater um apontamento. Na rodada 1, a conferência confirmou um vazamento
  real no código atual (CPF em claro no pacote mascarado), que virou correção imediata (etapa W-0).
* **Corrigir, não maquiar:** quando o desenho promete algo que a tecnologia não entrega (ex.: "o Vault valida selos",
  "o worker só cifra"), declarar o risco residual ou criar o componente que entrega de fato (`assinador`, `chaveiro`).
* **Edições pontuais** a partir da v2, com substituições verificadas (cada trecho tem de existir exatamente uma vez),
  em vez de reescrever o documento inteiro.
* **Histórico de versões** no topo e **matriz de rastreabilidade** (Anexo C) com uma linha por bloqueante:
  `ponto → seção onde foi tratado`. É o que permite ao avaliador conferir a revisão sem reler às cegas.
* **Varredura de restos:** depois de cada revisão, procurar no texto referências antigas que ficaram inconsistentes
  (prazos, nomes de etapas, afirmações substituídas).

## 5. Histórico desta aplicação

| Avaliador | R1 (v1) | R2 (v2) | R3 (v3) | R4 (v4) |
| --- | --- | --- | --- | --- |
| Arquitetura | 6,5 | 8 | 8,5 | **9** |
| Segurança | 6 | 8 | 8,5 | **9** |
| Privacidade/LGPD | 6 | 8 | 9 | **9** (mantida) |
| UX e acessibilidade | 6 | 8,5 | 9 | **9** (mantida) |
| Perícia e auditoria | 6,5 | 8 | 8,5 | **9** |

Ajustes menores pedidos na R4, sem bloqueio, para antes do início da execução: tokens Vault das chaves `K_alvo`,
`K_historico` e `K_segredos` e alta disponibilidade do `chaveiro` (arquitetura); gatilho explícito e volume da classe
"tentativa com o identificador do alvo" (LGPD); contagem regressiva da preservação urgente, etiqueta da classe nova na
interface e identidade do aprovador no pedido recusado (UX).
Segurança e perícia pediram: contradição sobre tokens Vault, token OIDC do usuário validado pelo `chaveiro`, cobertura
e período de base no `--recalcular`, item de download duplicado. Os de texto foram corrigidos na hora; os demais ficaram
como "Pendências para a etapa D" no fim do Anexo C da proposta.

**Resultado: nota 9 nas cinco áreas na rodada 4.**

O que cada rodada trouxe de mais importante:

* **R1 → v2:** a v1 fazia afirmações erradas sobre o código (orçamento de carga "global", `consolidar()`
  reaproveitável, pacote "igual"). Entraram: modelo de ameaças, inventário completo de dado pessoal, cadeia de custódia
  desde a coleta, jornadas e navegação, direitos do titular, citações da LGPD corrigidas, cronograma com reserva.
* **R2 → v3:** custódia de chaves descrita com o risco residual real, `assinador` isolado, CLI de produção como cliente
  da API, compromissos com sal (a v2 tinha reaberto o vazamento por força bruta), ancoragem verificável por terceiro,
  inventário pós-expurgo, estados de tela e notificações.
* **R3 → v4:** `chaveiro` como porteiro das chaves, verificador que recalcula os números do relatório, classe própria
  para tentativas com o identificador do alvo, fundamento legal na lista para ofício, W0b com 3 semanas.

## 6. Lições

1. **A primeira versão sempre superestima o reaproveitamento.** Mandar a banca conferir o código com `arquivo:linha`
   foi o que derrubou as afirmações otimistas.
2. **Cada correção pode abrir outro problema.** O hash adicionado para tornar o pacote verificável (v2) virou oráculo de
   força bruta. Por isso a banca relê a proposta inteira em toda rodada, não só os trechos novos.
3. **Promessas sobre ferramentas de terceiros precisam ser checadas** (o que o Vault faz ou não faz). Quando a
   ferramenta não faz, o controle vira um componente próprio e um risco residual declarado.
4. **Avaliadores com contexto preservado** convergem mais rápido: na rodada seguinte eles conferem os próprios
   bloqueantes, em vez de começar do zero.
5. **Notas sobem em degraus de ~1,5, depois ~0,5.** A partir de 8,5, os bloqueantes são poucos e específicos. Vale
   aplicar também as melhorias opcionais baratas, que costumam ser o que separa 8,5 de 9.
6. **Problemas reais do código atual aparecem de brinde.** Registrá-los à parte (aqui, §1.2 da proposta) e corrigi-los
   antes de qualquer tela.

## 7. Custo

Cerca de 5 avaliadores × 4 rodadas, de 80 a 150 mil tokens por avaliador por rodada, e de 1,5 a 2,5 min de execução
por rodada, em paralelo. A consolidação e a revisão são o trabalho principal entre as rodadas.

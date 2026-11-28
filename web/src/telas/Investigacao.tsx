import { useEffect, useState } from 'react'
import { Link, NavLink, useLocation, useParams } from 'react-router'
import { ErroApi } from '../api/cliente'
import { comparacao, detalhe, linkPacote, pacotes as buscarPacotes, trilhaGlobal, urlDocumento, urlRelatorioAgregado,
  verificarCadeia } from '../api/rotas'
import type { Comparacao, Detalhe, ItemComparacao, Pacote } from '../api/tipos'
import { AcoesInvestigacao } from '../componentes/AcoesInvestigacao'
import { Acompanhamento } from '../componentes/Acompanhamento'
import { ErroTela, Esqueleto, Icone, Indicador, Mensagem, textoErro, Vazio } from '../componentes/Estado'
import { usePagina } from '../componentes/Pagina'
import { emColeta, indicador } from '../dominio/estados'
import { data, dataHora, duracao, numero } from '../dominio/formato'
import { useSessao } from '../sessao'
import { useCarregar } from '../usar'
import { ProvedorAnalise } from '../componentes/SessaoAnalise'
import { Cobertura, Contas, Dashboard, Eventos, VisaoAgregada } from './Analise'
import { TIPOS_PROCESSO } from './NovaSolicitacao'
import { ResultadoVerif } from '../componentes/Verificacao'

export type Aba = 'resumo' | 'dashboard' | 'eventos' | 'contas' | 'cobertura' | 'pacotes' | 'comparar' | 'trilha'

export function Investigacao({ aba }: { aba: Aba }) {
  const id = Number(useParams().id)
  const { tem } = useSessao()
  const local = useLocation()
  const avisoNav = (local.state as { aviso?: string } | null)?.aviso
  const { dados: d, erro, carregando, recarregar } = useCarregar((s) => detalhe(id, s), [id])
  // estados de passagem (na fila, preparando, fechando) não têm acompanhamento ao vivo: consulta o detalhe a cada 3 s
  const passagem = d ? Boolean(indicador(d.status).preparando) : false
  useEffect(() => {
    if (!passagem) return
    const t = setInterval(recarregar, 3000)
    return () => clearInterval(t)
  }, [passagem, recarregar])
  const nomeAba = { resumo: 'Resumo', dashboard: 'Dashboard', eventos: 'Eventos', contas: 'Contas', cobertura: 'Cobertura',
    pacotes: 'Pacotes', comparar: 'Comparar execuções', trilha: 'Trilha' }[aba]
  usePagina(`Investigação ${id} · ${nomeAba}`, [{ rotulo: 'Investigações', rota: '/investigacoes' },
    { rotulo: `nº ${id}`, rota: `/investigacoes/${id}` }, { rotulo: nomeAba }])

  if (carregando && !d) return <section><h1 id="titulo-tela" tabIndex={-1}>Investigação {id}</h1><Esqueleto linhas={8} rotulo="Carregando a investigação" /></section>
  if (erro || !d) {
    const semAcesso = erro instanceof ErroApi && ['sem_acesso', 'designacao', 'inexistente'].includes(erro.codigo)
    return semAcesso ? <ErroTela erro={erro} investigacao={id} />
      : <section><h1 id="titulo-tela" tabIndex={-1}>Investigação {id}</h1><ErroTela erro={erro} investigacao={id} tentar={recarregar} /></section>
  }

  const abas: { id: Aba; rotulo: string; rota: string }[] = [
    { id: 'resumo', rotulo: 'Resumo', rota: `/investigacoes/${id}` },
    ...(d.analise?.dados ? (['dashboard', 'eventos', 'contas', 'cobertura'] as Aba[]).map((a) => ({ id: a,
      rotulo: { dashboard: 'Dashboard', eventos: 'Eventos', contas: 'Contas', cobertura: 'Cobertura' }[a as 'dashboard'],
      rota: `/investigacoes/${id}/${a}` })) : []),
    ...(tem('solicitante', 'investigador', 'auditor_interno') ? [{ id: 'pacotes' as Aba, rotulo: 'Pacotes', rota: `/investigacoes/${id}/pacotes` }] : []),
    ...(d.acoes.includes('comparar') ? [{ id: 'comparar' as Aba, rotulo: 'Comparar', rota: `/investigacoes/${id}/comparar` }] : []),
    ...(tem('auditor_interno') ? [{ id: 'trilha' as Aba, rotulo: 'Trilha', rota: `/investigacoes/${id}/trilha` }] : []),
  ]

  return (
    <section className="investigacao">
      <header className="cabecalho-investigacao" aria-label="Cabeçalho da investigação">
        <div className="linha-titulo">
          <h1 id="titulo-tela" tabIndex={-1}>Investigação {d.id}</h1>
          <Indicador status={d.status} progresso={d.progresso_pct} />
        </div>
        <p className="meta">
          {d.alvo_mascarado && <span className="mono" aria-label={`Alvo ${d.alvo_mascarado}`}>{d.alvo_mascarado}</span>}
          <span>{data(d.de, d.fuso ?? undefined)} – {data(d.ate, d.fuso ?? undefined)} ({d.fuso ?? 'fuso não informado'})</span>
          {d.origem_externa && <span className="selo"><Icone nome="fa-file-import" /> Pedido externo</span>}
          {d.sigilosa && <span className="selo"><Icone nome="fa-user-secret" /> Sigilosa</span>}
        </p>
        <nav className="br-tab abas" aria-label="Seções da investigação">
          <ul className="tab-nav">
            {abas.map((a) => <li key={a.id} className={`tab-item${a.id === aba ? ' active' : ''}`}>
              <NavLink to={a.rota} end aria-current={a.id === aba ? 'page' : undefined}>{a.rotulo}</NavLink></li>)}
          </ul>
        </nav>
      </header>
      {avisoNav && <Mensagem tipo="success" papel="status">{avisoNav}</Mensagem>}
      {aba === 'resumo' && <Resumo d={d} recarregar={recarregar} />}
      {['dashboard', 'eventos', 'contas', 'cobertura'].includes(aba) && <ProvedorAnalise id={d.id} habilitado={Boolean(d.analise?.dados)}>
        {aba === 'dashboard' && <Dashboard d={d} />}
        {aba === 'eventos' && <Eventos d={d} />}
        {aba === 'contas' && <Contas d={d} />}
        {aba === 'cobertura' && <Cobertura d={d} />}
      </ProvedorAnalise>}
      {aba === 'pacotes' && <Pacotes d={d} recarregar={recarregar} />}
      {aba === 'comparar' && <Comparar d={d} />}
      {aba === 'trilha' && <TrilhaInvestigacao id={d.id} />}
    </section>
  )
}

function Resumo({ d, recarregar }: { d: Detalhe; recarregar: () => void }) {
  const { tem } = useSessao()
  const recusa = d.status === 'recusada' ? [...d.linha_do_tempo].reverse().find((p) => p.status === 'recusada') : undefined
  const devolucao = d.status === 'devolvida' ? [...d.linha_do_tempo].reverse().find((p) => p.status === 'devolvida') : undefined
  const tipoProc = TIPOS_PROCESSO.find((t) => t.id === d.tipo_processo)
  return <>
    <AcoesInvestigacao inv={d} aoMudar={recarregar} ocultar={['relatorio_agregado']} />
    {recusa && tem('solicitante') && <Mensagem tipo="danger" titulo="Pedido recusado.">
      Seu pedido foi recusado em {data(recusa.quando, d.fuso ?? undefined)}{recusa.por ? ` por ${recusa.por}` : ''}{recusa.motivo ? `: ${recusa.motivo}` : '.'}
      {' '}Você pode <Link to="/nova">abrir um novo pedido corrigido</Link>.</Mensagem>}
    {devolucao && <Mensagem tipo="warning" titulo="Devolvido para correção.">{devolucao.por ? `${devolucao.por}: ` : ''}{devolucao.motivo ?? 'veja a linha do tempo.'}</Mensagem>}
    {d.status === 'expurgada' && <Mensagem tipo="info">Esta investigação foi expurgada em {data(d.atualizado_em)}. Restam os metadados, o hash e a
      assinatura do manifesto e a verificação de pacotes.</Mensagem>}
    {d.status === 'preservacao_urgente' && <Mensagem tipo="info" titulo="Coleta lacrada.">Os eventos estão sendo coletados e cifrados, mas nenhuma tela de
      dados abre até a aprovação do pedido completo.{d.preservacao && <> Escalona ao coordenador em {dataHora(d.preservacao.escalona_em, d.fuso ?? undefined)};
      sem decisão, os dados são destruídos em {dataHora(d.preservacao.destroi_em, d.fuso ?? undefined)}{d.preservacao.prorrogada ? ' (prazo já prorrogado)' : ''}.</>}</Mensagem>}
    {emColeta(d.status) && d.status !== 'preservacao_urgente' && !indicador(d.status).preparando && <Acompanhamento id={d.id} fuso={d.fuso ?? undefined}
      aoMudarStatus={(s) => { if (s !== d.status) recarregar() }} />}
    {indicador(d.status).preparando && <Mensagem tipo="info" papel="status">Preparando a coleta… as tarefas aparecem aqui em instantes.</Mensagem>}

    {d.analise?.agregada && !d.analise.dados && <VisaoAgregada d={d} />}
    {d.analise?.dados && <Mensagem tipo="info">Os números, eventos e contas estão nas abas <Link to={`/investigacoes/${d.id}/dashboard`}>Dashboard</Link>,
      {' '}<Link to={`/investigacoes/${d.id}/eventos`}>Eventos</Link> e <Link to={`/investigacoes/${d.id}/contas`}>Contas</Link>.</Mensagem>}
    <div className="grade-resumo">
      <section className="br-card" aria-labelledby="t-pedido">
        <div className="card-header"><h2 id="t-pedido">Pedido</h2></div>
        <div className="card-content">
          <dl className="definicoes">
            {d.processo && <><dt>Nº do processo</dt><dd className="mono">{d.processo}</dd></>}
            {tipoProc && <><dt>Tipo de processo</dt><dd>{tipoProc.rotulo} <span className="secundario">(LGPD, {tipoProc.base})</span></dd></>}
            {d.solicitante && <><dt>Solicitante</dt><dd>{d.solicitante}</dd></>}
            {d.investigador && <><dt>Investigador designado</dt><dd>{d.investigador}</dd></>}
            {d.instancias && <><dt>Instâncias</dt><dd>{d.instancias.length ? d.instancias.join(', ') : 'Todas'}</dd></>}
            {d.granularidade && <><dt>Opções</dt><dd>por {d.granularidade}{d.varredura ? ', com varredura de falhas sem conta' : ''}
              {d.base_dias != null ? `, base de IP novo: ${d.base_dias} dias` : ''}</dd></>}
            {d.justificativa && <><dt>Justificativa</dt><dd>{d.justificativa}</dd></>}
            {d.origem && <><dt>Origem externa</dt><dd>{[d.origem.orgao, d.origem.documento, d.origem.fundamento, d.origem.destinatario &&
              `destinatário: ${d.origem.destinatario}`].filter(Boolean).join(' · ')}</dd></>}
            {d.documento && <><dt>Documento de origem</dt><dd>{d.documento.nome} · {numero(Math.round(d.documento.tamanho / 1024))} KB
              <br /><span className="mono hash" title="SHA-256">SHA-256 {d.documento.sha256.slice(0, 16)}…</span>
              {d.acoes.includes('baixar_documento') && <> · <a href={urlDocumento(d.id)} download>Baixar</a></>}</dd></>}
            {d.estimativa && <><dt>Estimativa</dt><dd>{numero(d.estimativa.tarefas)} tarefas · {duracao(d.estimativa.segundos)}</dd></>}
            {d.execucao_anterior && <><dt>Reexecução de</dt><dd><Link to={`/investigacoes/${d.execucao_anterior}`}>investigação nº {d.execucao_anterior}</Link>
              {d.acoes.includes('comparar') && <> · <Link to={`/investigacoes/${d.id}/comparar`}>comparar execuções</Link></>}</dd></>}
            {d.reexecucoes && d.reexecucoes.length > 0 && <><dt>Reexecuções</dt><dd>{d.reexecucoes.map((n, k) => <span key={n}>{k > 0 && ', '}
              <Link to={`/investigacoes/${n}`}>nº {n}</Link></span>)}</dd></>}
            <dt>Criada em</dt><dd>{dataHora(d.criado_em, d.fuso ?? undefined)}</dd>
          </dl>
        </div>
      </section>
      <section className="br-card" aria-labelledby="t-linha">
        <div className="card-header"><h2 id="t-linha">Linha do tempo</h2></div>
        <div className="card-content">
          {d.linha_do_tempo.length === 0 ? <Vazio>Sem registros ainda.</Vazio> : (
            <ol className="linha-do-tempo">
              {d.linha_do_tempo.map((p, k) => (
                <li key={k}>
                  <span className="quando">{dataHora(p.quando, d.fuso ?? undefined)}</span>
                  <span className="o-que">{MAPA_ACAO[p.status] ? MAPA_ACAO[p.status] : indicador(p.status).rotulo}</span>
                  {p.por && <span className="por">por {p.por}</span>}
                  {p.motivo && <span className="motivo">“{p.motivo}”</span>}
                </li>
              ))}
            </ol>
          )}
        </div>
      </section>
    </div>
    {d.expiracao.length > 0 && (
      <section className="br-card" aria-labelledby="t-exp">
        <div className="card-header"><h2 id="t-exp">Expiração dos eventos na origem</h2></div>
        <div className="card-content br-table">
          <table>
            <thead><tr><th scope="col">Instância</th><th scope="col">Realm</th><th scope="col">Eventos desde</th><th scope="col">Situação</th></tr></thead>
            <tbody>{d.expiracao.map((e) => <tr key={`${e.instancia}/${e.realm}`}><td>{e.instancia}</td><td>{e.realm}</td>
              <td>{e.eventos_desde ? data(e.eventos_desde, d.fuso ?? undefined) : 'Sem eventos gravados'}</td>
              <td>{e.expira_antes_da_aprovacao ? <span className="estado tom-ambar"><Icone nome="fa-hourglass-end" /> Expira antes da aprovação</span>
                : <span className="estado tom-verde"><Icone nome="fa-check" /> Dentro do prazo</span>}</td></tr>)}</tbody>
          </table>
        </div>
      </section>
    )}
  </>
}

/** Ações da trilha do W1 (linha do tempo vinda da trilha) em texto simples. */
const MAPA_ACAO: Record<string, string> = { pedir_investigacao: 'Pedido registrado', aprovar_investigacao: 'Aprovada',
  devolver_investigacao: 'Devolvida', recusar_investigacao: 'Recusada', iniciar_coleta: 'Coleta iniciada', pausar: 'Pausada',
  retomar: 'Retomada', cancelar: 'Cancelada', pedir_pacote: 'Pacote pedido', abrir: 'Aberta', fechar: 'Fechada' }

function Pacotes({ d, recarregar }: { d: Detalhe; recarregar: () => void }) {
  const { dados, erro, carregando, recarregar: recarregarLista } = useCarregar(() => buscarPacotes(d.id), [d.id])
  const [links, setLinks] = useState<Record<number, { link?: string; expira_em?: string; erro?: string }>>({})
  const acoesPacote = d.acoes.filter((a) => a === 'gerar_pacote' || a === 'pedir_sem_mascara' || a === 'relatorio_agregado')
  const gerando = (dados ?? []).some((p) => p.status === 'gerando')
  useEffect(() => {
    if (!gerando) return
    const t = setInterval(recarregarLista, 4000)
    return () => clearInterval(t)
  }, [gerando, recarregarLista])
  async function gerarLink(p: Pacote) {
    try { const r = await linkPacote(p.pacote); setLinks((l) => ({ ...l, [p.pacote]: r })) }
    catch (e) { setLinks((l) => ({ ...l, [p.pacote]: { erro: e instanceof ErroApi && e.status === 410 ? e.message : textoErro(e) } })) }
  }
  const expirado = (p: Pacote) => Boolean(p.expira_em && new Date(p.expira_em).getTime() < Date.now()) || p.status === 'expirado'
  const soInvestigador = erro instanceof ErroApi && (erro.status === 404 || erro.status === 403)
  return <>
    <AcoesInvestigacao inv={{ ...d, acoes: acoesPacote }} aoMudar={() => { recarregar(); recarregarLista() }} />
    {carregando && !dados ? <Esqueleto linhas={3} rotulo="Carregando pacotes" /> : soInvestigador
      ? <Mensagem tipo="info">Os pacotes de evidência desta investigação ficam com o investigador designado.
        {d.acoes.includes('relatorio_agregado') ? <> Para você, o <a href={urlRelatorioAgregado(d.id)} download>relatório agregado em PDF</a>:
          estado, cobertura, totais e séries por dia e por aplicação, sem dados individuais.</>
          : ' O relatório agregado fica disponível quando a coleta termina.'}</Mensagem>
      : erro ? <ErroTela erro={erro} tentar={recarregarLista} />
      : !dados?.length ? <Vazio>Nenhum pacote gerado ainda.</Vazio> : <>
        <p className="secundario">Cada pacote é imutável e versionado. Logo depois de gerado, ele passa pelo verificador offline
          (o mesmo que o perito usa: <code>kc-verificar</code>), que confere assinatura, carimbo do tempo, hashes, cadeia de custódia e
          recalcula os resultados.</p>
        <div className="br-table tabela-rolavel" tabIndex={0} role="region" aria-label="Pacotes">
          <table>
            <thead><tr><th scope="col">Pacote</th><th scope="col">Tipo</th><th scope="col">Estado</th><th scope="col">Verificação</th>
              <th scope="col">Criado</th><th scope="col">Download</th></tr></thead>
            <tbody>{dados.map((p) => {
              const l = links[p.pacote]
              return (
                <tr key={p.pacote}>
                  <td><span className="mono">{p.nome ?? `pacote ${p.pacote}`}</span>
                    {p.formato && <span className="secundario"> · formato {p.formato}{p.eventos != null ? ` · ${numero(p.eventos)} eventos` : ''}</span>}
                    {p.manifesto_sha256 && <><br /><span className="mono hash" title="SHA-256 do manifesto">manifesto {p.manifesto_sha256.slice(0, 16)}…</span></>}</td>
                  <td>{p.sem_mascara ? <span className="estado tom-vermelho"><Icone nome="fa-eye" /> Sem máscara</span>
                    : <span className="estado tom-azul"><Icone nome="fa-mask" /> Mascarado</span>}</td>
                  <td>{expirado(p) ? 'Expirado' : { pronto: 'Pronto', gerando: 'Gerando…', falhou: 'Falhou' }[p.status] ?? p.status}</td>
                  <td className="celula-verificacao">{p.verificacao ? <ResultadoVerif r={p.verificacao} titulo={`Pacote ${p.nome ?? p.pacote}`} compacto />
                    : p.status === 'pronto' ? <span className="secundario">Pacote de formato 1 (anterior à W5)</span> : '—'}</td>
                  <td>{dataHora(p.criado_em)}</td>
                  <td>{expirado(p) ? <span>O pacote sem máscara ficou disponível por 24 h e foi apagado. Peça novamente.</span>
                    : l?.link ? <span><a className="br-button small primary" href={l.link} download>Baixar {p.nome ?? `pacote ${p.pacote}`}</a>
                      <span className="secundario"> uso único, vale até {dataHora(l.expira_em)}</span></span>
                    : l?.erro ? <span role="alert">{l.erro}</span>
                    : p.status === 'pronto' || p.sha256 ? <button type="button" className="br-button small secondary" onClick={() => gerarLink(p)}>
                      Gerar link de download<span className="sr-only"> do pacote {p.nome ?? p.pacote}</span></button>
                    : p.status === 'falhou' ? 'Falhou' : 'Gerando…'}</td>
                </tr>
              )
            })}</tbody>
          </table>
        </div>
      </>}
  </>
}

function ListaComparacao({ titulo, id, itens, total, fuso, vazio }: { titulo: string; id: string; itens: ItemComparacao[]; total: number;
  fuso?: string; vazio: string }) {
  return (
    <section className="br-card" aria-labelledby={id}>
      <div className="card-header"><h2 id={id}>{titulo} <span className="secundario">({numero(total)})</span></h2></div>
      <div className="card-content">
        {!itens.length ? <Vazio>{vazio}</Vazio> : <>
          {total > itens.length && <p className="secundario">Mostrando os {numero(itens.length)} primeiros de {numero(total)}.</p>}
          <div className="br-table tabela-rolavel" tabIndex={0} role="region" aria-label={titulo}>
            <table><thead><tr><th scope="col">Horário</th><th scope="col">Evento</th><th scope="col">Instância / realm</th>
              <th scope="col">Conta</th><th scope="col">IP</th></tr></thead>
              <tbody>{itens.map((e, k) => <tr key={k}><td>{dataHora(e.horario, fuso)}</td><td className="mono">{e.tipo}</td>
                <td>{e.instancia} / {e.realm}</td><td>{e.conta}</td><td>{e.ip ?? '—'}</td></tr>)}</tbody></table>
          </div>
        </>}
      </div>
    </section>
  )
}

/** Comparar execuções (§6.7): só rótulos herdados da execução de origem; IP 12 é o mesmo IP nas duas colunas. */
function Comparar({ d }: { d: Detalhe }) {
  const [recalc, setRecalc] = useState(0)
  const { dados: c, erro, carregando } = useCarregar((s) => comparacao(d.id, recalc > 0, s), [d.id, recalc])
  const fuso = d.fuso ?? undefined
  if (carregando && !c) return <Esqueleto linhas={6} rotulo="Comparando as execuções" />
  if (erro || !c) return <ErroTela erro={erro} tentar={() => setRecalc((n) => n + 1)} />
  const t = c.totais
  const cob = (x: Comparacao['cobertura']['antes']) => `realms ${x.realms[0]}/${x.realms[1]} · dias ${x.tempo[0]}/${x.tempo[1]}${x.completa ? ' (completa)' : ''}`
  return <>
    <p>Comparação com a <Link to={`/investigacoes/${c.anterior}`}>investigação nº {c.anterior}</Link> (execução de origem), no período comum
      de {dataHora(c.periodo_comum.de, fuso)} a {dataHora(c.periodo_comum.ate, fuso)}. Os eventos são casados pelo id original;
      os rótulos são os da execução de origem. Calculado em {dataHora(c.calculado_em, fuso)}.{' '}
      <button type="button" className="br-button small secondary" onClick={() => setRecalc((n) => n + 1)}>Recalcular</button></p>
    <div className="kpis" role="list" aria-label="Totais da comparação">
      {[['Eventos na origem', t.anterior], ['Eventos nesta execução', t.atual], ['Novos no período comum', t.novos_no_periodo_comum],
        ['Deixaram de existir', t.deixaram_de_existir], ['Conteúdo diferente', t.conteudo_diferente], ['Possível alteração', t.possivel_alteracao]]
        .map(([r, v]) => <div key={r as string} className="kpi" role="listitem"><span className="kpi-rotulo">{r}</span>
          <span className="kpi-valor">{numero(v as number)}</span></div>)}
    </div>
    {(t.deixaram_de_existir > 0 || t.conteudo_diferente > 0 || t.possivel_alteracao > 0) && <Mensagem tipo="warning">
      Há eventos que deixaram de existir na origem (expirados pela retenção ou apagados) ou com conteúdo diferente entre as duas
      leituras. Isso é um indício para análise, não uma conclusão: o Keycloak pode ter expirado os eventos pela retenção configurada.</Mensagem>}
    <ListaComparacao titulo="Eventos novos no período comum" id="c-novos" itens={c.novos} total={t.novos_no_periodo_comum} fuso={fuso}
      vazio="Nenhum evento novo no período comum." />
    <ListaComparacao titulo="Eventos que deixaram de existir na origem" id="c-sumidos" itens={c.deixaram_de_existir}
      total={t.deixaram_de_existir} fuso={fuso} vazio="Nenhum evento da execução de origem sumiu." />
    <ListaComparacao titulo="Eventos com conteúdo diferente" id="c-dif" itens={c.conteudo_diferente} total={t.conteudo_diferente}
      fuso={fuso} vazio="Nenhum evento com conteúdo diferente." />
    {t.possivel_alteracao > 0 && <ListaComparacao titulo="Possível alteração (Keycloak 21 ou anterior)" id="c-pos"
      itens={c.possivel_alteracao} total={t.possivel_alteracao} fuso={fuso} vazio="" />}
    <div className="grade-resumo">
      <section className="br-card" aria-labelledby="c-contas">
        <div className="card-header"><h2 id="c-contas">Contas</h2></div>
        <div className="card-content">
          <dl className="definicoes">
            <dt>Novas nesta execução</dt><dd>{c.contas.novas.length ? c.contas.novas.map((x) => `${x.conta} (${x.instancia}/${x.realm})`).join('; ') : 'nenhuma'}</dd>
            <dt>Não encontradas nesta execução</dt><dd>{c.contas.nao_encontradas.length ? c.contas.nao_encontradas.map((x) => `${x.conta} (${x.instancia}/${x.realm})`).join('; ') : 'nenhuma'}</dd>
            <dt>Inclusão mudou</dt><dd>{c.contas.inclusao_mudou.length ? c.contas.inclusao_mudou.map((x) => `${x.conta}: ${x.incluida ? 'incluída' : 'excluída'}`).join('; ') : 'nenhuma'}</dd>
          </dl>
        </div>
      </section>
      <section className="br-card" aria-labelledby="c-cob">
        <div className="card-header"><h2 id="c-cob">Cobertura</h2></div>
        <div className="card-content">
          <dl className="definicoes">
            <dt>Origem</dt><dd>{cob(c.cobertura.antes)}</dd>
            <dt>Esta execução</dt><dd>{cob(c.cobertura.depois)}</dd>
            <dt>Mudanças</dt><dd>{c.cobertura.mudancas.length ? c.cobertura.mudancas.map((m) => `${m.instancia}/${m.realm}: ${m.antes ?? '—'} → ${m.depois ?? '—'}`).join('; ') : 'nenhuma'}</dd>
          </dl>
        </div>
      </section>
    </div>
  </>
}

function TrilhaInvestigacao({ id }: { id: number }) {
  const { dados, erro, carregando, recarregar } = useCarregar(() => trilhaGlobal(id), [id])
  const [verif, setVerif] = useState<string | null>(null)
  return <>
    <div className="acoes-botoes"><button type="button" className="br-button secondary" onClick={() => verificarCadeia(id)
      .then((r) => setVerif(r.integras === r.cadeias ? `Cadeia íntegra (${r.cadeias} verificada${r.cadeias === 1 ? '' : 's'}).`
        : `Problemas em ${r.cadeias - r.integras} de ${r.cadeias} cadeias.`)).catch((e) => setVerif(textoErro(e)))}>
      <Icone nome="fa-link" /> Verificar cadeia</button></div>
    <div aria-live="polite">{verif && <Mensagem tipo={verif.startsWith('Cadeia íntegra') ? 'success' : 'warning'}>{verif}</Mensagem>}</div>
    {carregando && !dados ? <Esqueleto linhas={4} /> : erro ? <ErroTela erro={erro} tentar={recarregar} /> : !dados?.length ? <Vazio>Sem registros.</Vazio> : (
      <div className="br-table tabela-rolavel" tabIndex={0} role="region" aria-label="Trilha da investigação">
        <table><thead><tr><th scope="col">Seq.</th><th scope="col">Quando</th><th scope="col">Ação</th><th scope="col">Operador</th><th scope="col">Hash</th></tr></thead>
          <tbody>{dados.map((r) => <tr key={`${r.cadeia}-${r.seq}`}><td>{r.seq}</td><td>{dataHora(r.quando)}</td><td>{r.acao}</td>
            <td className="mono">{r.operador}</td><td className="mono hash">{r.hash.slice(0, 12)}…</td></tr>)}</tbody></table>
      </div>
    )}
  </>
}

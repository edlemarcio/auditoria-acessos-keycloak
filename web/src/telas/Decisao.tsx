import { useState, type FormEvent } from 'react'
import { Link, useParams, useSearchParams } from 'react-router'
import * as R from '../api/revelacao'
import { aprovacoes, decidirPacote, detalhe } from '../api/rotas'
import type { Detalhe } from '../api/tipos'
import { tomarRetomada } from '../armazenamento'
import { AcoesInvestigacao } from '../componentes/AcoesInvestigacao'
import { Area } from '../componentes/Campo'
import { ErroTela, Esqueleto, Icone, Indicador, Mensagem, textoErro } from '../componentes/Estado'
import { Titulo, usePagina } from '../componentes/Pagina'
import { pareceIdentificador } from '../dominio/documentos'
import { data, dataHora, duracao, numero } from '../dominio/formato'
import { useCarregar } from '../usar'
import { TIPO_PEDIDO } from './Aprovacoes'
import { TIPOS_PROCESSO } from './NovaSolicitacao'

/** Tela de decisão (§4.4): tudo o que o aprovador precisa ver, nunca os valores. */
export function Decisao() {
  const pedido = Number(useParams().pedido)
  const [sp] = useSearchParams()
  const inv = Number(sp.get('inv'))
  const tipo = sp.get('tipo') ?? 'investigacao'
  const t = TIPO_PEDIDO[tipo] ?? { rotulo: tipo, icone: 'fa-question' }
  usePagina(`Decisão · pedido ${pedido}`, [{ rotulo: 'Aprovações', rota: '/aprovacoes' }, { rotulo: `Pedido ${pedido}` }])
  const revelacao = (R.TIPOS_REVELACAO as readonly string[]).includes(tipo)
  const { dados: d, erro, carregando, recarregar } = useCarregar((s) => (revelacao ? Promise.resolve(null) : detalhe(inv, s)), [inv, revelacao])
  if (revelacao) return (
    <section className="decisao">
      <Titulo><Icone nome={t.icone} /> {t.rotulo} · investigação {inv}</Titulo>
      <DecisaoRevelacao pedido={pedido} />
    </section>
  )

  return (
    <section className="decisao">
      <Titulo><Icone nome={t.icone} /> {t.rotulo} · investigação {inv}</Titulo>
      {carregando && !d ? <Esqueleto linhas={8} rotulo="Carregando o pedido" /> : erro || !d ? <ErroTela erro={erro} investigacao={inv} tentar={recarregar} />
        : tipo === 'pacote_sem_mascara' ? <DecisaoPacote pedido={pedido} d={d} /> : <DecisaoInvestigacao d={d} recarregar={recarregar} />}
    </section>
  )
}

function Escopo({ d }: { d: Detalhe }) {
  const tp = TIPOS_PROCESSO.find((x) => x.id === d.tipo_processo)
  return (
    <section className="br-card" aria-labelledby="t-escopo">
      <div className="card-header linha-titulo"><h2 id="t-escopo">Escopo</h2><Indicador status={d.status} /></div>
      <div className="card-content">
        <dl className="definicoes">
          <dt>Identificador</dt><dd className="mono">{d.alvo_mascarado ?? '—'}</dd>
          <dt>Período</dt><dd>{data(d.de, d.fuso ?? undefined)} a {data(d.ate, d.fuso ?? undefined)} ({d.fuso})</dd>
          <dt>Instâncias</dt><dd>{d.instancias?.length ? d.instancias.join(', ') : 'Todas'}</dd>
          <dt>Opções</dt><dd>por {d.granularidade ?? 'dia'}{d.varredura ? ', com varredura de falhas sem conta' : ''}, base de IP novo: {d.base_dias ?? 0} dias</dd>
          <dt>Nº do processo</dt><dd className="mono">{d.processo ?? '—'}</dd>
          <dt>Tipo de processo</dt><dd>{tp ? `${tp.rotulo} (LGPD, ${tp.base})` : '—'}</dd>
          <dt>Solicitante</dt><dd>{d.solicitante ?? '—'}</dd>
          <dt>Justificativa</dt><dd>{d.justificativa ?? '—'}</dd>
          {d.origem && <><dt>Pedido externo</dt><dd>{d.origem.orgao} · {d.origem.documento}<br />Fundamento: {d.origem.fundamento}
            {d.origem.destinatario && <><br />Destinatário: {d.origem.destinatario}</>}</dd></>}
          <dt>Documento de origem</dt><dd>{d.documento ? <>{d.documento.nome} ({numero(Math.round(d.documento.tamanho / 1024))} KB)
            <span className="mono hash"> SHA-256 {d.documento.sha256.slice(0, 16)}…</span></> : 'Não anexado'}</dd>
          <dt>Estimativa</dt><dd>{d.estimativa ? `${numero(d.estimativa.tarefas)} tarefas · ${duracao(d.estimativa.segundos)}` : '—'}</dd>
        </dl>
      </div>
    </section>
  )
}

function DecisaoInvestigacao({ d, recarregar }: { d: Detalhe; recarregar: () => void }) {
  const risco = d.expiracao.filter((e) => e.expira_antes_da_aprovacao)
  return <>
    {risco.length > 0 && <Mensagem tipo="warning" titulo="Eventos expiram antes do prazo de aprovação:">
      {risco.map((e) => `${e.instancia}/${e.realm} (desde ${data(e.eventos_desde, d.fuso ?? undefined)})`).join('; ')}.
      {d.acoes.includes('autorizar_preservacao') && ' Você pode autorizar a preservação urgente (coleta lacrada) agora e decidir o pedido completo depois.'}</Mensagem>}
    {d.status === 'preservacao_urgente' && d.preservacao && <Mensagem tipo="info" titulo="Coleta lacrada em andamento.">
      Escalona ao coordenador em {dataHora(d.preservacao.escalona_em, d.fuso ?? undefined)}; sem decisão, os dados são destruídos em
      {' '}{dataHora(d.preservacao.destroi_em, d.fuso ?? undefined)}.</Mensagem>}
    <div className="grade-decisao">
      <Escopo d={d} />
      <section className="br-card" aria-labelledby="t-exp">
        <div className="card-header"><h2 id="t-exp">Expiração por realm</h2></div>
        <div className="card-content br-table">
          {d.expiracao.length === 0 ? <p>Sem dados de expiração (sondas ainda não rodaram).</p> : <table>
            <thead><tr><th scope="col">Instância/realm</th><th scope="col">Eventos desde</th><th scope="col">Situação</th></tr></thead>
            <tbody>{d.expiracao.map((e) => <tr key={`${e.instancia}/${e.realm}`}><td>{e.instancia}/{e.realm}</td>
              <td>{e.eventos_desde ? data(e.eventos_desde, d.fuso ?? undefined) : 'Sem eventos'}</td>
              <td>{e.expira_antes_da_aprovacao ? <span className="estado tom-ambar"><Icone nome="fa-hourglass-end" /> Expira antes</span>
                : <span className="estado tom-verde"><Icone nome="fa-check" /> OK</span>}</td></tr>)}</tbody>
          </table>}
        </div>
      </section>
    </div>
    <section className="br-card" aria-labelledby="t-decidir">
      <div className="card-header"><h2 id="t-decidir">Decidir</h2></div>
      <div className="card-content">
        {d.acoes.length === 0 ? <Mensagem tipo="info">Não há decisão sua pendente neste pedido. <Link to={`/investigacoes/${d.id}`}>Ver investigação</Link></Mensagem>
          : <AcoesInvestigacao inv={d} aoMudar={recarregar} />}
      </div>
    </section>
  </>
}

function DecisaoPacote({ pedido, d }: { pedido: number; d: Detalhe }) {
  const { dados: fila } = useCarregar(aprovacoes, [])
  const item = fila?.find((f) => f.pedido === pedido)
  const [motivo, setMotivo] = useState('')
  const [erro, setErro] = useState<string | null>(null)
  const [feito, setFeito] = useState<string | null>(null)
  const [retomada] = useState(() => Boolean(tomarRetomada(location.pathname, (a) => a === `decidir_${pedido}`)))

  async function decidir(aprovar: boolean, e?: FormEvent) {
    e?.preventDefault()
    if (motivo.trim().length < 5) return setErro('Escreva o motivo da decisão (pelo menos 5 caracteres).')
    if (pareceIdentificador(motivo)) return setErro('Não escreva CPF ou título no motivo.')
    setErro(null)
    try {
      await decidirPacote(pedido, aprovar, motivo)
      setFeito(aprovar ? 'Pacote sem máscara aprovado. Ele fica disponível por 24 h para o investigador.' : 'Pedido de pacote sem máscara recusado.')
    } catch (x) { setErro(textoErro(x)) }
  }
  const par = (item?.parametros ?? {}) as Record<string, unknown>
  return <>
    <div className="grade-decisao">
      <Escopo d={d} />
      <section className="br-card" aria-labelledby="t-pac">
        <div className="card-header"><h2 id="t-pac">Pacote pedido</h2></div>
        <div className="card-content">
          <dl className="definicoes">
            <dt>Destinatário e destino</dt><dd>{String(par.destino ?? '—')}</dd>
            {par.arquivos != null && <><dt>Arquivos</dt><dd>{String(par.arquivos)}</dd></>}
            {par.eventos != null && <><dt>Eventos</dt><dd>{numero(Number(par.eventos))}</dd></>}
            <dt>Fundamento do pedido externo</dt><dd>{d.origem?.fundamento ?? 'Pedido interno'}</dd>
          </dl>
        </div>
      </section>
    </div>
    <section className="br-card" aria-labelledby="t-decpac">
      <div className="card-header"><h2 id="t-decpac">Decidir</h2></div>
      <div className="card-content">
        {retomada && !feito && <Mensagem tipo="info" papel="status">Identidade confirmada. Escreva o motivo e confirme de novo.</Mensagem>}
        {feito ? <Mensagem tipo="success" papel="status">{feito} <Link to="/aprovacoes">Voltar à fila</Link></Mensagem> : (
          <form onSubmit={(e) => decidir(true, e)} noValidate className="form-estreito">
            <Area rotulo="Motivo da decisão" obrigatorio rows={3} value={motivo} onChange={(e) => setMotivo(e.target.value)} erro={erro}
              ajuda="Fica na trilha. O pacote sem máscara só pode ir para quem requisitou com fundamento." />
            <div className="acoes-botoes">
              <button type="submit" className="br-button primary"><Icone nome="fa-check" /> Aprovar pacote sem máscara</button>
              <button type="button" className="br-button secondary perigo" onClick={() => decidir(false)}><Icone nome="fa-ban" /> Recusar</button>
            </div>
          </form>
        )}
      </div>
    </section>
  </>
}

const NOME_CLASSE: Record<string, string> = { conta: 'contas', ip: 'IPs', sessao: 'sessões', evento: 'eventos completos' }

/** Pedido de revelação (acima da cota, de terceiro, total) ou lista para ofício (§4.4): quantidade, classe, motivos,
 * fundamento e histórico do investigador. Nunca os valores. */
function DecisaoRevelacao({ pedido }: { pedido: number }) {
  const { dados: p, erro: erroCarga, carregando, recarregar } = useCarregar((s) => R.detalhePedido(pedido, s), [pedido])
  const [motivo, setMotivo] = useState('')
  const [erro, setErro] = useState<string | null>(null)
  const [feito, setFeito] = useState<string | null>(null)
  const [retomada] = useState(() => Boolean(tomarRetomada(location.pathname, (a) => a === `decidir_${pedido}`)))
  if (carregando && !p) return <Esqueleto linhas={6} rotulo="Carregando o pedido" />
  if (erroCarga || !p) return <ErroTela erro={erroCarga} tentar={recarregar} />
  async function decidir(aprovar: boolean, e?: FormEvent) {
    e?.preventDefault()
    if (motivo.trim().length < 5) return setErro('Escreva o motivo da decisão (pelo menos 5 caracteres).')
    if (pareceIdentificador(motivo)) return setErro('Não escreva CPF ou título no motivo.')
    setErro(null)
    try {
      await R.decidir(pedido, aprovar, motivo)
      setFeito(aprovar ? `${p!.nome[0].toUpperCase()}${p!.nome.slice(1)} aprovada.` : 'Pedido recusado.')
    } catch (x) { setErro(textoErro(x)) }
  }
  const aguardando = p.status === 'aguardando'
  return <>
    <div className="grade-decisao">
      <section className="br-card" aria-labelledby="t-rev">
        <div className="card-header"><h2 id="t-rev">O que foi pedido</h2></div>
        <div className="card-content">
          <dl className="definicoes">
            <dt>Investigador</dt><dd>{p.investigador ?? '—'}</dd>
            <dt>Pedido em</dt><dd>{dataHora(p.criado_em)}</dd>
            <dt>Quantidade</dt><dd>{p.tipo === 'revelacao_total' ? `todos os itens (${numero(p.volume_investigacao)} eventos na investigação)`
              : `${numero(p.quantidade)} item(ns): ${Object.entries(p.por_classe).map(([k, v]) => `${v} ${NOME_CLASSE[k] ?? k}`).join(', ')}`}</dd>
            {p.terceiros > 0 && <><dt>Dado de terceiro</dt><dd>{p.terceiros} item(ns) de outras pessoas (varredura de falhas)</dd></>}
            <dt>Motivo do pedido</dt><dd>{p.motivo ?? '—'}</dd>
            {p.motivo_sessao && <><dt>Motivo da sessão de análise</dt><dd>{p.motivo_sessao}</dd></>}
            {p.fundamento && <><dt>Fundamento</dt><dd>{p.fundamento}</dd></>}
            {p.destinatario && <><dt>Destinatário</dt><dd>{p.destinatario}</dd></>}
            {p.rotulos.length > 0 && <><dt>Itens (pseudônimos)</dt><dd>{p.rotulos.join(', ')}</dd></>}
          </dl>
          {p.avisos.map((a) => <Mensagem key={a} tipo="warning">{a}</Mensagem>)}
        </div>
      </section>
      <section className="br-card" aria-labelledby="t-hist">
        <div className="card-header"><h2 id="t-hist">Revelações já feitas por este investigador nesta investigação</h2></div>
        <div className="card-content">
          {!p.historico.length ? <p>Nenhuma.</p> : <div className="br-table"><table>
            <thead><tr><th scope="col">Classe</th><th scope="col" className="num">Quantidade</th><th scope="col" className="num">De terceiro</th>
              <th scope="col">Motivos das sessões</th></tr></thead>
            <tbody>{p.historico.map((h) => <tr key={h.classe}><td>{NOME_CLASSE[h.classe] ?? h.classe}</td><td className="num">{numero(h.n)}</td>
              <td className="num">{numero(h.terceiros)}</td><td>{h.motivos.join(', ')}</td></tr>)}</tbody>
          </table></div>}
        </div>
      </section>
    </div>
    <section className="br-card" aria-labelledby="t-decrev">
      <div className="card-header"><h2 id="t-decrev">Decidir</h2></div>
      <div className="card-content">
        {retomada && !feito && <Mensagem tipo="info" papel="status">Identidade confirmada. Escreva o motivo e confirme de novo.</Mensagem>}
        {feito ? <Mensagem tipo="success" papel="status">{feito} <Link to="/aprovacoes">Voltar à fila</Link></Mensagem>
          : !aguardando ? <Mensagem tipo="info">Este pedido já foi decidido ({p.status}).</Mensagem> : (
          <form onSubmit={(e) => decidir(true, e)} noValidate className="form-estreito">
            <Area rotulo="Motivo da decisão" obrigatorio rows={3} value={motivo} onChange={(e) => setMotivo(e.target.value)} erro={erro}
              ajuda="Fica na trilha. Você não vê os valores; o investigador só os vê enquanto a sessão de análise estiver ativa." />
            <div className="acoes-botoes">
              <button type="submit" className="br-button primary"><Icone nome="fa-check" /> Aprovar</button>
              <button type="button" className="br-button secondary perigo" onClick={() => decidir(false)}><Icone nome="fa-ban" /> Recusar</button>
            </div>
          </form>
        )}
      </div>
    </section>
  </>
}

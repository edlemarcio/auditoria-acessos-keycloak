/**
 * Telas da análise (W3, PROPOSTA_WEB §7.3, §7.6, §7.7, §7.12): Dashboard, Eventos, Contas, Cobertura e a visão
 * agregada do solicitante. Filtros técnicos e rótulos de pseudônimo vão na URL (para compartilhar uma visão); valores
 * reais nunca. Clicar num ponto do gráfico, num destaque, num IP ou numa aplicação abre Eventos já filtrado.
 */
import { useEffect, useMemo, useState } from 'react'
import { Link, useNavigate, useSearchParams } from 'react-router'
import * as A from '../api/analise'
import type { Detalhe } from '../api/tipos'
import { gravarPrefEventos, lerPrefEventos } from '../armazenamento'
import { Area } from '../componentes/Campo'
import { Dialogo } from '../componentes/Dialogo'
import { ErroTela, Esqueleto, Icone, Mensagem, textoErro, Vazio } from '../componentes/Estado'
import { Barras, GraficoSerie, MapaCalor } from '../componentes/Graficos'
import { data, dataHora, numero } from '../dominio/formato'
import { useCarregar } from '../usar'

// ------------------------------------------------------------------ fuso: janela local → UTC
function deslocamento(fuso: string, utcMs: number): number {
  const p = Object.fromEntries(new Intl.DateTimeFormat('en-US', { timeZone: fuso, hourCycle: 'h23', year: 'numeric',
    month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit', second: '2-digit' })
    .formatToParts(new Date(utcMs)).filter((x) => x.type !== 'literal').map((x) => [x.type, Number(x.value)]))
  return Date.UTC(p.year, p.month - 1, p.day, p.hour, p.minute, p.second) - utcMs
}

/** "2026-06-01T00:00:00" no fuso da investigação → ms UTC. */
export function localParaUtc(naive: string, fuso: string): number {
  const [d, t = '00:00:00'] = naive.split('T')
  const [y, m, dd] = d.split('-').map(Number)
  const [hh, mi, ss] = t.split(':').map((v) => Number(v.slice(0, 2)))
  const chute = Date.UTC(y, m - 1, dd, hh, mi, ss || 0)
  const o1 = deslocamento(fuso, chute)
  const o2 = deslocamento(fuso, chute - o1)
  return chute - o2
}

function proximaJanela(naive: string, gran: string): string {
  const [d] = naive.split('T')
  const [y, m, dd] = d.split('-').map(Number)
  const h = Number(naive.split('T')[1]?.slice(0, 2) ?? 0)
  const base = new Date(Date.UTC(y, m - 1, dd, h))
  if (gran === 'hora') base.setUTCHours(base.getUTCHours() + 1)
  else if (gran === 'semana') base.setUTCDate(base.getUTCDate() + 7)
  else if (gran === 'mes') base.setUTCMonth(base.getUTCMonth() + 1)
  else base.setUTCDate(base.getUTCDate() + 1)
  return base.toISOString().slice(0, 19)
}

function rotuloJanela(naive: string, gran: string, longo = false): string {
  const [d, t] = naive.split('T')
  const [y, m, dd] = d.split('-')
  if (gran === 'mes') return `${m}/${y}`
  if (gran === 'hora') return longo ? `${dd}/${m}/${y} ${t.slice(0, 5)}` : `${dd}/${m} ${t.slice(0, 2)}h`
  if (gran === 'semana') return longo ? `semana de ${dd}/${m}/${y}` : `${dd}/${m}`
  return longo ? `${dd}/${m}/${y}` : `${dd}/${m}`
}

// ------------------------------------------------------------------ peças comuns
const NOMES_FILTRO: Record<string, string> = { instancia: 'Instância', realm: 'Realm', cliente: 'Aplicação', categorias: 'Categorias',
  tecnicos: 'Eventos técnicos', tipo: 'Tipo', resultado: 'Resultado', de: 'De', ate: 'Até', destaque: 'Destaque', conta: 'Conta',
  ip: 'IP', sessao: 'Sessão' }
const VALOR_FILTRO: Record<string, Record<string, string>> = {
  tipo: { falhas: 'falhas de login', logins: 'logins' }, tecnicos: { '1': 'incluídos' },
  destaque: { fora_expediente: 'fora do expediente', ip_novo: 'IP novo' }, resultado: { sucesso: 'sucesso', falha: 'com erro' } }

function valorChip(k: string, v: string, fuso: string): string {
  if ((k === 'de' || k === 'ate') && /^\d+$/.test(v)) return dataHora(new Date(Number(v)).toISOString(), fuso)
  return VALOR_FILTRO[k]?.[v] ?? v
}

function Chips({ f, fuso, aoTirar, aoLimpar }: { f: A.Filtros; fuso: string; aoTirar: (k: string) => void; aoLimpar: () => void }) {
  const ks = Object.keys(f).filter((k) => f[k as keyof A.Filtros])
  if (!ks.length) return null
  return (
    <ul className="chips" aria-label="Filtros aplicados">
      {ks.map((k) => <li key={k} className="chip">{NOMES_FILTRO[k] ?? k}: {valorChip(k, String(f[k as keyof A.Filtros]), fuso)}
        <button type="button" aria-label={`Tirar o filtro ${NOMES_FILTRO[k] ?? k}`} onClick={() => aoTirar(k)}><Icone nome="fa-times" /></button></li>)}
      <li><button type="button" className="br-button small tertiary" onClick={aoLimpar}>Limpar filtros</button></li>
    </ul>
  )
}

function useFiltrosUrl(): [A.Filtros, (novo: A.Filtros) => void] {
  const [p, setP] = useSearchParams()
  const f = useMemo(() => A.filtrosDaUrl(p), [p])
  const mudar = (novo: A.Filtros) => {
    const q = new URLSearchParams()
    for (const [k, v] of Object.entries(novo)) if (v) q.set(k, String(v))
    setP(q, { replace: false })
  }
  return [f, mudar]
}

function FiltrosTecnicos({ f, opcoes, mudar }: { f: A.Filtros; opcoes?: A.Dashboard['opcoes']; mudar: (f: A.Filtros) => void }) {
  const sel = (k: 'instancia' | 'realm' | 'cliente', rotulo: string, lista: string[]) => (
    <div className="campo"><label htmlFor={`f-${k}`}>{rotulo}</label>
      <select id={`f-${k}`} value={f[k] ?? ''} onChange={(e) => mudar({ ...f, [k]: e.target.value || undefined })}>
        <option value="">Todas</option>{lista.map((v) => <option key={v} value={v}>{v}</option>)}
      </select></div>)
  return (
    <div className="filtros-analise" role="group" aria-label="Filtros">
      {sel('instancia', 'Instância', opcoes?.instancias ?? [])}
      {sel('realm', 'Realm', opcoes?.realms ?? [])}
      {sel('cliente', 'Aplicação', opcoes?.clientes ?? [])}
      <div className="br-checkbox"><input id="f-tecnicos" type="checkbox" checked={f.tecnicos === '1'}
        onChange={(e) => mudar({ ...f, tecnicos: e.target.checked ? '1' : undefined })} />
        <label htmlFor="f-tecnicos">Incluir eventos técnicos</label></div>
    </div>
  )
}

function Preliminar({ preliminar, rotulos }: { preliminar: boolean; rotulos?: boolean }) {
  if (!preliminar) return null
  return <p className="faixa-preliminar" role="status"><strong>PRELIMINAR</strong> — a coleta ainda não terminou; números e rótulos podem
    mudar.{rotulos === false && ' Rótulos aparecem como “IP (numeração no fechamento)” e os filtros por pseudônimo ficam disponíveis depois do fechamento.'}</p>
}

function Recalculo({ a }: { a?: A.EstadoAnalise }) {
  if (!a?.recalculando) return null
  return <Mensagem tipo="warning" papel="status">Os números estão sendo recalculados por causa da {a.motivo ?? 'mudança nas contas'}.
    Isso leva cerca de 1 min. Os números abaixo estão desatualizados.</Mensagem>
}

function SeloCobertura({ s, id }: { s: A.SeloCobertura; id: number }) {
  if (!s.calculada) return <span className="estado tom-cinza"><Icone nome="fa-hourglass-half" /> Cobertura calculada no fechamento</span>
  return s.completa
    ? <span className="estado tom-verde"><Icone nome="fa-check" /> Cobertura completa</span>
    : <span className="estado tom-ambar"><Icone nome="fa-exclamation-triangle" /> Cobertura parcial: {s.realms_cobertos} de {s.realms} realms,
      {' '}{s.dias_cobertos} de {s.dias} dias — <Link to={`/investigacoes/${id}/cobertura`}>ver detalhes</Link></span>
}

function Kpis({ k, fuso, extra }: { k: { logins: number; falhas: number; aplicacoes: number; ips?: number; primeiro?: string | null;
  ultimo?: string | null }; fuso: string; extra?: boolean }) {
  return (
    <div className="kpis-analise">
      <div className="kpi-cartao"><span className="kpi-rotulo">Logins</span><span className="kpi-numero">{numero(k.logins)}</span></div>
      <div className="kpi-cartao"><span className="kpi-rotulo">Falhas de login</span><span className="kpi-numero">{numero(k.falhas)}</span></div>
      <div className="kpi-cartao"><span className="kpi-rotulo">Aplicações</span><span className="kpi-numero">{numero(k.aplicacoes)}</span></div>
      {extra && <div className="kpi-cartao"><span className="kpi-rotulo">IPs</span><span className="kpi-numero">{numero(k.ips)}</span></div>}
      {extra && <div className="kpi-cartao"><span className="kpi-rotulo">Primeiro acesso</span><span className="kpi-numero kpi-menor">{dataHora(k.primeiro, fuso)}</span></div>}
      {extra && <div className="kpi-cartao"><span className="kpi-rotulo">Último acesso</span><span className="kpi-numero kpi-menor">{dataHora(k.ultimo, fuso)}</span></div>}
    </div>
  )
}

// ------------------------------------------------------------------ Dashboard
export function Dashboard({ d }: { d: Detalhe }) {
  const [f, mudar] = useFiltrosUrl()
  const ir = useNavigate()
  const fuso = d.fuso ?? 'America/Sao_Paulo'
  const chave = JSON.stringify(f)
  const { dados: x, erro, carregando, recarregar } = useCarregar((s) => A.dashboard(d.id, f, s), [d.id, chave])
  useEffect(() => {   // recálculo em andamento: volta a consultar até terminar
    if (!x?.analise.recalculando && !x?.preliminar) return
    const t = setTimeout(recarregar, x?.analise.recalculando ? 5000 : 30000)
    return () => clearTimeout(t)
  }, [x, recarregar])
  const tecnicos = { instancia: f.instancia, realm: f.realm, cliente: f.cliente, tecnicos: f.tecnicos }
  const abrirEventos = (extra: Record<string, string | number | undefined>) => {
    const q = new URLSearchParams()
    for (const [k, v] of Object.entries({ ...tecnicos, ...extra })) if (v !== undefined && v !== '') q.set(k, String(v))
    ir(`/investigacoes/${d.id}/eventos?${q}`)
  }
  if (erro) return <ErroTela erro={erro} investigacao={d.id} tentar={recarregar} />
  if (!x) return <><p role="status">Calculando os números desta investigação…</p><Esqueleto linhas={8} rotulo="Carregando o dashboard" /></>
  const g = x.granularidade
  const rotulos = x.serie.map((s) => rotuloJanela(s.janela, g))
  const semEventos = x.kpis.eventos === 0
  return <>
    <Preliminar preliminar={x.preliminar} rotulos={x.rotulos_definitivos} />
    <Recalculo a={x.analise} />
    <FiltrosTecnicos f={f} opcoes={x.opcoes} mudar={mudar} />
    <Chips f={f} fuso={fuso} aoTirar={(k) => mudar({ ...f, [k]: undefined })} aoLimpar={() => mudar({})} />
    <p><SeloCobertura s={x.cobertura} id={d.id} /></p>
    <div aria-busy={carregando}>
      <Kpis k={x.kpis} fuso={fuso} extra />
      {semEventos ? <Vazio>{Object.keys(f).length ? 'Nenhum evento com estes filtros.' : 'Nenhum acesso encontrado no período em nenhum realm pesquisado.'}</Vazio> : <>
        <GraficoSerie titulo={`Logins e falhas por ${g}`} rotulos={rotulos}
          rotuloLongo={(i) => rotuloJanela(x.serie[i].janela, g, true)}
          series={[{ chave: 'logins', nome: 'Logins', cor: 1, valores: x.serie.map((s) => s.logins) },
            { chave: 'falhas', nome: 'Falhas de login', cor: 2, valores: x.serie.map((s) => s.falhas) }]}
          aoSelecionar={(i) => {
            const j = x.serie[i].janela
            abrirEventos({ de: localParaUtc(j, fuso), ate: localParaUtc(proximaJanela(j, g), fuso) - 1 })
          }} />
        <section aria-labelledby="t-destaques">
          <h2 id="t-destaques">Destaques</h2>
          {!x.destaques.length ? <Vazio>Nenhum destaque (fora do expediente, rajada de falhas ou IP novo) neste recorte.</Vazio> : (
            <ul className="destaques">
              {x.destaques.slice(0, 20).map((z, k) => <li key={k}>
                <button type="button" className="destaque" onClick={() => abrirEventos(z.filtro)}>
                  <strong>{z.titulo}</strong>
                  <span className="meta-destaque">{numero(z.n)} evento{z.n === 1 ? '' : 's'} · {dataHora(z.inicio, fuso)}
                    {z.fim && z.tipo === 'rajada' ? ` a ${dataHora(z.fim, fuso)}` : ''}
                    {z.conta ? ` · ${z.conta}` : ''}{z.ip ? ` · ${z.ip}` : ''}{z.instancia ? ` · ${z.instancia}/${z.realm}` : ''}</span>
                  <span className="sr-only">Ver eventos</span>
                </button></li>)}
            </ul>)}
          {x.destaques.length > 20 && <p className="secundario">Mais {numero(x.destaques.length - 20)} destaques: use os filtros de Eventos.</p>}
        </section>
        <div className="grade-analise">
          <Barras titulo="IPs com mais eventos" unidade="eventos"
            itens={x.ranking_ips.map((r) => ({ rotulo: r.ip, valor: r.eventos, detalhe: `${numero(r.falhas)} falhas` }))}
            aoSelecionar={x.rotulos_definitivos ? (k) => abrirEventos({ ip: x.ranking_ips[k].ip }) : undefined} />
          <Barras titulo="Aplicações com mais logins" unidade="logins"
            itens={x.ranking_aplicacoes.map((r) => ({ rotulo: r.cliente ?? '(sem aplicação)', valor: r.logins, detalhe: `${r.instancia}/${r.realm}` }))}
            aoSelecionar={(k) => { const r = x.ranking_aplicacoes[k]; abrirEventos({ instancia: r.instancia, realm: r.realm, cliente: r.cliente ?? undefined }) }} />
        </div>
        <MapaCalor titulo={`Logins por dia da semana e hora (${fuso})`} celulas={x.mapa_calor} />
        <section aria-labelledby="t-por-app">
          <h2 id="t-por-app">Por instância, realm e aplicação</h2>
          <div className="br-table tabela-rolavel" tabIndex={0} role="region" aria-labelledby="t-por-app">
            <table>
              <thead><tr><th scope="col">Instância</th><th scope="col">Realm</th><th scope="col">Aplicação</th>
                <th scope="col" className="num">Logins</th><th scope="col" className="num">Falhas</th><th scope="col" className="num">Eventos</th>
                <th scope="col"><span className="sr-only">Ação</span></th></tr></thead>
              <tbody>{x.por_aplicacao.map((r, k) => <tr key={k}><td>{r.instancia}</td><td>{r.realm}</td><td>{r.cliente ?? '—'}</td>
                <td className="num">{numero(r.logins)}</td><td className="num">{numero(r.falhas)}</td><td className="num">{numero(r.eventos)}</td>
                <td><button type="button" className="br-button small tertiary"
                  onClick={() => abrirEventos({ instancia: r.instancia, realm: r.realm, cliente: r.cliente ?? undefined })}>
                  Ver eventos<span className="sr-only"> de {r.cliente ?? 'sem aplicação'} em {r.instancia}/{r.realm}</span></button></td></tr>)}</tbody>
            </table>
          </div>
        </section>
      </>}
      <section className="br-card" aria-labelledby="t-prova">
        <div className="card-header"><h2 id="t-prova">Saúde da prova</h2></div>
        <div className="card-content">
          <dl className="saude-prova">
            <div><dt>Fatias seladas</dt><dd>{numero(x.saude_prova.seladas)} de {numero(x.saude_prova.fatias)}</dd></div>
            <div><dt>Relidas</dt><dd>{numero(x.saude_prova.relidas)}</dd></div>
            <div><dt>Releituras divergentes</dt><dd>{numero(x.saude_prova.divergentes)}</dd></div>
            <div><dt>Fatias no limite</dt><dd>{numero(x.saude_prova.em_limite)}</dd></div>
            <div><dt>Fatias com falha</dt><dd>{numero(x.saude_prova.falharam)}</dd></div>
            <div><dt>Último selo</dt><dd>{dataHora(x.saude_prova.ultimo_selo, fuso)}</dd></div>
            <div><dt>Última âncora</dt><dd>{dataHora(x.saude_prova.ultima_ancora, fuso)}</dd></div>
          </dl>
        </div>
      </section>
    </div>
  </>
}

// ------------------------------------------------------------------ Eventos
const COLUNAS: { id: keyof A.Evento; rotulo: string }[] = [
  { id: 'horario', rotulo: 'Horário' }, { id: 'instancia', rotulo: 'Instância' }, { id: 'realm', rotulo: 'Realm' },
  { id: 'aplicacao', rotulo: 'Aplicação' }, { id: 'tipo_nome', rotulo: 'Tipo' }, { id: 'conta', rotulo: 'Conta' },
  { id: 'ip', rotulo: 'IP' }, { id: 'sessao', rotulo: 'Sessão' }, { id: 'resultado', rotulo: 'Resultado' }]
const PADRAO = ['horario', 'instancia', 'realm', 'aplicacao', 'tipo_nome', 'conta', 'ip', 'resultado']

function useCelular() {
  const [c, setC] = useState(() => typeof matchMedia !== 'undefined' && matchMedia('(max-width: 767px)').matches)
  useEffect(() => {
    if (typeof matchMedia === 'undefined') return
    const m = matchMedia('(max-width: 767px)')
    const f = () => setC(m.matches)
    m.addEventListener('change', f)
    return () => m.removeEventListener('change', f)
  }, [])
  return c
}

export function Eventos({ d }: { d: Detalhe }) {
  const [f, mudar] = useFiltrosUrl()
  const fuso = d.fuso ?? 'America/Sao_Paulo'
  const celular = useCelular()
  const [cursores, setCursores] = useState<(string | undefined)[]>([undefined])
  const [sel, setSel] = useState<string | null>(null)
  const pref = lerPrefEventos()
  const [colunas, setColunas] = useState<string[]>(pref?.colunas ?? PADRAO)
  const [compacta, setCompacta] = useState(pref?.compacta ?? false)
  const chave = JSON.stringify(f)
  useEffect(() => { setCursores([undefined]); setSel(null) }, [chave])
  const apos = cursores[cursores.length - 1]
  const { dados: p, erro, carregando, recarregar } = useCarregar((s) => A.eventos(d.id, { ...f, apos, limite: 50 }, s), [d.id, chave, apos])
  useEffect(() => { gravarPrefEventos({ colunas, compacta }) }, [colunas, compacta])
  const [rotuloIp, setRotuloIp] = useState(f.ip ?? '')
  const [rotuloConta, setRotuloConta] = useState(f.conta ?? '')
  useEffect(() => { setRotuloIp(f.ip ?? ''); setRotuloConta(f.conta ?? '') }, [f.ip, f.conta])
  if (erro) return <ErroTela erro={erro} investigacao={d.id} tentar={recarregar} />
  const visiveis = COLUNAS.filter((c) => colunas.includes(c.id))
  return <>
    {p && <Preliminar preliminar={p.preliminar} rotulos={p.rotulos_definitivos} />}
    <FiltrosTecnicos f={f} mudar={mudar} />
    <form className="filtros-analise" onSubmit={(e) => { e.preventDefault(); mudar({ ...f, ip: rotuloIp.trim() || undefined, conta: rotuloConta.trim() || undefined }) }}>
      <div className="campo"><label htmlFor="f-tipo">Tipo</label>
        <select id="f-tipo" value={f.tipo ?? ''} onChange={(e) => mudar({ ...f, tipo: e.target.value || undefined })}>
          <option value="">Todos</option><option value="logins">Logins</option><option value="falhas">Falhas de login</option>
        </select></div>
      <div className="campo"><label htmlFor="f-resultado">Resultado</label>
        <select id="f-resultado" value={f.resultado ?? ''} onChange={(e) => mudar({ ...f, resultado: e.target.value || undefined })}>
          <option value="">Todos</option><option value="sucesso">Sucesso</option><option value="falha">Com erro</option>
        </select></div>
      <div className="campo"><label htmlFor="f-ip">IP (pseudônimo)</label>
        <input id="f-ip" type="text" placeholder="IP 3" value={rotuloIp} disabled={p ? !p.rotulos_definitivos : false}
          onChange={(e) => setRotuloIp(e.target.value)} aria-describedby="ajuda-pseudo" /></div>
      <div className="campo"><label htmlFor="f-conta">Conta (pseudônimo)</label>
        <input id="f-conta" type="text" placeholder="Conta 2" value={rotuloConta} disabled={p ? !p.rotulos_definitivos : false}
          onChange={(e) => setRotuloConta(e.target.value)} aria-describedby="ajuda-pseudo" /></div>
      <button type="submit" className="br-button small secondary">Aplicar</button>
      <p id="ajuda-pseudo" className="secundario">Pelo rótulo do pseudônimo, como aparece na tabela. Buscar por valor real (IP, username) é
        revelação e chega com a sessão de análise (W4).</p>
    </form>
    <Chips f={f} fuso={fuso} aoTirar={(k) => mudar({ ...f, [k]: undefined })} aoLimpar={() => mudar({})} />
    <div className="barra-paginacao">
      <p role="status" aria-live="polite">{p ? `${numero(p.total_filtrado)} de ${numero(p.total)} eventos` : 'Carregando…'}</p>
      {!celular && <details className="seletor-colunas">
        <summary className="br-button small tertiary">Colunas</summary>
        <fieldset><legend className="sr-only">Colunas visíveis</legend>
          {COLUNAS.map((c) => <div key={c.id} className="br-checkbox"><input id={`col-${c.id}`} type="checkbox" checked={colunas.includes(c.id)}
            onChange={(e) => setColunas((cs) => e.target.checked ? [...cs, c.id] : cs.filter((x) => x !== c.id))} />
            <label htmlFor={`col-${c.id}`}>{c.rotulo}</label></div>)}
        </fieldset>
      </details>}
      {!celular && <button type="button" className="br-button small tertiary" aria-pressed={compacta} onClick={() => setCompacta((v) => !v)}>
        {compacta ? 'Densidade confortável' : 'Densidade compacta'}</button>}
    </div>
    {!p ? <Esqueleto linhas={10} rotulo="Carregando eventos" /> : !p.itens.length
      ? <Vazio acao={Object.keys(f).length ? <button type="button" className="br-button small secondary" onClick={() => mudar({})}>Limpar filtros</button> : undefined}>
        {Object.keys(f).length ? 'Nenhum evento com estes filtros.' : 'Nenhum acesso encontrado no período.'}</Vazio>
      : <div className={`eventos-layout${sel && !celular ? ' com-painel' : ''}`} aria-busy={carregando}>
        {celular ? <ul className="cartoes-eventos">{p.itens.map((e) => <li key={e.ref}>
          <strong>{dataHora(e.horario, fuso)}</strong> · {e.tipo_nome} · {e.resultado}<br />
          <span className="secundario">{e.instancia}/{e.realm} · {e.aplicacao ?? '—'} · {e.conta ?? '—'} · {e.ip ?? '—'}</span></li>)}</ul>
          : <div className="br-table tabela-rolavel" tabIndex={0} role="region" aria-label="Eventos">
            <table className={`tabela-eventos${compacta ? ' compacta' : ''}`}>
              <thead><tr>{visiveis.map((c) => <th key={c.id} scope="col">{c.rotulo}</th>)}<th scope="col"><span className="sr-only">Detalhe</span></th></tr></thead>
              <tbody>{p.itens.map((e) => <tr key={e.ref} className={sel === e.ref ? 'selecionada' : undefined}>
                {visiveis.map((c) => <td key={c.id} className={c.id === 'horario' ? 'mono' : undefined}>
                  {c.id === 'horario' ? dataHora(e.horario, fuso) : String(e[c.id] ?? '—')}</td>)}
                <td><button type="button" className="br-button small tertiary" aria-expanded={sel === e.ref}
                  onClick={() => setSel(sel === e.ref ? null : e.ref)}>Detalhe<span className="sr-only"> do evento de {dataHora(e.horario, fuso)}</span></button></td>
              </tr>)}</tbody>
            </table>
          </div>}
        {sel && !celular && <PainelEvento id={d.id} ref_={sel} fuso={fuso} aoFechar={() => setSel(null)} />}
      </div>}
    {p && <nav className="barra-paginacao" aria-label="Paginação dos eventos">
      <button type="button" className="br-button small secondary" disabled={cursores.length <= 1}
        onClick={() => setCursores((c) => c.slice(0, -1))}>Anteriores</button>
      <span>Página {cursores.length}</span>
      <button type="button" className="br-button small secondary" disabled={!p.proximo}
        onClick={() => p.proximo && setCursores((c) => [...c, p.proximo!])}>Próximos</button>
    </nav>}
  </>
}

function PainelEvento({ id, ref_, fuso, aoFechar }: { id: number; ref_: string; fuso: string; aoFechar: () => void }) {
  const { dados: e, erro } = useCarregar((s) => A.evento(id, ref_, s), [id, ref_])
  return (
    <aside className="painel-evento" aria-labelledby="t-evento" onKeyDown={(ev) => { if (ev.key === 'Escape') aoFechar() }}>
      <div className="linha-titulo"><h2 id="t-evento" tabIndex={-1}>Detalhe do evento</h2>
        <button type="button" className="br-button circle small" aria-label="Fechar o detalhe" onClick={aoFechar}><Icone nome="fa-times" /></button></div>
      {erro ? <Mensagem tipo="danger">{textoErro(erro)}</Mensagem> : !e ? <Esqueleto linhas={6} rotulo="Carregando o evento" /> : <>
        <dl>
          <dt>Horário</dt><dd>{dataHora(e.horario, fuso)} ({fuso})</dd>
          <dt>Tipo</dt><dd>{e.tipo_nome} <span className="mono">({e.tipo})</span></dd>
          <dt>Resultado</dt><dd>{e.resultado}</dd>
          <dt>Onde</dt><dd>{e.instancia}/{e.realm} · {e.aplicacao ?? '—'}</dd>
          <dt>Conta</dt><dd>{e.conta ?? '—'}</dd><dt>IP</dt><dd>{e.ip ?? '—'}</dd><dt>Sessão</dt><dd>{e.sessao ?? '—'}</dd>
          <dt>ID do evento</dt><dd className="mono">{e.evento_id}</dd>
        </dl>
        <h3>Prova</h3>
        <dl>
          <dt>Folha (Merkle)</dt><dd className="mono hash">{e.folha ?? '—'}</dd>
          <dt>Hash do conteúdo</dt><dd className="mono hash">{e.hash_conteudo ?? '—'}</dd>
          {e.selo && <><dt>Selo da fatia</dt><dd>nº {e.selo.id} · {numero(e.selo.eventos)} eventos · selado em {dataHora(e.selo.selado_em, fuso)}
            <br /><span className="mono hash">raiz {e.selo.raiz}</span></dd></>}
          {e.requisicao && <><dt>Requisição de origem</dt><dd>nº {e.requisicao.id} · {e.requisicao.metodo} {e.requisicao.status} ·
            {' '}{dataHora(e.requisicao.quando, fuso)}<br /><span className="mono hash">SHA-256 {e.requisicao.sha256}</span></dd></>}
        </dl>
        <h3>Campos (pseudonimizados)</h3>
        <pre>{JSON.stringify(e.json, null, 2)}</pre>
      </>}
    </aside>
  )
}

// ------------------------------------------------------------------ Contas
export function Contas({ d }: { d: Detalhe }) {
  const fuso = d.fuso ?? 'America/Sao_Paulo'
  const { dados: x, erro, recarregar } = useCarregar((s) => A.contas(d.id, s), [d.id])
  const [acao, setAcao] = useState<{ conta: A.Conta; incluir: boolean } | null>(null)
  const [motivo, setMotivo] = useState('')
  const [erroAcao, setErroAcao] = useState<string | null>(null)
  const [aviso, setAviso] = useState<string | null>(null)
  const [aberta, setAberta] = useState<number | null>(null)
  useEffect(() => {
    if (!x?.analise.recalculando) return
    const t = setTimeout(recarregar, 5000)
    return () => clearTimeout(t)
  }, [x, recarregar])
  if (erro) return <ErroTela erro={erro} investigacao={d.id} tentar={recarregar} />
  if (!x) return <Esqueleto linhas={6} rotulo="Carregando as contas" />
  async function confirmar() {
    if (!acao) return
    if (motivo.trim().length < 10) { setErroAcao('Escreva a justificativa (mínimo de 10 caracteres).'); return }
    try {
      await A.decidirConta(d.id, acao.conta.id, acao.incluir, motivo.trim())
      setAviso(`${acao.conta.conta ?? 'Conta'} ${acao.incluir ? 'incluída' : 'excluída'}. Os números estão sendo recalculados.`)
      setAcao(null); setMotivo(''); setErroAcao(null); recarregar()
    } catch (e) { setErroAcao(textoErro(e)) }
  }
  return <>
    <Preliminar preliminar={x.preliminar} />
    <Recalculo a={x.analise} />
    {aviso && <Mensagem tipo="success" papel="status">{aviso}</Mensagem>}
    {!x.contas.length ? <Vazio>Nenhuma conta encontrada.</Vazio> : (
      <div className="br-table tabela-rolavel" tabIndex={0} role="region" aria-label="Contas da investigação">
        <table>
          <thead><tr><th scope="col">Conta</th><th scope="col">Instância / realm</th><th scope="col">Como foi achada</th>
            <th scope="col">Situação</th><th scope="col" className="num">Eventos</th><th scope="col">Período</th>
            <th scope="col" className="num">Sessões ativas</th><th scope="col" className="num">Alterações</th><th scope="col">Ações</th></tr></thead>
          <tbody>{x.contas.map((c) => <ContaLinha key={c.id} c={c} fuso={fuso} id={d.id} aberta={aberta === c.id}
            alternar={() => setAberta(aberta === c.id ? null : c.id)} preliminar={x.preliminar}
            aoDecidir={(incluir) => { setAcao({ conta: c, incluir }); setMotivo(''); setErroAcao(null) }} />)}</tbody>
        </table>
      </div>)}
    <Dialogo aberto={Boolean(acao)} titulo={acao ? `${acao.incluir ? 'Incluir' : 'Excluir'} ${acao.conta.conta ?? 'conta'}` : ''}
      aoFechar={() => setAcao(null)}
      rodape={<><button type="button" className="br-button secondary" onClick={() => setAcao(null)}>Cancelar</button>
        <button type="button" className="br-button primary" onClick={confirmar}>Confirmar: {acao?.incluir ? 'incluir' : 'excluir'}</button></>}>
      <p>{acao?.incluir ? 'Os eventos desta conta voltam aos números, aos destaques e ao pacote.'
        : 'Os eventos desta conta saem dos números, dos destaques e do pacote. A decisão e a justificativa ficam na trilha.'}</p>
      <Area id="motivo-conta" rotulo="Justificativa" obrigatorio rows={3} value={motivo} onChange={(e) => setMotivo(e.target.value)}
        erro={erroAcao ?? undefined} />
    </Dialogo>
  </>
}

function ContaLinha({ c, fuso, id, aberta, alternar, aoDecidir, preliminar }: { c: A.Conta; fuso: string; id: number; aberta: boolean;
  alternar: () => void; aoDecidir: (incluir: boolean) => void; preliminar: boolean }) {
  const VIA: Record<string, string> = { atributo: 'pelo identificador', informada: 'informada no pedido', historico: 'pelo histórico',
    varredura: 'varredura de falhas', realm: 'realm inteiro' }
  return <>
    <tr>
      <th scope="row">{c.conta ?? '—'}{c.duplicidade && <span className="selo"> <Icone nome="fa-clone" /> duplicidade no realm</span>}</th>
      <td>{c.instancia}/{c.realm}</td>
      <td>{VIA[c.via] ?? c.via}{c.origem ? ` · ${c.origem}` : ''}</td>
      <td>{c.incluida ? <span className="estado tom-verde"><Icone nome="fa-check" /> Incluída</span>
        : <span className="estado tom-cinza"><Icone nome="fa-ban" /> Excluída</span>}
        {c.decisao && <div className="secundario">{c.decisao.incluida ? 'Incluída' : 'Excluída'} em {dataHora(c.decisao.quando, fuso)}
          {c.decisao.motivo ? `: “${c.decisao.motivo}”` : ''}</div>}</td>
      <td className="num">{numero(c.eventos)}</td>
      <td>{c.primeiro ? `${data(c.primeiro, fuso)} a ${data(c.ultimo, fuso)}` : '—'}</td>
      <td className="num">{numero(c.sessoes_ativas)}</td><td className="num">{numero(c.alteracoes)}</td>
      <td className="acoes-linha">
        {c.via !== 'varredura' && !preliminar && <button type="button" className="br-button small secondary" onClick={() => aoDecidir(!c.incluida)}>
          {c.incluida ? 'Excluir' : 'Incluir'}<span className="sr-only"> {c.conta}</span></button>}
        {(c.sessoes_ativas > 0 || c.alteracoes > 0) && <button type="button" className="br-button small tertiary" aria-expanded={aberta} onClick={alternar}>
          Sessões e alterações<span className="sr-only"> de {c.conta}</span></button>}
      </td>
    </tr>
    {aberta && <tr><td colSpan={9}><ExtrasConta id={id} conta={c.id} fuso={fuso} /></td></tr>}
  </>
}

function ExtrasConta({ id, conta, fuso }: { id: number; conta: number; fuso: string }) {
  const { dados: x, erro } = useCarregar((s) => A.extrasConta(id, conta, s), [id, conta])
  if (erro) return <Mensagem tipo="danger">{textoErro(erro)}</Mensagem>
  if (!x) return <Esqueleto linhas={2} rotulo="Carregando sessões e alterações" />
  return <div className="grade-analise">
    <section><h3>Sessões ativas (fotografia no fechamento)</h3>
      {!x.sessoes_ativas.length ? <p>Nenhuma.</p> : <ul>{x.sessoes_ativas.map((s, k) => <li key={k}>{s.ip} · desde {dataHora(s.inicio, fuso)}
        · último acesso {dataHora(s.ultimo_acesso, fuso)}{s.aplicacoes.length ? ` · ${s.aplicacoes.join(', ')}` : ''}</li>)}</ul>}</section>
    <section><h3>Alterações na conta</h3>
      {!x.alteracoes.length ? <p>Nenhuma.</p> : <ul>{x.alteracoes.map((a, k) => <li key={k}>{dataHora(a.quando, fuso)} · {a.operacao}
        · {a.recurso} · por {a.autor_ip}</li>)}</ul>}</section>
  </div>
}

// ------------------------------------------------------------------ Cobertura
const ICONE_CLASSE: Record<string, string> = { coberto: 'fa-check', parcial: 'fa-adjust', sem_dados: 'fa-ban', pendente: 'fa-hourglass-half' }
const TOM_CLASSE: Record<string, string> = { coberto: 'tom-verde', parcial: 'tom-ambar', sem_dados: 'tom-vermelho', pendente: 'tom-cinza' }
const NOME_CLASSE: Record<string, string> = { coberto: 'Coberto', parcial: 'Parcial', sem_dados: 'Sem dados', pendente: 'Pendente' }

export function Cobertura({ d }: { d: Detalhe }) {
  const fuso = d.fuso ?? 'America/Sao_Paulo'
  const { dados: x, erro, recarregar } = useCarregar((s) => A.cobertura(d.id, s), [d.id])
  if (erro) return <ErroTela erro={erro} investigacao={d.id} tentar={recarregar} />
  if (!x) return <Esqueleto linhas={6} rotulo="Carregando a cobertura" />
  const ini = new Date(x.de).getTime(), fim = new Date(x.ate).getTime()
  return <>
    <p><SeloCobertura s={x.selo} id={d.id} /></p>
    <ul className="legenda" aria-label="Classes de cobertura">
      {['coberto', 'parcial', 'sem_dados', 'pendente'].map((k) => <li key={k}><span className={`faixa ${k}`} style={{ width: 24, height: 12 }} aria-hidden="true" />
        {NOME_CLASSE[k]}</li>)}
    </ul>
    {!x.linhas.length ? <Vazio>A cobertura é calculada no fechamento da coleta.</Vazio> : (
      <div className="br-table tabela-rolavel" tabIndex={0} role="region" aria-label="Cobertura por realm">
        <table>
          <thead><tr><th scope="col">Instância / realm</th><th scope="col">Conta</th><th scope="col">Classe</th>
            <th scope="col">Período ({data(x.de, fuso)} a {data(x.ate, fuso)})</th><th scope="col">Motivo</th><th scope="col">Ação recomendada</th></tr></thead>
          <tbody>{x.linhas.map((l, k) => <tr key={k}>
            <th scope="row">{l.instancia}/{l.realm}</th><td>{l.conta ?? '—'}</td>
            <td><span className={`estado ${TOM_CLASSE[l.classe] ?? 'tom-cinza'}`}><Icone nome={ICONE_CLASSE[l.classe] ?? 'fa-question'} /> {l.classe_nome}</span></td>
            <td>
              <span className="faixas-cobertura" aria-hidden="true">{l.faixas.map((f, j) => {
                const w = Math.max(0.5, ((new Date(f.ate).getTime() - new Date(f.de).getTime()) / Math.max(1, fim - ini)) * 100)
                return <span key={j} className={`faixa ${f.classe}`} style={{ width: `${w}%` }} />
              })}</span>
              <span className="sr-only">{l.faixas.map((f) => `${NOME_CLASSE[f.classe] ?? f.classe} de ${data(f.de, fuso)} a ${data(f.ate, fuso)}`).join('; ')}</span>
              {l.faixas.length > 1 && <details><summary>Ver faixas</summary><ul>{l.faixas.map((f, j) => <li key={j}>{NOME_CLASSE[f.classe] ?? f.classe}:
                {' '}{data(f.de, fuso)} a {data(f.ate, fuso)}</li>)}</ul></details>}
            </td>
            <td>{l.motivo ?? '—'}</td><td>{l.acao ?? '—'}</td>
          </tr>)}</tbody>
        </table>
      </div>)}
  </>
}

// ------------------------------------------------------------------ Visão agregada (solicitante)
export function VisaoAgregada({ d }: { d: Detalhe }) {
  const fuso = d.fuso ?? 'America/Sao_Paulo'
  const { dados: x, erro, recarregar } = useCarregar((s) => A.visaoAgregada(d.id, s), [d.id])
  if (erro) return <ErroTela erro={erro} investigacao={d.id} tentar={recarregar} />
  if (!x) return <Esqueleto linhas={4} rotulo="Carregando a visão agregada" />
  return (
    <section className="br-card" aria-labelledby="t-agregada">
      <div className="card-header"><h2 id="t-agregada">Visão agregada</h2></div>
      <div className="card-content">
        <p className="secundario">Totais do período, sem IPs, contas nem pseudônimos. <SeloCobertura s={x.cobertura} id={d.id} /></p>
        <Kpis k={x.kpis} fuso={fuso} />
        <GraficoSerie titulo="Logins e falhas por dia" rotulos={x.serie_dia.map((s) => data(s.dia).slice(0, 5))}
          rotuloLongo={(i) => data(x.serie_dia[i].dia)}
          series={[{ chave: 'logins', nome: 'Logins', cor: 1, valores: x.serie_dia.map((s) => s.logins) },
            { chave: 'falhas', nome: 'Falhas de login', cor: 2, valores: x.serie_dia.map((s) => s.falhas) }]} />
        <Barras titulo="Aplicações por quantidade de logins" unidade="logins"
          itens={x.aplicacoes.map((a) => ({ rotulo: a.aplicacao, valor: a.logins }))} />
      </div>
    </section>
  )
}

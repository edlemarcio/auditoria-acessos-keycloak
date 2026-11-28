/**
 * Sessão de análise e revelação na tela (W4, §5.5 e §7.5).
 * - Cabeçalho: tempo restante, cota ("12 de 30 revelados"), Prorrogar, Encerrar; aviso 5 min antes do fim e quando
 *   termina (aria-live). O relógio é do servidor: a tela só conta o tempo e consulta de novo.
 * - "Revelar" ao lado do pseudônimo, nunca no lugar: `IP 12 · 200.155.34.8 (olho) Revelado`.
 * - Acima da cota ou dado de terceiro: diálogo para pedir aprovação (quatro olhos).
 * - Lista para ofício: IPs juntados na memória da tela e pedidos em bloco.
 * - Marca d'água com o usuário e o horário enquanto houver valor revelado (aria-hidden, não reduz o contraste).
 * - Celular (< 768 px): revelação desabilitada.
 * Valores revelados ficam só na memória deste componente.
 */
import { createContext, useCallback, useContext, useEffect, useRef, useState, type ReactNode } from 'react'
import { ErroApi } from '../api/cliente'
import * as R from '../api/revelacao'
import { tomarRetomada } from '../armazenamento'
import { pareceIdentificador } from '../dominio/documentos'
import { dataHora, numero } from '../dominio/formato'
import { useSessao } from '../sessao'
import { Area, Campo } from './Campo'
import { Dialogo } from './Dialogo'
import { Icone, Mensagem, textoErro } from './Estado'

interface Item { classe: string; rotulo: string }
interface Ctx {
  id: number; habilitado: boolean; celular: boolean
  est: R.EstadoSessao | null
  restante_s: number | null
  recarregar: () => void
  revelado: (classe: string, rotulo?: string | null) => R.Revelado | undefined
  revelarItem: (i: Item) => Promise<void>
  abrirIniciar: (depois?: Item) => void
  pedirAprovacao: (tipo: string, itens: Item[]) => void
  oficio: string[]; adicionarOficio: (rotulo: string) => void; removerOficio: (rotulo: string) => void; limparOficio: () => void
}
const C = createContext<Ctx | null>(null)
export const useAnalise = () => useContext(C)

function useCelular() {
  const q = '(max-width: 767px)'
  const [c, setC] = useState(() => typeof matchMedia !== 'undefined' && matchMedia(q).matches)
  useEffect(() => {
    if (typeof matchMedia === 'undefined') return
    const m = matchMedia(q)
    const f = () => setC(m.matches)
    m.addEventListener('change', f)
    return () => m.removeEventListener('change', f)
  }, [])
  return c
}

export function ProvedorAnalise({ id, habilitado, children }: { id: number; habilitado: boolean; children: ReactNode }) {
  const [est, setEst] = useState<R.EstadoSessao | null>(null)
  const [aviso, setAviso] = useState<string | null>(null)
  const [erro, setErro] = useState<string | null>(null)
  const [iniciar, setIniciar] = useState<{ aberto: boolean; depois?: Item }>({ aberto: false })
  const [pedido, setPedido] = useState<{ tipo: string; itens: Item[] } | null>(null)
  const [oficio, setOficio] = useState<string[]>([])
  const [agora, setAgora] = useState(() => Date.now())
  const desvio = useRef(0)   // relógio do servidor - relógio local
  const avisou5 = useRef<number | null>(null)
  const celular = useCelular()
  const ativa = useRef(false)

  const recarregar = useCallback(() => {
    if (!habilitado) return
    R.estado(id).then((e) => {
      if (e.sessao) desvio.current = new Date(e.sessao.agora).getTime() - Date.now()
      if (ativa.current && !e.sessao) setAviso('A sessão de análise terminou. Os valores revelados voltaram a ser pseudônimos.')
      ativa.current = Boolean(e.sessao)
      setEst(e)
    }).catch((x) => setErro(textoErro(x)))
  }, [id, habilitado])

  useEffect(() => { recarregar() }, [recarregar])
  useEffect(() => {   // retomada depois do step-up: reabre o diálogo de início
    if (habilitado && tomarRetomada(location.pathname, (a) => a === 'iniciar_sessao_analise')) setIniciar({ aberto: true })
  }, [habilitado])
  useEffect(() => {
    if (!habilitado) return
    const t = setInterval(() => setAgora(Date.now()), 1000)
    const p = setInterval(recarregar, 30_000)
    return () => { clearInterval(t); clearInterval(p) }
  }, [habilitado, recarregar])

  const restante_s = est?.sessao ? Math.max(0, Math.round((new Date(est.sessao.expira_em).getTime() - (agora + desvio.current)) / 1000)) : null
  useEffect(() => {
    if (restante_s == null) return
    if (restante_s === 0) { recarregar(); return }
    if (restante_s <= 300 && avisou5.current !== est?.sessao?.id) {
      avisou5.current = est?.sessao?.id ?? null
      setAviso(`A sessão de análise termina em ${Math.ceil(restante_s / 60)} min.${est?.sessao?.pode_prorrogar ? ' Você pode prorrogar.' : ''}`)
    }
  }, [restante_s, est, recarregar])

  const revelado = useCallback((classe: string, rotulo?: string | null) =>
    rotulo ? est?.revelados.find((r) => r.classe === classe && (r.classe === 'evento' ? r.chave === rotulo : r.rotulo === rotulo)) : undefined, [est])

  const revelarItem = useCallback(async (i: Item) => {
    setErro(null)
    if (!est?.sessao) { setIniciar({ aberto: true, depois: i }); return }
    try {
      await R.revelar(id, i.classe, i.rotulo)
      recarregar()
    } catch (x) {
      if (x instanceof ErroApi && (x.codigo === 'cota' || x.codigo === 'terceiro')) {
        setPedido({ tipo: x.codigo === 'cota' ? 'revelacao_cota' : 'revelacao_terceiro', itens: [i] })
        setErro(x.message)
      } else if (x instanceof ErroApi && x.codigo === 'sem_sessao') {
        recarregar(); setIniciar({ aberto: true, depois: i })
      } else setErro(textoErro(x))
    }
  }, [est, id, recarregar])

  const ctx: Ctx = {
    id, habilitado, celular, est, restante_s, recarregar, revelado, revelarItem,
    abrirIniciar: (depois) => setIniciar({ aberto: true, depois }),
    pedirAprovacao: (tipo, itens) => setPedido({ tipo, itens }),
    oficio, adicionarOficio: (r) => setOficio((o) => (o.includes(r) ? o : [...o, r])),
    removerOficio: (r) => setOficio((o) => o.filter((x) => x !== r)), limparOficio: () => setOficio([]),
  }
  return (
    <C.Provider value={ctx}>
      {habilitado && <BarraSessao aviso={aviso} erro={erro} limparAviso={() => { setAviso(null); setErro(null) }} />}
      {children}
      {habilitado && <>
        <DialogoIniciar aberto={iniciar.aberto} aoFechar={() => setIniciar({ aberto: false })}
          aoIniciar={async (cod, txt) => {
            await R.iniciar(id, cod, txt)
            const depois = iniciar.depois
            setIniciar({ aberto: false })
            recarregar()
            if (depois) { try { await R.revelar(id, depois.classe, depois.rotulo); recarregar() } catch (x) { setErro(textoErro(x)) } }
          }} motivos={est?.motivos ?? {}} />
        <DialogoPedido p={pedido} aoFechar={() => setPedido(null)} aoEnviar={async (motivo) => {
          const r = await R.pedir(id, pedido!.tipo, pedido!.itens, motivo)
          setPedido(null); setErro(null)
          setAviso(`Pedido nº ${r.pedido} enviado ao aprovador. Os demais itens continuam disponíveis; este fica bloqueado até a decisão.`)
          recarregar()
        }} />
        <MarcaDagua />
      </>}
    </C.Provider>
  )
}

function mmss(s: number) {
  const h = Math.floor(s / 3600), m = Math.floor((s % 3600) / 60), ss = s % 60
  return h ? `${h} h ${String(m).padStart(2, '0')} min` : `${m}:${String(ss).padStart(2, '0')}`
}

function BarraSessao({ aviso, erro, limparAviso }: { aviso: string | null; erro: string | null; limparAviso: () => void }) {
  const a = useAnalise()!
  const s = a.est?.sessao
  const [ocupado, setOcupado] = useState(false)
  const fazer = async (f: () => Promise<unknown>) => { setOcupado(true); try { await f(); a.recarregar() } finally { setOcupado(false) } }
  if (a.celular) return <p className="barra-sessao secundario">Revelação disponível em telas maiores (768 px ou mais).</p>
  return (
    <div className="barra-sessao" role="region" aria-label="Sessão de análise">
      {s ? <>
        <span className="estado tom-roxo"><Icone nome="fa-user-secret" /> Sessão de análise ativa até {dataHora(s.expira_em)}</span>
        <span>restam <strong>{mmss(a.restante_s ?? 0)}</strong></span>
        <span>{s.total ? 'revelação total aprovada' : <>{numero(a.est!.cota.sessao)} de {numero(a.est!.cota.sessao_limite)} revelados</>}
          {' '}· investigação {numero(a.est!.cota.investigacao)} de {numero(a.est!.cota.investigacao_limite)}</span>
        <span className="secundario">Motivo: {s.motivo}</span>
        {s.pode_prorrogar && <button type="button" className="br-button small secondary" disabled={ocupado}
          onClick={() => fazer(() => R.prorrogar(a.id))}>Prorrogar</button>}
        <button type="button" className="br-button small secondary" disabled={ocupado} onClick={() => fazer(() => R.encerrar(a.id))}>Encerrar</button>
        <button type="button" className="br-button small tertiary" onClick={() => a.pedirAprovacao('revelacao_total', [])}>Pedir revelação total</button>
      </> : <>
        <span className="secundario">Valores reais só numa sessão de análise (motivo, até 4 h, registrada na trilha).</span>
        <button type="button" className="br-button small secondary" onClick={() => a.abrirIniciar()}><Icone nome="fa-user-secret" /> Iniciar sessão de análise</button>
      </>}
      <div aria-live="polite" className="barra-sessao-aviso">
        {aviso && <Mensagem tipo="info">{aviso} <button type="button" className="br-button small tertiary" onClick={limparAviso}>Ok</button></Mensagem>}
        {erro && <Mensagem tipo="warning">{erro}</Mensagem>}
      </div>
    </div>
  )
}

function DialogoIniciar({ aberto, aoFechar, aoIniciar, motivos }: { aberto: boolean; aoFechar: () => void;
  aoIniciar: (cod: string, txt?: string) => Promise<void>; motivos: Record<string, string> }) {
  const [cod, setCod] = useState('')
  const [txt, setTxt] = useState('')
  const [erro, setErro] = useState<string | null>(null)
  async function ok() {
    if (!cod) return setErro('Escolha o motivo.')
    if (cod === 'outro' && txt.trim().length < 10) return setErro('Descreva o motivo (mínimo de 10 caracteres).')
    if (pareceIdentificador(txt)) return setErro('Não escreva CPF ou título no motivo.')
    try { await aoIniciar(cod, cod === 'outro' ? txt.trim() : undefined); setCod(''); setTxt(''); setErro(null) } catch (x) { setErro(textoErro(x)) }
  }
  return (
    <Dialogo aberto={aberto} titulo="Iniciar sessão de análise" aoFechar={aoFechar}
      rodape={<><button type="button" className="br-button secondary" onClick={aoFechar}>Cancelar</button>
        <button type="button" className="br-button primary" onClick={ok}>Iniciar sessão</button></>}>
      <p>A sessão dura até 4 h (prorrogável duas vezes), com cota de 30 itens. O motivo e cada item revelado vão para a trilha.
        Pode ser pedida a confirmação da sua identidade.</p>
      <fieldset>
        <legend>Motivo</legend>
        {Object.entries(motivos).map(([k, v]) => <div key={k} className="br-radio">
          <input id={`motivo-${k}`} type="radio" name="motivo-sessao" value={k} checked={cod === k} onChange={() => setCod(k)} />
          <label htmlFor={`motivo-${k}`}>{v}</label></div>)}
      </fieldset>
      {cod === 'outro' && <Area id="motivo-outro" rotulo="Descreva o motivo" obrigatorio rows={2} value={txt} onChange={(e) => setTxt(e.target.value)} />}
      {erro && <Mensagem tipo="danger">{erro}</Mensagem>}
    </Dialogo>
  )
}

const NOME_PEDIDO: Record<string, string> = { revelacao_cota: 'Pedir revelação acima da cota', revelacao_terceiro: 'Pedir revelação de dado de terceiro',
  revelacao_total: 'Pedir revelação total da investigação', lista_oficio: 'Pedir lista para ofício' }

function DialogoPedido({ p, aoFechar, aoEnviar }: { p: { tipo: string; itens: Item[] } | null; aoFechar: () => void;
  aoEnviar: (motivo: string) => Promise<void> }) {
  const [motivo, setMotivo] = useState('')
  const [erro, setErro] = useState<string | null>(null)
  async function ok() {
    if (motivo.trim().length < 10) return setErro('Escreva o motivo (mínimo de 10 caracteres).')
    if (pareceIdentificador(motivo)) return setErro('Não escreva CPF ou título no motivo.')
    try { await aoEnviar(motivo.trim()); setMotivo(''); setErro(null) } catch (x) { setErro(textoErro(x)) }
  }
  return (
    <Dialogo aberto={Boolean(p)} titulo={p ? NOME_PEDIDO[p.tipo] ?? 'Pedir aprovação' : ''} aoFechar={aoFechar}
      rodape={<><button type="button" className="br-button secondary" onClick={aoFechar}>Cancelar</button>
        <button type="button" className="br-button primary" onClick={ok}>Enviar ao aprovador</button></>}>
      {p && <p>{p.itens.length ? <>Itens: {p.itens.map((i) => i.rotulo === i.classe ? i.classe : i.rotulo).join(', ')}.</> : 'Todos os itens da investigação.'}
        {' '}Outra pessoa decide; o aprovador vê a quantidade, a classe e os motivos, nunca os valores.</p>}
      <Area id="motivo-pedido" rotulo="Motivo" obrigatorio rows={3} value={motivo} onChange={(e) => setMotivo(e.target.value)} erro={erro ?? undefined} />
    </Dialogo>
  )
}

function MarcaDagua() {
  const a = useAnalise()!
  const { eu } = useSessao()
  const [hora, setHora] = useState(() => new Date())
  useEffect(() => { const t = setInterval(() => setHora(new Date()), 60_000); return () => clearInterval(t) }, [])
  if (!a.est?.sessao || !a.est.revelados.length || a.celular) return null
  const texto = `${eu.usuario} · ${hora.toLocaleString('pt-BR', { dateStyle: 'short', timeStyle: 'short' })}`
  // o texto sai por CSS (content: attr(data-t)): é dissuasão visual, não conteúdo; não entra na árvore de acessibilidade
  return <div className="marca-dagua" aria-hidden="true">{Array.from({ length: 40 }, (_, k) => <span key={k} data-t={texto} />)}</div>
}

/** Ao lado do pseudônimo: o valor revelado, ou o botão "Revelar". */
export function Revelar({ classe, rotulo, curto }: { classe: 'conta' | 'ip' | 'sessao' | 'evento'; rotulo?: string | null; curto?: boolean }) {
  const a = useAnalise()
  if (!a?.habilitado || a.celular || !rotulo || /numeração no fechamento|Tentativas com/.test(rotulo)) return null
  const r = a.revelado(classe, rotulo)
  if (r) return <span className="revelado"> · <span className="valor-revelado">{R.textoValor(classe === 'evento' ? 'evento completo abaixo' : r.valor)}</span>
    {' '}<Icone nome="fa-eye" /> <span className="secundario">Revelado</span></span>
  const nome = classe === 'evento' ? 'o evento completo' : rotulo
  return <button type="button" className="br-button small tertiary revelar" onClick={() => a.revelarItem({ classe, rotulo })}>
    <Icone nome="fa-eye" /> {curto ? 'Revelar' : `Revelar ${classe === 'evento' ? 'evento completo' : ''}`.trim()}<span className="sr-only"> {nome}</span></button>
}

/** Painel da lista para ofício (Eventos): revisão dos IPs, motivo, fundamento e destinatário; pedidos e tabelas. */
export function ListaOficio() {
  const a = useAnalise()
  const [motivo, setMotivo] = useState('')
  const [fundamento, setFundamento] = useState('')
  const [dest, setDest] = useState('')
  const [erro, setErro] = useState<string | null>(null)
  const [feito, setFeito] = useState<string | null>(null)
  if (!a?.habilitado || a.celular) return null
  const listas = (a.est?.pedidos ?? []).filter((p) => p.tipo === 'lista_oficio')
  if (!a.oficio.length && !listas.length) return null
  async function enviar() {
    if (motivo.trim().length < 10) return setErro('Escreva o motivo (mínimo de 10 caracteres).')
    if (fundamento.trim().length < 10) return setErro('Informe o fundamento (ordem judicial ou competência legal do requisitante).')
    if ([motivo, fundamento, dest].some(pareceIdentificador)) return setErro('Não escreva CPF ou título nos campos.')
    try {
      const r = await R.pedir(a!.id, 'lista_oficio', a!.oficio.map((rotulo) => ({ rotulo })), motivo.trim(), fundamento.trim(), dest.trim() || undefined)
      setFeito(`Lista nº ${r.pedido} enviada ao aprovador (${r.quantidade} IPs).`)
      a!.limparOficio(); setMotivo(''); setFundamento(''); setDest(''); setErro(null); a!.recarregar()
    } catch (x) { setErro(textoErro(x)) }
  }
  return (
    <section className="br-card lista-oficio" aria-labelledby="t-oficio">
      <div className="card-header"><h2 id="t-oficio">Lista para ofício</h2></div>
      <div className="card-content">
        {feito && <Mensagem tipo="success" papel="status">{feito}</Mensagem>}
        {a.oficio.length > 0 && <>
          <p>Revise antes de enviar. Depois da aprovação em bloco, a tabela do ofício sai com os IPs reais e os horários em UTC, e
            cada IP vai para a trilha.</p>
          <ul className="chips" aria-label="IPs na lista">{a.oficio.map((r) => <li key={r} className="chip">{r}
            <button type="button" aria-label={`Tirar ${r} da lista`} onClick={() => a.removerOficio(r)}><Icone nome="fa-times" /></button></li>)}</ul>
          <Area id="oficio-motivo" rotulo="Motivo" obrigatorio rows={2} value={motivo} onChange={(e) => setMotivo(e.target.value)} />
          <Area id="oficio-fundamento" rotulo="Fundamento (ordem judicial — Lei 12.965/2014, art. 10, § 1º e art. 22 — ou competência legal)"
            obrigatorio rows={2} value={fundamento} onChange={(e) => setFundamento(e.target.value)} />
          <Campo id="oficio-destino" rotulo="Provedor de destino" value={dest} onChange={(e) => setDest(e.target.value)} />
          {erro && <Mensagem tipo="danger">{erro}</Mensagem>}
          <button type="button" className="br-button primary" onClick={enviar}>Enviar a lista ao aprovador</button>
        </>}
        {listas.length > 0 && <div className="br-table"><table>
          <caption>Listas pedidas</caption>
          <thead><tr><th scope="col">Lista</th><th scope="col">IPs</th><th scope="col">Situação</th><th scope="col">Tabela</th></tr></thead>
          <tbody>{listas.map((p) => <tr key={p.pedido}><td>nº {p.pedido}</td><td>{p.quantidade}</td>
            <td>{p.status === 'aprovado' ? 'Aprovada' : p.status === 'recusado' ? 'Recusada' : 'Aguardando aprovação'}</td>
            <td>{p.status === 'aprovado' ? <a className="br-button small secondary" href={R.urlTabelaOficio(a.id, p.pedido)} download>
              Baixar tabela (XLSX)<span className="sr-only"> da lista {p.pedido}</span></a> : '—'}</td></tr>)}</tbody>
        </table></div>}
      </div>
    </section>
  )
}

/** Botão "Adicionar à lista para ofício" para um rótulo de IP. */
export function AdicionarOficio({ rotulo }: { rotulo?: string | null }) {
  const a = useAnalise()
  if (!a?.habilitado || a.celular || !rotulo || !/^IP \d+$/.test(rotulo)) return null
  const ja = a.oficio.includes(rotulo)
  return <button type="button" className="br-button small tertiary" disabled={ja} onClick={() => a.adicionarOficio(rotulo)}>
    <Icone nome="fa-file-alt" /> {ja ? 'Na lista para ofício' : 'Adicionar à lista para ofício'}<span className="sr-only"> {rotulo}</span></button>
}

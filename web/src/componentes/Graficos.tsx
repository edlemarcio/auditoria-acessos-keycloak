/**
 * Gráficos da análise (W3, §7.6): série por janela, mapa de calor dia × hora e barras de ranking. SVG e CSS do próprio
 * app (CSP sem script externo). Regras: logins na série 1 (azul) e falhas na série 2 (laranja), paleta validada nos
 * dois temas; linhas de 2 px, grade de 1 px recessiva, legenda sempre presente com duas séries, mira com uma tooltip
 * para todas as séries, alvo por teclado, e "Ver como tabela" em cada gráfico (o laranja fica abaixo de 3:1 no tema
 * claro: a tabela e os rótulos diretos são o alívio). Texto sempre nas cores de texto, nunca na cor da série.
 */
import { useEffect, useMemo, useRef, useState, type KeyboardEvent, type PointerEvent } from 'react'
import { numero } from '../dominio/formato'

const DIAS = ['seg', 'ter', 'qua', 'qui', 'sex', 'sáb', 'dom']
const DIAS_LONGOS = ['segunda', 'terça', 'quarta', 'quinta', 'sexta', 'sábado', 'domingo']

function useLargura<T extends HTMLElement>(): [React.RefObject<T | null>, number] {
  const ref = useRef<T>(null)
  const [l, setL] = useState(720)
  useEffect(() => {
    const el = ref.current
    if (!el || typeof ResizeObserver === 'undefined') return
    const ro = new ResizeObserver((es) => { const w = Math.floor(es[0].contentRect.width); if (w > 0) setL(w) })
    ro.observe(el)
    return () => ro.disconnect()
  }, [])
  return [ref, l]
}

function escala(max: number): { topo: number; marcas: number[] } {
  if (max <= 0) return { topo: 1, marcas: [0, 1] }
  const passo0 = max / 4
  const p10 = 10 ** Math.floor(Math.log10(passo0))
  const passo = [1, 2, 2.5, 5, 10].map((m) => m * p10).find((p) => p >= passo0) ?? p10 * 10
  const topo = Math.ceil(max / passo) * passo
  return { topo, marcas: Array.from({ length: Math.round(topo / passo) + 1 }, (_, i) => i * passo) }
}

export interface Serie { chave: string; nome: string; cor: 1 | 2; valores: number[] }

/** Série temporal com mira: uma tooltip lista todas as séries no X; ←/→ movem a mira; Enter abre o ponto. */
export function GraficoSerie({ titulo, rotulos, series, rotuloLongo, aoSelecionar, altura = 240 }: {
  titulo: string; rotulos: string[]; series: Serie[]; rotuloLongo: (i: number) => string
  aoSelecionar?: (i: number) => void; altura?: number
}) {
  const [ref, largura] = useLargura<HTMLDivElement>()
  const [tabela, setTabela] = useState(false)
  const [i, setI] = useState<number | null>(null)
  const m = { e: 56, d: 16, t: 12, b: 28 }
  const w = Math.max(240, largura), h = altura
  const n = rotulos.length
  const { topo, marcas } = useMemo(() => escala(Math.max(0, ...series.flatMap((s) => s.valores))), [series])
  const x = (k: number) => m.e + (n <= 1 ? 0 : (k * (w - m.e - m.d)) / (n - 1))
  const y = (v: number) => h - m.b - (v / topo) * (h - m.t - m.b)
  const passoRot = Math.max(1, Math.ceil(n / Math.max(2, Math.floor((w - m.e) / 90))))
  const mover = (ev: PointerEvent<SVGSVGElement>) => {
    const r = ev.currentTarget.getBoundingClientRect()
    const px = ((ev.clientX - r.left) / r.width) * w
    setI(Math.max(0, Math.min(n - 1, Math.round(((px - m.e) / (w - m.e - m.d)) * (n - 1)))))
  }
  const tecla = (ev: KeyboardEvent<SVGSVGElement>) => {
    if (!n) return
    if (ev.key === 'ArrowRight' || ev.key === 'ArrowLeft') {
      ev.preventDefault()
      setI((k) => Math.max(0, Math.min(n - 1, (k ?? (ev.key === 'ArrowRight' ? -1 : n)) + (ev.key === 'ArrowRight' ? 1 : -1))))
    } else if (ev.key === 'Home') { ev.preventDefault(); setI(0) }
    else if (ev.key === 'End') { ev.preventDefault(); setI(n - 1) }
    else if (ev.key === 'Enter' && i != null && aoSelecionar) { ev.preventDefault(); aoSelecionar(i) }
  }
  const caminho = (vs: number[]) => vs.map((v, k) => `${k ? 'L' : 'M'}${x(k).toFixed(1)},${y(v).toFixed(1)}`).join('')
  const ultimo = n - 1
  return (
    <figure className="grafico">
      <div className="grafico-topo">
        <figcaption className="grafico-titulo">{titulo}</figcaption>
        <ul className="legenda" aria-label="Legenda">
          {series.map((s) => <li key={s.chave}><span className={`chave-linha serie-${s.cor}`} aria-hidden="true" />{s.nome}</li>)}
        </ul>
        <button type="button" className="br-button small secondary" aria-pressed={tabela} onClick={() => setTabela((t) => !t)}>
          {tabela ? 'Ver como gráfico' : 'Ver como tabela'}</button>
      </div>
      {tabela ? <TabelaSerie rotulos={rotulos} series={series} rotuloLongo={rotuloLongo} aoSelecionar={aoSelecionar} />
        : <div ref={ref} className="grafico-area" style={{ height: h }}>
          {!n ? <p className="grafico-vazio">Sem eventos no período.</p> : <>
            <svg width={w} height={h} viewBox={`0 0 ${w} ${h}`} role="img" tabIndex={0}
              aria-label={`${titulo}. ${n} janelas. Use as setas para percorrer${aoSelecionar ? ' e Enter para ver os eventos da janela' : ''}.`}
              onPointerMove={mover} onPointerLeave={() => setI(null)} onKeyDown={tecla} onBlur={() => setI(null)}
              onClick={() => { if (i != null && aoSelecionar) aoSelecionar(i) }} className={aoSelecionar ? 'clicavel' : undefined}>
              {marcas.map((v) => <g key={v}>
                <line className="grade" x1={m.e} x2={w - m.d} y1={y(v)} y2={y(v)} />
                <text className="eixo" x={m.e - 8} y={y(v)} dy="0.32em" textAnchor="end">{numero(v)}</text>
              </g>)}
              {rotulos.map((r, k) => (k % passoRot === 0 || k === ultimo) && (k === ultimo || ultimo - k >= passoRot / 2) &&
                <text key={k} className="eixo" x={x(k)} y={h - 8} textAnchor={k === 0 ? 'start' : k === ultimo ? 'end' : 'middle'}>{r}</text>)}
              {series.map((s) => <path key={s.chave} className={`linha serie-${s.cor}`} d={caminho(s.valores)} />)}
              {series.map((s) => n > 0 && <circle key={s.chave} className={`ponto serie-${s.cor}`} cx={x(ultimo)} cy={y(s.valores[ultimo])} r={4} />)}
              {i != null && <g>
                <line className="mira" x1={x(i)} x2={x(i)} y1={m.t} y2={h - m.b} />
                {series.map((s) => <circle key={s.chave} className={`ponto serie-${s.cor}`} cx={x(i)} cy={y(s.valores[i])} r={4} />)}
              </g>}
            </svg>
            {i != null && <div className="dica" role="status" style={{ left: Math.min(Math.max(x(i) + 12, 0), w - 200), top: m.t }}>
              <div className="dica-titulo">{rotuloLongo(i)}</div>
              {series.map((s) => <div key={s.chave} className="dica-linha">
                <span className={`chave-linha serie-${s.cor}`} aria-hidden="true" /><strong>{numero(s.valores[i])}</strong> {s.nome}</div>)}
              {aoSelecionar && <div className="dica-rodape">Clique ou Enter: ver eventos</div>}
            </div>}
          </>}
        </div>}
    </figure>
  )
}

function TabelaSerie({ rotulos, series, rotuloLongo, aoSelecionar }: { rotulos: string[]; series: Serie[];
  rotuloLongo: (i: number) => string; aoSelecionar?: (i: number) => void }) {
  return (
    <div className="br-table tabela-rolavel" tabIndex={0} role="region" aria-label="Tabela do gráfico">
      <table>
        <thead><tr><th scope="col">Janela</th>{series.map((s) => <th key={s.chave} scope="col" className="num">{s.nome}</th>)}
          {aoSelecionar && <th scope="col"><span className="sr-only">Ação</span></th>}</tr></thead>
        <tbody>{rotulos.map((_, k) => <tr key={k}>
          <th scope="row">{rotuloLongo(k)}</th>
          {series.map((s) => <td key={s.chave} className="num">{numero(s.valores[k])}</td>)}
          {aoSelecionar && <td><button type="button" className="br-button small tertiary" onClick={() => aoSelecionar(k)}>Ver eventos</button></td>}
        </tr>)}</tbody>
      </table>
    </div>
  )
}

/** Mapa de calor dia da semana × hora (logins), rampa sequencial de um matiz; tabela equivalente navegável. */
export function MapaCalor({ celulas, titulo }: { celulas: { dia_semana: number; hora: number; n: number }[]; titulo: string }) {
  const [tabela, setTabela] = useState(false)
  const [foco, setFoco] = useState<{ d: number; h: number } | null>(null)
  const grade = useMemo(() => {
    const g = Array.from({ length: 7 }, () => Array<number>(24).fill(0))
    for (const c of celulas) g[c.dia_semana - 1][c.hora] = c.n
    return g
  }, [celulas])
  const max = Math.max(0, ...celulas.map((c) => c.n))
  const passo = (v: number) => (v <= 0 ? 0 : Math.min(5, 1 + Math.floor((v / max) * 4.999)))
  return (
    <figure className="grafico">
      <div className="grafico-topo">
        <figcaption className="grafico-titulo">{titulo}</figcaption>
        <div className="legenda-escala" aria-hidden="true"><span>menos</span>{[1, 2, 3, 4, 5].map((k) => <i key={k} className={`seq-${k}`} />)}<span>mais</span></div>
        <button type="button" className="br-button small secondary" aria-pressed={tabela} onClick={() => setTabela((t) => !t)}>
          {tabela ? 'Ver como gráfico' : 'Ver como tabela'}</button>
      </div>
      {tabela || !max ? (
        <div className="br-table tabela-rolavel" tabIndex={0} role="region" aria-label="Logins por dia da semana e hora">
          {!max ? <p>Sem logins no período.</p> : <table>
            <thead><tr><th scope="col">Dia</th>{Array.from({ length: 24 }, (_, h) => <th key={h} scope="col" className="num">{h}h</th>)}</tr></thead>
            <tbody>{grade.map((linha, d) => <tr key={d}><th scope="row">{DIAS_LONGOS[d]}</th>
              {linha.map((v, h) => <td key={h} className="num">{v ? numero(v) : '·'}</td>)}</tr>)}</tbody>
          </table>}
        </div>
      ) : (
        <div className="mapa-calor">
        <div role="grid" aria-label={`${titulo}: setas para percorrer`}>
          <div role="row" className="mapa-linha mapa-cab"><span role="columnheader"><span className="sr-only">Dia</span></span>
            {Array.from({ length: 24 }, (_, h) => <span key={h} role="columnheader" className="mapa-hora">
              <span className={h % 3 === 0 ? undefined : 'sr-only'}>{h}h</span></span>)}</div>
          {grade.map((linha, d) => <div key={d} role="row" className="mapa-linha">
            <span role="rowheader" className="mapa-dia">{DIAS[d]}</span>
            {linha.map((v, h) => {
              const ativo = foco?.d === d && foco?.h === h
              return <span key={h} role="gridcell" tabIndex={(foco ? ativo : d === 0 && h === 0) ? 0 : -1}
                className={`mapa-celula seq-${passo(v)}${ativo ? ' ativo' : ''}`}
                aria-label={`${DIAS_LONGOS[d]}, ${h}h: ${numero(v)} logins`}
                onFocus={() => setFoco({ d, h })} onPointerEnter={() => setFoco({ d, h })}
                onKeyDown={(ev) => {
                  const mv: Record<string, [number, number]> = { ArrowRight: [0, 1], ArrowLeft: [0, -1], ArrowDown: [1, 0], ArrowUp: [-1, 0] }
                  const dl = mv[ev.key]
                  if (!dl) return
                  ev.preventDefault()
                  const nd = Math.max(0, Math.min(6, d + dl[0])), nh = Math.max(0, Math.min(23, h + dl[1]))
                  const alvo = ev.currentTarget.parentElement?.parentElement?.children[nd + 1]?.children[nh + 1] as HTMLElement | undefined
                  alvo?.focus()
                }} />
            })}
          </div>)}
        </div>
          <p className="mapa-leitura" aria-live="polite">{foco ? `${DIAS_LONGOS[foco.d]}, ${foco.h}h: ${numero(grade[foco.d][foco.h])} logins` : ' '}</p>
        </div>
      )}
    </figure>
  )
}

/** Barras horizontais (uma série): rótulo, barra e valor; cada linha é um botão que abre os eventos filtrados. */
export function Barras({ titulo, itens, aoSelecionar, unidade = 'eventos' }: {
  titulo: string; itens: { rotulo: string; valor: number; detalhe?: string }[]; aoSelecionar?: (k: number) => void; unidade?: string
}) {
  const max = Math.max(1, ...itens.map((i) => i.valor))
  return (
    <figure className="grafico">
      <div className="grafico-topo"><figcaption className="grafico-titulo">{titulo}</figcaption></div>
      {!itens.length ? <p className="grafico-vazio">Nada a mostrar.</p> : <ol className="barras">
        {itens.map((it, k) => {
          const conteudo = <>
            <span className="barra-rotulo">{it.rotulo}</span>
            <span className="barra-trilho" aria-hidden="true"><span className="barra serie-1" style={{ width: `${(it.valor / max) * 100}%` }} /></span>
            <span className="barra-valor">{numero(it.valor)}{it.detalhe ? <small> · {it.detalhe}</small> : null}</span>
          </>
          return <li key={k}>{aoSelecionar
            ? <button type="button" className="barra-linha" onClick={() => aoSelecionar(k)}>{conteudo}
              <span className="sr-only"> {unidade}; ver eventos</span></button>
            : <div className="barra-linha">{conteudo}</div>}</li>
        })}
      </ol>}
    </figure>
  )
}

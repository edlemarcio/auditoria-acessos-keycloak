/**
 * Acompanhamento ao vivo por SSE (contrato §8; PROPOSTA §8.8). Lido com fetch + stream (e não EventSource) para
 * mandar `Last-Event-ID` também nas reconexões feitas pela tela e tratar 401/429 como o resto da API.
 */
import { useEffect, useRef, useState } from 'react'
import { api, ErroApi } from './cliente'
import { acompanhamento } from './rotas'
import type { Acompanhamento } from './tipos'

export type Conexao = 'conectando' | 'ao_vivo' | 'reconectando' | 'consulta_periodica' | 'parado'

export interface EventoSSE { id?: string; event: string; data: string }

/** Separa os eventos de um pedaço de texto SSE; devolve os completos e o resto. */
export function lerEventos(buffer: string): { eventos: EventoSSE[]; resto: string } {
  const partes = buffer.replace(/\r\n/g, '\n').split('\n\n')
  const resto = partes.pop() ?? ''
  const eventos = partes.map((bloco) => {
    const e: EventoSSE = { event: 'message', data: '' }
    const dados: string[] = []
    for (const linha of bloco.split('\n')) {
      if (!linha || linha.startsWith(':')) continue
      const i = linha.indexOf(':')
      const campo = i < 0 ? linha : linha.slice(0, i)
      const valor = i < 0 ? '' : linha.slice(i + 1).replace(/^ /, '')
      if (campo === 'id') e.id = valor
      else if (campo === 'event') e.event = valor
      else if (campo === 'data') dados.push(valor)
    }
    e.data = dados.join('\n')
    return e
  }).filter((e) => e.data || e.event !== 'message')
  return { eventos, resto }
}

const espera = (ms: number, sinal: AbortSignal) => new Promise<void>((ok) => {
  const t = setTimeout(ok, ms)
  sinal.addEventListener('abort', () => { clearTimeout(t); ok() }, { once: true })
})

export function useAoVivo(id: number, ativo: boolean) {
  const [dados, setDados] = useState<Acompanhamento | null>(null)
  const [conexao, setConexao] = useState<Conexao>('conectando')
  const [anuncio, setAnuncio] = useState('')
  const ultimoAnuncio = useRef(0)
  const ultimoId = useRef<string | null>(null)

  useEffect(() => {
    if (!ativo) { setConexao('parado'); return }
    const ctl = new AbortController()
    const sinal = ctl.signal
    const receber = (a: Acompanhamento) => {
      setDados(a)
      const agora = Date.now()
      if (agora - ultimoAnuncio.current >= 10_000) {   // aria-live no máximo a cada 10 s (§7.9)
        ultimoAnuncio.current = agora
        setAnuncio(`Coleta em ${Math.round(a.progresso_pct)}%, ${a.eventos.toLocaleString('pt-BR')} eventos.`)
      }
    }
    acompanhamento(id).then(receber).catch(() => {})

    async function laco() {
      let pausa = 1000
      while (!sinal.aborted) {
        const vigia = new AbortController()
        const parar = () => vigia.abort()
        sinal.addEventListener('abort', parar, { once: true })
        let silencio: ReturnType<typeof setTimeout> | undefined
        const rearmar = () => { clearTimeout(silencio); silencio = setTimeout(() => vigia.abort(), 45_000) }
        try {
          const h: Record<string, string> = { Accept: 'text/event-stream' }
          if (ultimoId.current) h['Last-Event-ID'] = ultimoId.current
          const r = await fetch(`/api/investigacoes/${id}/acompanhamento/stream`, { headers: h, credentials: 'same-origin', signal: vigia.signal })
          if (r.status === 401) { await api('/api/eu').catch(() => {}); return }
          if (r.status === 429 || r.status === 404 && !r.headers.get('content-type')?.includes('event-stream')) {
            // limite de 3 conexões por usuário (ou servidor sem SSE): consulta a cada 15 s
            setConexao('consulta_periodica')
            while (!sinal.aborted) {
              await espera(15_000, sinal)
              if (!sinal.aborted) await acompanhamento(id).then(receber).catch(() => {})
            }
            return
          }
          if (!r.ok || !r.body) throw new ErroApi(r.status, 'sse', 'Falha no acompanhamento')
          setConexao('ao_vivo')
          pausa = 1000
          rearmar()
          const leitor = r.body.pipeThrough(new TextDecoderStream()).getReader()
          let buf = ''
          for (;;) {
            const { value, done } = await leitor.read()
            if (done) break
            rearmar()
            const { eventos, resto } = lerEventos(buf + value)
            buf = resto
            for (const e of eventos) {
              if (e.id) ultimoId.current = e.id
              if (e.event === 'progresso') { try { receber(JSON.parse(e.data)) } catch { /* evento malformado */ } }
            }
          }
        } catch { /* queda: reconecta abaixo */ } finally {
          clearTimeout(silencio)
          sinal.removeEventListener('abort', parar)
        }
        if (sinal.aborted) return
        setConexao('reconectando')
        await espera(pausa, sinal)
        pausa = Math.min(pausa * 2, 15_000)
      }
    }
    void laco()
    return () => ctl.abort()
  }, [id, ativo])

  return { dados, conexao, anuncio }
}

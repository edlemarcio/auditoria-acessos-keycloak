import { useCallback, useEffect, useRef, useState } from 'react'
import { Link } from 'react-router'
import { marcarLida, marcarTodasLidas, notificacoes as buscar } from '../api/rotas'
import type { Notificacao } from '../api/tipos'
import { dataHora } from '../dominio/formato'

/** Sino do cabeçalho e central de notificações (§7.12). */
export function Notificacoes() {
  const [lista, setLista] = useState<Notificacao[] | null>(null)
  const [aberto, setAberto] = useState(false)
  const botao = useRef<HTMLButtonElement>(null)
  const painel = useRef<HTMLDivElement>(null)

  const carregar = useCallback(() => { buscar().then(setLista).catch(() => setLista((l) => l ?? [])) }, [])
  useEffect(() => {
    carregar()
    const t = setInterval(carregar, 60_000)
    return () => clearInterval(t)
  }, [carregar])
  useEffect(() => {
    if (!aberto) return
    painel.current?.querySelector<HTMLElement>('h2')?.focus()
    const fora = (e: MouseEvent) => {
      if (!painel.current?.contains(e.target as Node) && !botao.current?.contains(e.target as Node)) setAberto(false)
    }
    const esc = (e: KeyboardEvent) => { if (e.key === 'Escape') { setAberto(false); botao.current?.focus() } }
    document.addEventListener('mousedown', fora)
    document.addEventListener('keydown', esc)
    return () => { document.removeEventListener('mousedown', fora); document.removeEventListener('keydown', esc) }
  }, [aberto])

  const naoLidas = lista?.filter((n) => !n.lida).length ?? 0
  const fechar = () => { setAberto(false); botao.current?.focus() }
  const ler = async (n: Notificacao) => {
    if (!n.lida) { await marcarLida(n.id).catch(() => {}); carregar() }
  }

  return (
    <div className="notificacoes">
      <button ref={botao} type="button" className="br-button circle sino" aria-expanded={aberto} aria-controls="painel-notificacoes"
        aria-label={naoLidas ? `Notificações: ${naoLidas} não lidas` : 'Notificações: nenhuma não lida'} onClick={() => setAberto((a) => !a)}>
        <i className="fas fa-bell" aria-hidden="true" />
        {naoLidas > 0 && <span className="contador" aria-hidden="true">{naoLidas}</span>}
      </button>
      <div id="painel-notificacoes" ref={painel} className="painel-notificacoes" hidden={!aberto} role="region"
        aria-label="Central de notificações">
        <div className="painel-topo">
          <h2 tabIndex={-1}>Notificações</h2>
          {naoLidas > 0 && <button type="button" className="br-button small secondary"
            onClick={() => marcarTodasLidas().then(carregar).then(() => painel.current?.querySelector<HTMLElement>('h2')?.focus()).catch(() => {})}>Marcar todas como lidas</button>}
        </div>
        {!lista?.length ? <p className="vazio-curto">Nenhuma notificação.</p> : (
          <ul className="lista-notificacoes">
            {lista.map((n) => (
              <li key={n.id} className={n.lida ? 'lida' : 'nao-lida'}>
                <span className="sr-only">{n.lida ? 'Lida: ' : 'Não lida: '}</span>
                {n.investigacao != null
                  ? <Link to={`/investigacoes/${n.investigacao}`} onClick={() => { void ler(n); setAberto(false) }}>{n.texto}</Link>
                  : <span>{n.texto}</span>}
                <span className="quando">{dataHora(n.quando)}</span>
                {!n.lida && <button type="button" className="br-button small tertiary" onClick={() => ler(n)}>
                  Marcar como lida</button>}
              </li>
            ))}
          </ul>
        )}
        <button type="button" className="br-button small tertiary" onClick={fechar}>Fechar</button>
      </div>
    </div>
  )
}

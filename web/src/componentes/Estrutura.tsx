import { useEffect, useRef, useState, type ReactNode } from 'react'
import { Link, NavLink, useLocation } from 'react-router'
import { navegador, postar } from '../api/cliente'
import { menuPara, NOME_PAPEL, type Papel } from '../dominio/perfis'
import { useSessao } from '../sessao'
import { temaInicial, trocarTema } from '../tema'
import { Notificacoes } from './Notificacoes'
import { useTrilha } from './Pagina'

/** Estrutura das telas (§7.1): cabeçalho com sino, barra lateral filtrada por perfil e trilha de navegação. */
export function Estrutura({ children }: { children: ReactNode }) {
  const { eu } = useSessao()
  const local = useLocation()
  const trilha = useTrilha()
  const [menuAberto, setMenuAberto] = useState(false)
  const [tema, setTema] = useState(temaInicial())
  const anterior = useRef(local.pathname)

  useEffect(() => {
    setMenuAberto(false)
    if (anterior.current === local.pathname) return
    anterior.current = local.pathname
    // foco no título da nova tela, para o leitor de tela anunciar a troca
    const t = setTimeout(() => document.getElementById('titulo-tela')?.focus(), 50)
    return () => clearTimeout(t)
  }, [local.pathname])

  const itens = menuPara(eu.papeis)
  const alternarTema = () => { const t = tema === 'claro' ? 'escuro' : 'claro'; setTema(t); trocarTema(t) }
  const sair = async () => {
    try {
      await postar('/auth/sair')
    } finally { navegador.ir('/') }
  }

  return (
    <div className={`app${menuAberto ? ' menu-aberto' : ''}`}>
      <a className="pular" href="#conteudo">Ir para o conteúdo</a>
      <header className="br-header cabecalho">
        <div className="cabecalho-linha">
          <button type="button" className="br-button circle botao-menu" aria-label={menuAberto ? 'Fechar menu' : 'Abrir menu'}
            aria-expanded={menuAberto} aria-controls="menu-principal" onClick={() => setMenuAberto((a) => !a)}>
            <i className="fas fa-bars" aria-hidden="true" />
          </button>
          <Link to="/" className="marca"><i className="fas fa-shield-alt" aria-hidden="true" /> <span>kc-auditor</span></Link>
          <span className="subtitulo">Auditoria de acessos</span>
          <div className="cabecalho-acoes">
            <button type="button" className="br-button circle" onClick={alternarTema}
              aria-label={tema === 'claro' ? 'Usar tema escuro' : 'Usar tema claro'} aria-pressed={tema === 'escuro'}>
              <i className={`fas ${tema === 'claro' ? 'fa-moon' : 'fa-sun'}`} aria-hidden="true" />
            </button>
            <Notificacoes />
            <div className="usuario">
              <span className="usuario-nome">{eu.nome || eu.usuario}</span>
              <span className="usuario-papeis">{eu.papeis.map((p) => NOME_PAPEL[p as Papel] ?? p).join(', ')}</span>
            </div>
            <button type="button" className="br-button secondary small" onClick={sair}>Sair</button>
          </div>
        </div>
      </header>
      <div className="corpo">
        <nav id="menu-principal" className="barra-lateral" aria-label="Navegação principal">
          <ul className="menu-lista">
            {itens.map((m) => (
              <li key={m.rota}>
                <NavLink to={m.rota} end={m.rota === '/'} className={({ isActive }) => `menu-item${isActive ? ' active' : ''}`}>
                  <i className={`fas ${m.icone}`} aria-hidden="true" /> <span>{m.rotulo}</span>
                </NavLink>
              </li>
            ))}
          </ul>
        </nav>
        <main id="conteudo" className="conteudo" tabIndex={-1}>
          {trilha.length > 0 && (
            <nav className="br-breadcrumb migalhas" aria-label="Você está em">
              <ol className="crumb-list">
                <li className="crumb home"><Link to="/">Início</Link></li>
                {trilha.map((m, k) => (
                  <li key={k} className="crumb">
                    <i className="fas fa-chevron-right" aria-hidden="true" />
                    {m.rota && k < trilha.length - 1 ? <Link to={m.rota}>{m.rotulo}</Link> : <span aria-current="page">{m.rotulo}</span>}
                  </li>
                ))}
              </ol>
            </nav>
          )}
          {children}
        </main>
      </div>
    </div>
  )
}

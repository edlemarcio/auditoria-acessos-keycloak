import type { ReactNode } from 'react'
import { Link } from 'react-router'
import { ErroApi } from '../api/cliente'
import { indicador } from '../dominio/estados'
import { SemAcesso } from '../telas/SemAcesso'

export function Icone({ nome, rotulo }: { nome: string; rotulo?: string }) {
  return rotulo
    ? <i className={`fas ${nome}`} role="img" aria-label={rotulo} />
    : <i className={`fas ${nome}`} aria-hidden="true" />
}

/** Estado da investigação: cor + ícone + texto (§7.2). */
export function Indicador({ status, progresso }: { status: string; progresso?: number | null }) {
  const i = indicador(status, progresso)
  return (
    <span className={`estado tom-${i.tom}`} data-status={status}>
      <Icone nome={i.icone} /> {i.rotulo}
    </span>
  )
}

export function Mensagem({ tipo, titulo, children, papel }: { tipo: 'info' | 'success' | 'warning' | 'danger'; titulo?: string;
  children: ReactNode; papel?: 'alert' | 'status' }) {
  const icone = { info: 'fa-info-circle', success: 'fa-check-circle', warning: 'fa-exclamation-triangle', danger: 'fa-times-circle' }[tipo]
  return (
    <div className={`br-message ${tipo}`} role={papel}>
      <div className="icon"><Icone nome={`${icone} fa-lg`} /></div>
      <div className="content">
        {titulo && <span className="message-title">{titulo} </span>}
        <span className="message-body">{children}</span>
      </div>
    </div>
  )
}

/** Esqueleto da tela enquanto carrega (§7.12). */
export function Esqueleto({ linhas = 4, rotulo = 'Carregando' }: { linhas?: number; rotulo?: string }) {
  return (
    <div className="esqueleto" role="status" aria-live="polite">
      <span className="sr-only">{rotulo}…</span>
      {Array.from({ length: linhas }, (_, k) => <div key={k} className="esqueleto-linha" aria-hidden="true" />)}
    </div>
  )
}

export function Vazio({ children, acao }: { children: ReactNode; acao?: ReactNode }) {
  return (
    <div className="vazio">
      <Icone nome="fa-inbox fa-2x" />
      <p>{children}</p>
      {acao}
    </div>
  )
}

/** Erro de tela: sem acesso (§7.1), link expirado, erro do servidor com código de correlação (§7.12). */
export function ErroTela({ erro, investigacao, tentar }: { erro: unknown; investigacao?: number; tentar?: () => void }) {
  if (erro instanceof ErroApi) {
    if (erro.codigo === 'sem_acesso' || erro.codigo === 'designacao' || erro.codigo === 'inexistente' && investigacao != null)
      return <SemAcesso investigacao={investigacao} />
    if (erro.codigo === 'perfil' || erro.codigo === 'sem_perfil')
      return <Mensagem tipo="warning" titulo="Sem permissão." papel="alert">Seu perfil não dá acesso a esta tela. <Link to="/">Voltar ao início</Link></Mensagem>
    if (erro.status === 410 || erro.codigo === 'expirado')
      return <Mensagem tipo="warning" titulo="Link expirado." papel="alert">{erro.message || 'Este link expirou (válido por 10 min). Gere um novo em Pacotes.'}</Mensagem>
    if (erro.codigo === 'lacrada')
      return <Mensagem tipo="info" titulo="Coleta lacrada." papel="status">Os dados desta investigação só abrem depois da aprovação do pedido completo.</Mensagem>
    if (erro.status >= 500)
      return (
        <Mensagem tipo="danger" titulo="Algo deu errado do nosso lado." papel="alert">
          {erro.correlacao ? <>Informe ao suporte o código <strong className="codigo">{erro.correlacao}</strong>.</> : 'Tente de novo em instantes.'}
          {tentar && <> <button type="button" className="br-button secondary small" onClick={tentar}>Tentar de novo</button></>}
        </Mensagem>
      )
    if (erro.status === 401) return null
    return <Mensagem tipo="danger" papel="alert">{erro.message}</Mensagem>
  }
  return (
    <Mensagem tipo="danger" titulo="Não foi possível falar com o servidor." papel="alert">
      Verifique a conexão. {tentar && <button type="button" className="br-button secondary small" onClick={tentar}>Tentar de novo</button>}
    </Mensagem>
  )
}

export function textoErro(e: unknown): string {
  if (e instanceof ErroApi) {
    if (e.status >= 500) return `Algo deu errado do nosso lado.${e.correlacao ? ` Informe ao suporte o código ${e.correlacao}.` : ''}`
    return e.message
  }
  return 'Não foi possível falar com o servidor.'
}

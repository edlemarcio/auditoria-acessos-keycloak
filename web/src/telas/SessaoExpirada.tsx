import { useEffect } from 'react'
import { telaAtual, urlLogin } from '../api/cliente'

/** Sessão expirada (§7.12): login que volta à mesma tela; avisa que as revelações foram encerradas. */
export function SessaoExpirada() {
  useEffect(() => { document.title = 'Sessão expirada · kc-auditor' }, [])
  return (
    <main className="conteudo-solto" id="conteudo">
      <div className="br-card cartao-central">
        <div className="card-content">
          <h1><i className="fas fa-user-clock" aria-hidden="true" /> Sua sessão expirou</h1>
          <p>Por segurança, a sessão termina depois de 30 minutos sem atividade ou 8 horas de uso.
            Sessões de análise e revelações ativas foram encerradas.</p>
          <a className="br-button primary" href={urlLogin(false, telaAtual())}>Entrar de novo e voltar para esta tela</a>
        </div>
      </div>
    </main>
  )
}

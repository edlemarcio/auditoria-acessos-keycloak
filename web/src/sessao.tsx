import { createContext, useContext, useEffect, useState, type ReactNode } from 'react'
import { quandoSessaoExpirar, navegador, urlLogin, ErroApi } from './api/cliente'
import { eu as buscarEu } from './api/rotas'
import type { Eu } from './api/tipos'
import { tem as temPapel, type Papel } from './dominio/perfis'

interface Sessao { eu: Eu; tem: (...p: Papel[]) => boolean }
const Ctx = createContext<Sessao | null>(null)

export function useSessao(): Sessao {
  const s = useContext(Ctx)
  if (!s) throw new Error('fora da sessão')
  return s
}

export function ProvedorSessao({ children, expirada, erro }: { children: ReactNode; expirada: ReactNode;
  erro: (e: unknown) => ReactNode }) {
  const [eu, setEu] = useState<Eu | null>(null)
  const [falha, setFalha] = useState<unknown>(null)
  const [perdida, setPerdida] = useState(false)

  useEffect(() => {
    quandoSessaoExpirar(() => setPerdida(true))
    buscarEu().then(setEu).catch((e) => {
      // primeiro acesso sem sessão: vai direto para o login, que volta para esta mesma tela
      if (e instanceof ErroApi && e.status === 401) navegador.ir(urlLogin())
      else setFalha(e)
    })
  }, [])

  if (perdida) return <>{expirada}</>
  if (falha) return <>{erro(falha)}</>
  if (!eu) return <div className="carregando-app" role="status" aria-live="polite">Carregando…</div>
  return <Ctx.Provider value={{ eu, tem: (...p) => temPapel(eu.papeis, ...p) }}>{children}</Ctx.Provider>
}

/** Para testes de componentes. */
export function SessaoFixa({ eu, children }: { eu: Eu; children: ReactNode }) {
  return <Ctx.Provider value={{ eu, tem: (...p) => temPapel(eu.papeis, ...p) }}>{children}</Ctx.Provider>
}

import { createContext, useContext, useEffect, useState, type ReactNode } from 'react'

export interface Migalha { rotulo: string; rota?: string }
interface Ctx { trilha: Migalha[]; definir: (t: Migalha[]) => void }
const C = createContext<Ctx>({ trilha: [], definir: () => {} })

export function ProvedorPagina({ children }: { children: ReactNode }) {
  const [trilha, definir] = useState<Migalha[]>([])
  return <C.Provider value={{ trilha, definir }}>{children}</C.Provider>
}
export const useTrilha = () => useContext(C).trilha

/** Título da aba e trilha de navegação (breadcrumb) da tela. */
export function usePagina(titulo: string, trilha: Migalha[] = []) {
  const { definir } = useContext(C)
  const chave = JSON.stringify(trilha)
  useEffect(() => {
    document.title = `${titulo} · kc-auditor`
    definir(trilha)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [titulo, chave])
}

/** Cabeçalho da tela: o h1 recebe o foco ao trocar de tela (anunciado pelo leitor de tela). */
export function Titulo({ children, extra }: { children: ReactNode; extra?: ReactNode }) {
  return (
    <div className="titulo-tela">
      <h1 tabIndex={-1} id="titulo-tela">{children}</h1>
      {extra && <div className="titulo-extra">{extra}</div>}
    </div>
  )
}

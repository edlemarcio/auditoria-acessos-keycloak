import { useCallback, useEffect, useRef, useState } from 'react'

/** Carrega dados com estado de carregando/erro e cancelamento ao trocar de tela. */
export function useCarregar<T>(f: (sinal: AbortSignal) => Promise<T>, deps: unknown[]) {
  const [estado, setEstado] = useState<{ dados?: T; erro?: unknown; carregando: boolean }>({ carregando: true })
  const [n, setN] = useState(0)
  const fRef = useRef(f)
  fRef.current = f
  useEffect(() => {
    const c = new AbortController()
    setEstado((e) => ({ dados: e.dados, carregando: true }))
    fRef.current(c.signal)
      .then((dados) => { if (!c.signal.aborted) setEstado({ dados, carregando: false }) })
      .catch((erro) => { if (!c.signal.aborted) setEstado({ erro, carregando: false }) })
    return () => c.abort()
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [...deps, n])
  const recarregar = useCallback(() => setN((x) => x + 1), [])
  return { ...estado, recarregar }
}

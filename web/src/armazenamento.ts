/**
 * Único ponto que usa o armazenamento do navegador. Guarda só preferências e marcadores sem dado pessoal:
 * o tema e, durante o step-up, o nome da ação a retomar (nunca o que foi digitado, nunca CPF/título).
 */
const TEMA = 'kc-auditor:tema'
const RETOMAR = 'kc-auditor:retomar'

function seguro<T>(f: () => T, padrao: T): T { try { return f() } catch { return padrao } }

export type Tema = 'claro' | 'escuro'
export const lerTema = (): Tema | null => seguro(() => localStorage.getItem(TEMA) as Tema | null, null)
export const gravarTema = (t: Tema) => seguro(() => localStorage.setItem(TEMA, t), undefined)

export function guardarRetomada(tela: string, acao?: string) {
  if (!acao) return
  seguro(() => sessionStorage.setItem(RETOMAR, JSON.stringify({ tela: tela.split('?')[0], acao, em: Date.now() })), undefined)
}

/** Devolve a ação pendente desta tela (se recente e aceita por quem pergunta) e a apaga. */
export function tomarRetomada(tela: string, aceitar: (acao: string) => boolean = () => true): string | null {
  return seguro(() => {
    const s = sessionStorage
    const v = s.getItem(RETOMAR)
    if (!v) return null
    const r = JSON.parse(v) as { tela: string; acao: string; em: number }
    if (r.tela !== tela.split('?')[0] || !aceitar(r.acao)) return null
    s.removeItem(RETOMAR)
    return Date.now() - r.em < 10 * 60_000 ? r.acao : null
  }, null)
}

/** Preferências da tabela de eventos (W3): colunas visíveis e densidade. Sem dado pessoal. */
const COLUNAS = 'kc-auditor:eventos-colunas'
export interface PrefEventos { colunas: string[]; compacta: boolean }
export const lerPrefEventos = (): PrefEventos | null =>
  seguro(() => { const v = localStorage.getItem(COLUNAS); return v ? JSON.parse(v) as PrefEventos : null }, null)
export const gravarPrefEventos = (p: PrefEventos) => seguro(() => localStorage.setItem(COLUNAS, JSON.stringify(p)), undefined)

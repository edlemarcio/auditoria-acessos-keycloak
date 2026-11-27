import { gravarTema, lerTema, type Tema } from './armazenamento'

export function temaInicial(): Tema {
  const t = lerTema()
  if (t) return t
  return typeof matchMedia === 'function' && matchMedia('(prefers-color-scheme: dark)').matches ? 'escuro' : 'claro'
}
export function aplicarTema(t: Tema) {
  document.documentElement.dataset.theme = t
  document.documentElement.style.colorScheme = t === 'escuro' ? 'dark' : 'light'
}
export function trocarTema(t: Tema) { aplicarTema(t); gravarTema(t) }

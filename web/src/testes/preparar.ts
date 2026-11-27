import '@testing-library/jest-dom/vitest'
import { cleanup } from '@testing-library/react'
import { setupServer } from 'msw/node'
import { afterAll, afterEach, beforeAll } from 'vitest'
import { handlers, reiniciar } from '../dubles/handlers'

// jsdom não tem <dialog>.showModal
if (!HTMLDialogElement.prototype.showModal) {
  HTMLDialogElement.prototype.showModal = function () { this.open = true }
  HTMLDialogElement.prototype.close = function () { this.open = false }
}

const lerTexto = (b: Blob) => new Promise<string>((ok, falha) => {
  const r = new FileReader()
  r.onload = () => ok(String(r.result))
  r.onerror = falha
  r.readAsText(b)
})

// fetch do Node: FormData do jsdom não serve; monta o multipart como o navegador faria
function embrulhar(fetchOriginal: typeof fetch): typeof fetch {
  return async (entrada: RequestInfo | URL, init?: RequestInit) => {
  const url = typeof entrada === 'string' && entrada.startsWith('/') ? new URL(entrada, location.origin).toString() : entrada
  const h = new Headers(init?.headers)
  if (document.cookie) h.set('Cookie', document.cookie)
  let body = init?.body
  if (body instanceof FormData) {   // FormData do jsdom: o fetch do Node não entende; monta o multipart à mão
    const limite = '----kcauditor' + Math.random().toString(16).slice(2)
    let txt = ''
    for (const [k, v] of body.entries()) {
      txt += `--${limite}\r\nContent-Disposition: form-data; name="${k}"`
      txt += typeof v === 'string' ? `\r\n\r\n${v}\r\n` : `; filename="${v.name}"\r\nContent-Type: ${v.type}\r\n\r\n${await lerTexto(v)}\r\n`
    }
    body = `${txt}--${limite}--\r\n`
    h.set('Content-Type', `multipart/form-data; boundary=${limite}`)
  }
  return fetchOriginal(url, { ...init, headers: h, body })
  }
}

export const servidor = setupServer(...handlers)
beforeAll(() => {
  servidor.listen({ onUnhandledRequest: 'error' })
  globalThis.fetch = embrulhar(globalThis.fetch)   // por cima do interceptador do MSW
})
afterEach(() => {
  cleanup()
  servidor.resetHandlers()
  reiniciar()
  document.cookie.split(';').forEach((c) => { document.cookie = `${c.split('=')[0].trim()}=; expires=Thu, 01 Jan 1970 00:00:00 GMT; path=/` })
  localStorage.clear()
  sessionStorage.clear()
})
afterAll(() => servidor.close())

export function sessaoDuble(perfil = 'solicitante', stepUp = false) {
  document.cookie = 'dubles_sessao=1; path=/'
  document.cookie = `dubles_perfil=${perfil}; path=/`
  if (stepUp) document.cookie = `dubles_step_up=${Date.now()}; path=/`
}

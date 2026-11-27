import { readdirSync, readFileSync, statSync } from 'node:fs'
import { join } from 'node:path'

function arquivos(d: string): string[] {
  return readdirSync(d).flatMap((n) => {
    const p = join(d, n)
    return statSync(p).isDirectory() ? arquivos(p) : /\.(ts|tsx)$/.test(n) && !/\.test\./.test(n) ? [p] : []
  })
}

describe('armazenamento do navegador', () => {
  it('só src/armazenamento.ts usa localStorage/sessionStorage (nada de dado pessoal persistido)', () => {
    const raiz = join(__dirname, '..')
    const usam = arquivos(raiz).filter((f) => !f.includes('/testes/') && /\b(localStorage|sessionStorage|indexedDB)\b/.test(readFileSync(f, 'utf8')))
    expect(usam.map((f) => f.slice(raiz.length + 1))).toEqual(['armazenamento.ts'])
  })
  it('não há script ou estilo inline no index.html (CSP default-src self)', () => {
    const html = readFileSync(join(__dirname, '../../index.html'), 'utf8')
    expect(html).not.toMatch(/<script(?![^>]*\bsrc=)[^>]*>/)
    expect(html).not.toMatch(/<style|style=/)
  })
})

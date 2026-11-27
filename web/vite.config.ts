/// <reference types="vitest/config" />
import { defineConfig, type Plugin } from 'vite'
import react from '@vitejs/plugin-react'

/**
 * Desenvolvimento:
 *  - `npm run dev` → proxy de /api e /auth para a API (AUDITOR_API, padrão http://localhost:8100);
 *  - `npm run dev:dubles` → dublês do contrato (MSW) e um /auth/entrar de mentira que só volta para a tela.
 * O build de produção não leva dublês nem o service worker do MSW (publicDir só existe no `vite dev`).
 */
const DUBLES = process.env.VITE_DUBLES === '1'
const API = process.env.AUDITOR_API ?? 'http://localhost:8100'

function loginDeMentira(): Plugin {
  return {
    name: 'kc-auditor-login-dubles',
    configureServer(server) {
      server.middlewares.use('/auth/entrar', (req, res) => {
        const u = new URL(req.url ?? '/', 'http://x')
        let volta = u.searchParams.get('volta') ?? '/'
        if (!volta.startsWith('/') || volta.startsWith('//')) volta = '/'
        const cookies = ['dubles_sessao=1; Path=/; SameSite=Strict']
        if (u.searchParams.get('step_up') === '1') cookies.push(`dubles_step_up=${Date.now()}; Path=/; SameSite=Strict`)
        res.statusCode = 302
        res.setHeader('Set-Cookie', cookies)
        res.setHeader('Location', volta)
        res.end()
      })
    },
  }
}

export default defineConfig(({ command }) => ({
  plugins: [react(), ...(DUBLES && command === 'serve' ? [loginDeMentira()] : [])],
  publicDir: command === 'serve' ? 'dev-public' : false,
  build: { outDir: 'dist', assetsDir: 'assets', sourcemap: false, assetsInlineLimit: 0 },
  server: {
    port: 5173,
    strictPort: true,
    proxy: DUBLES ? undefined : {
      '/api': { target: API, changeOrigin: false },
      '/auth': { target: API, changeOrigin: false },
    },
  },
  // `npm run preview` serve o build com a mesma CSP da API (contrato §14): nada inline, nada de CDN
  preview: { port: 4173, strictPort: true, headers: { 'Content-Security-Policy': "default-src 'self'; frame-ancestors 'none'; object-src 'none'" } },
  test: {
    environment: 'jsdom',
    globals: true,
    setupFiles: ['src/testes/preparar.ts'],
    include: ['src/**/*.test.{ts,tsx}'],
    css: false,
    testTimeout: 20_000,
  },
}))

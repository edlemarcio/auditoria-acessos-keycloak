import { defineConfig, devices } from '@playwright/test'

/** Confere o build de produção (`npm run build`) servido com a CSP da API: sem violação de CSP, fontes e ícones locais. */
export default defineConfig({
  testDir: 'e2e',
  testMatch: ['build.spec.ts'],
  reporter: [['list']],
  use: { baseURL: 'http://localhost:4173' },
  projects: [{ name: 'build', use: { ...devices['Desktop Chrome'] } }],
  webServer: { command: 'npx vite preview', url: 'http://localhost:4173', reuseExistingServer: false, timeout: 60_000 },
})

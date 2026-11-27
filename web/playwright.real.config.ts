import { defineConfig, devices } from '@playwright/test'

/**
 * Ponta a ponta real: `vite dev` em :5173 com proxy de /api e /auth para a API do W1 em :8100 (subida à parte, ver
 * web/README.md), login de verdade no realm `auditor` do Keycloak :8090 com senha e OTP.
 */
export default defineConfig({
  testDir: 'e2e',
  testMatch: ['real.spec.ts'],
  workers: 1,
  retries: 0,
  timeout: 120_000,
  reporter: [['list']],
  use: { baseURL: 'http://localhost:5173', locale: 'pt-BR', timezoneId: 'America/Bahia', trace: 'retain-on-failure' },
  projects: [{ name: 'real', use: { ...devices['Desktop Chrome'] } }],
  webServer: {
    command: 'npx vite --port 5173 --strictPort',
    env: { VITE_DUBLES: '0', AUDITOR_API: 'http://localhost:8100' },
    url: 'http://localhost:5173',
    reuseExistingServer: false,
    timeout: 60_000,
  },
})

import { defineConfig, devices } from '@playwright/test'

/**
 * Aceite do W2 (PROPOSTA_WEB §11): o ciclo inteiro de uma investigação de 180 dias só pela web, contra a API
 * integrada servindo web/dist em :8000 (subida à parte, com worker), login real no Keycloak :8090 com senha e OTP.
 */
export default defineConfig({
  testDir: 'e2e',
  testMatch: ['aceite_w2.spec.ts', 'aceite_w3.spec.ts'],
  workers: 1,
  retries: 0,
  timeout: 900_000,
  reporter: [['list']],
  use: { baseURL: 'http://localhost:8000', locale: 'pt-BR', timezoneId: 'America/Bahia', trace: 'retain-on-failure' },
  projects: [{ name: 'aceite', use: { ...devices['Desktop Chrome'] } }],
})

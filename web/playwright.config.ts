import { defineConfig, devices } from '@playwright/test'

/** Testes de tela contra o `vite dev` com os dublês do contrato (VITE_DUBLES=1). */
export default defineConfig({
  testDir: 'e2e',
  testIgnore: ['real.spec.ts', 'build.spec.ts'],
  fullyParallel: true,
  workers: 4,
  retries: 0,
  reporter: [['list'], ['html', { open: 'never', outputFolder: 'playwright-report' }]],
  use: { baseURL: 'http://localhost:5173', locale: 'pt-BR', timezoneId: 'America/Bahia', trace: 'retain-on-failure' },
  projects: [{ name: 'chromium', use: { ...devices['Desktop Chrome'], viewport: { width: 1366, height: 900 } } }],
  webServer: {
    command: 'npx vite --port 5173 --strictPort',
    env: { VITE_DUBLES: '1' },
    url: 'http://localhost:5173',
    reuseExistingServer: true,
    timeout: 60_000,
  },
})

import { setupWorker } from 'msw/browser'
import { handlers } from './handlers'

export async function iniciarDubles() {
  await setupWorker(...handlers).start({ onUnhandledRequest: 'bypass', quiet: true, serviceWorker: { url: '/mockServiceWorker.js' } })
}

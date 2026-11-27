import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import '@fontsource/raleway/400.css'
import '@fontsource/raleway/600.css'
import '@fontsource/raleway/700.css'
import '@fortawesome/fontawesome-free/css/all.min.css'
import '@fortawesome/fontawesome-free/css/v5-font-face.min.css'
import '@govbr-ds/core/dist/core.min.css'
import './estilos/app.css'
import { aplicarTema, temaInicial } from './tema'
import { App } from './App'

aplicarTema(temaInicial())

async function iniciar() {
  // Dublês só no `vite dev` com VITE_DUBLES=1: no build de produção este ramo some (import.meta.env.DEV é false).
  if (import.meta.env.DEV && import.meta.env.VITE_DUBLES === '1') {
    const { iniciarDubles } = await import('./dubles/navegador')
    await iniciarDubles()
  }
  createRoot(document.getElementById('raiz')!).render(<StrictMode><App /></StrictMode>)
}
void iniciar()

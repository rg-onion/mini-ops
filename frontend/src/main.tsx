import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import './index.css'
import './i18n'
import App from './App.tsx'

const PRELOAD_RELOAD_STATE_KEY = 'miniOpsPreloadReloadAt'
const PRELOAD_RELOAD_COOLDOWN_MS = 30_000

window.addEventListener('vite:preloadError', event => {
  const currentState = window.history.state
  const historyState = typeof currentState === 'object' && currentState !== null
    ? currentState as Record<string, unknown>
    : {}
  const previousReloadAt = historyState[PRELOAD_RELOAD_STATE_KEY]
  const now = Date.now()

  if (typeof previousReloadAt === 'number' && now - previousReloadAt < PRELOAD_RELOAD_COOLDOWN_MS) {
    return
  }

  try {
    window.history.replaceState({ ...historyState, [PRELOAD_RELOAD_STATE_KEY]: now }, '')
  } catch {
    return
  }

  event.preventDefault()
  window.location.reload()
})

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <App />
  </StrictMode>,
)

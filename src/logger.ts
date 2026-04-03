/**
 * Attestto Debug Logger
 *
 * Silent by default. Enable with:
 *   Attestto.debug = true
 *
 * Or from the console:
 *   window.Attestto.debug = true
 *
 * Logs are prefixed with [attestto] and color-coded by level.
 */

export type LogLevel = 'info' | 'warn' | 'error' | 'event'

const COLORS: Record<LogLevel, string> = {
  info: '#594FD3',
  warn: '#fbbf24',
  error: '#ef4444',
  event: '#4ade80',
}

function isEnabled(): boolean {
  if (typeof window === 'undefined') return false
  const g = window as unknown as { Attestto?: { debug?: boolean } }
  return g.Attestto?.debug === true
}

function emit(level: LogLevel, scope: string, msg: string, data?: unknown) {
  if (!isEnabled()) return
  const color = COLORS[level]
  const prefix = `%c[attestto:${scope}]%c`
  const args: unknown[] = [prefix, `color: ${color}; font-weight: bold`, 'color: inherit', msg]
  if (data !== undefined) args.push(data)
  if (level === 'error') {
    console.error(...args)
  } else if (level === 'warn') {
    console.warn(...args)
  } else {
    console.log(...args)
  }
}

function createScopedLogger(scope: string) {
  return {
    info: (msg: string, data?: unknown) => emit('info', scope, msg, data),
    warn: (msg: string, data?: unknown) => emit('warn', scope, msg, data),
    error: (msg: string, data?: unknown) => emit('error', scope, msg, data),
    event: (msg: string, data?: unknown) => emit('event', scope, msg, data),
  }
}

/** Pre-scoped loggers for each module */
export const logger = {
  sign: createScopedLogger('sign'),
  verify: createScopedLogger('verify'),
  plugin: createScopedLogger('plugin'),
  wallet: createScopedLogger('wallet'),
}

/** Initialize global Attestto namespace with debug toggle */
export function initGlobal() {
  if (typeof window === 'undefined') return
  const g = window as unknown as { Attestto?: Record<string, unknown> }
  if (!g.Attestto) g.Attestto = {}
  if (g.Attestto.debug !== undefined) return

  const STORAGE_KEY = 'attestto:debug'
  let debugEnabled = false

  // Restore from localStorage
  try {
    debugEnabled = localStorage.getItem(STORAGE_KEY) === '1'
  } catch {
    // localStorage unavailable (incognito, iframe sandbox)
  }

  Object.defineProperty(g.Attestto, 'debug', {
    get: () => debugEnabled,
    set: (v: boolean) => {
      debugEnabled = v
      try {
        if (v) localStorage.setItem(STORAGE_KEY, '1')
        else localStorage.removeItem(STORAGE_KEY)
      } catch {
        // ignore
      }
      if (v) printWelcome()
      else printDisabled()
    },
    configurable: true,
    enumerable: true,
  })

  // On load: show welcome if persisted ON, otherwise show hint
  if (debugEnabled) printWelcome()
  else printHint()
}

function printHint() {
  console.log(
    '%c@attestto/verify %c· Enable debug logging: %cAttesstto.debug = true',
    'color: #594FD3; font-weight: bold;',
    'color: #64748b;',
    'color: #e2e8f0; font-family: monospace;',
  )
}

function printDisabled() {
  console.log(
    '%c@attestto/verify %c· Debug logging disabled. Re-enable: %cAttesstto.debug = true',
    'color: #594FD3; font-weight: bold;',
    'color: #64748b;',
    'color: #e2e8f0; font-family: monospace;',
  )
}

function printWelcome() {
  console.log(
    '%cAttesstto Debug Mode',
    'color: #594FD3; font-size: 14px; font-weight: bold; font-family: system-ui, sans-serif;',
  )
  console.log(
    '%cLogs active for all components. Disable: %cAttesstto.debug = false',
    'color: #94a3b8; font-family: system-ui, sans-serif;',
    'color: #e2e8f0; font-family: monospace;',
  )
  console.log(
    '%cDocs %chttps://verify.attestto.com/docs\n%cGitHub %chttps://github.com/attestto/verify\n%cSupport %chttps://attestto.com/support',
    'color: #64748b;',
    'color: #594FD3;',
    'color: #64748b;',
    'color: #594FD3;',
    'color: #64748b;',
    'color: #594FD3;',
  )
  console.log(
    '%cLevels: info · warn · error · event\nScopes: sign · verify · plugin · wallet',
    'color: #64748b; font-family: system-ui, sans-serif;',
  )
}

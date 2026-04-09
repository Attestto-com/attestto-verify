/**
 * /c/ — Attestto Ark Extension Bridge page.
 *
 * Two-mode handshake page that talks to the Attestto ID extension via the
 * `@attestto/id-wallet-adapter` discovery protocol and the extension's
 * postMessage API. NEVER sends anything to the server.
 *
 *   1. LOGIN MODE — always available. User clicks "Login con Attestto",
 *      page generates a random nonce, posts ATTESTTO_AUTH_REQUEST, the
 *      extension prompts the holder for consent, returns a DID-signed
 *      proof of possession.
 *
 *   2. CREDENTIAL LOAD MODE — only when `location.hash` carries a
 *      `#vc=…&preview=…` fragment (typically the desktop's
 *      "Verificar en navegador" deep-link). Page renders a sanitized
 *      teaser from `preview` (type / issuer / level / issuedAt — never
 *      PII), and on user click posts ATTESTTO_CREDENTIAL_PUSH with the
 *      full VC. Fragment never reaches the server because the browser
 *      does not transmit URL fragments.
 *
 * Wire protocol references:
 *   - Discovery: `@attestto/id-wallet-adapter` `discoverWallets()`
 *   - Auth:      window.postMessage `ATTESTTO_AUTH_REQUEST` →
 *                `ATTESTTO_AUTH_RESPONSE`
 *   - Cred push: window.postMessage `ATTESTTO_CREDENTIAL_PUSH` →
 *                `ATTESTTO_CREDENTIAL_PUSH_RESPONSE`
 *
 * The auth and push protocols are not yet exposed via the adapter package.
 * Promote them to `@attestto/id-wallet-adapter` v0.5 (tracked separately)
 * once the wire shapes stabilize.
 */

import { discoverWallets, type WalletAnnouncement } from '@attestto/id-wallet-adapter'

// ── DOM helpers ────────────────────────────────────────────────

const $ = <T extends HTMLElement = HTMLElement>(id: string): T => {
  const el = document.getElementById(id)
  if (!el) throw new Error(`Missing element #${id}`)
  return el as T
}

function setStatus(state: 'idle' | 'ok' | 'warn' | 'err', text: string): void {
  const el = $('wallet-status')
  el.classList.remove('ok', 'warn', 'err')
  if (state !== 'idle') el.classList.add(state)
  $('wallet-status-text').textContent = text
}

let toastTimer: number | null = null
function toast(message: string, kind: 'ok' | 'err' | 'info' = 'info'): void {
  const el = $('toast')
  el.textContent = message
  el.classList.remove('ok', 'err')
  if (kind !== 'info') el.classList.add(kind)
  el.classList.add('show')
  if (toastTimer !== null) window.clearTimeout(toastTimer)
  toastTimer = window.setTimeout(() => el.classList.remove('show'), 2500)
}

// ── Fragment parsing (privacy-critical: # never reaches server) ─

interface CredentialPreview {
  type: string
  issuer: string
  level: string
  issuedAt?: string
  icon?: string
}

interface ParsedFragment {
  vc: string | null
  preview: CredentialPreview | null
}

function parseFragment(): ParsedFragment {
  const hash = window.location.hash.replace(/^#/, '')
  if (!hash) return { vc: null, preview: null }

  const params = new URLSearchParams(hash)
  const vc = params.get('vc')
  const previewRaw = params.get('preview')

  let preview: CredentialPreview | null = null
  if (previewRaw) {
    try {
      const json = atob(previewRaw.replace(/-/g, '+').replace(/_/g, '/'))
      preview = JSON.parse(json) as CredentialPreview
    } catch (err) {
      console.warn('[c-page] Failed to decode preview fragment', err)
    }
  }

  return { vc, preview }
}

// ── Credential teaser render ───────────────────────────────────

function renderCredentialCard(preview: CredentialPreview): void {
  $('credential-card').classList.remove('hidden')

  // Type label — never render PII fields. The desktop is responsible
  // for putting only safe fields into `preview`.
  $('cred-type').textContent = preview.type || 'Credencial Verificable'
  $('cred-level').textContent = preview.level || '—'
  $('cred-issuer').textContent = preview.issuer || 'Emisor desconocido'

  if (preview.issuedAt) {
    const d = new Date(preview.issuedAt)
    if (!isNaN(d.valueOf())) {
      $('cred-issued').textContent = `Emitida ${d.toLocaleDateString('es', {
        day: 'numeric',
        month: 'long',
        year: 'numeric',
      })}`
    } else {
      $('cred-issued').textContent = preview.issuedAt
    }
  }

  if (preview.icon) {
    $('cred-icon').textContent = preview.icon
  }

  // Update page header to be load-mode-specific
  $('page-title').textContent = 'Recibir credencial'
  $('page-lead').textContent =
    'Alguien te compartió una credencial verificable. Cárgala en tu extensión Attestto para conservarla bajo tu control.'
}

// ── Extension handshake — credential push ──────────────────────

function pushCredentialToExtension(
  vc: string,
  preview: CredentialPreview | null,
): Promise<{ ok: boolean; error?: string }> {
  return new Promise((resolve) => {
    const requestId = `c-push-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`

    const onMessage = (event: MessageEvent) => {
      if (event.source !== window) return
      const data = event.data
      if (!data || data.type !== 'ATTESTTO_CREDENTIAL_PUSH_RESPONSE') return
      if (data.requestId !== requestId) return
      window.removeEventListener('message', onMessage)
      resolve({ ok: !!data.success, error: data.error })
    }

    window.addEventListener('message', onMessage)

    window.postMessage(
      {
        type: 'ATTESTTO_CREDENTIAL_PUSH',
        requestId,
        credential: {
          format: 'attestto-id',
          raw: vc,
          issuer: preview?.issuer ?? 'Attestto Platform',
          claims: {
            type: preview?.type,
            level: preview?.level,
            issuedAt: preview?.issuedAt,
          },
        },
      },
      window.location.origin,
    )

    // Safety timeout — if extension never replies the user must not be
    // stuck on a spinner. Fail gracefully.
    setTimeout(() => {
      window.removeEventListener('message', onMessage)
      resolve({ ok: false, error: 'Timeout — la extensión no respondió.' })
    }, 60_000)
  })
}

// ── Extension handshake — DID auth (login) ─────────────────────

interface AuthResult {
  ok: boolean
  did?: string
  signature?: string
  error?: string
}

function requestLogin(): Promise<AuthResult> {
  return new Promise((resolve) => {
    const requestId = `c-auth-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`
    const nonce = crypto.randomUUID()
    const timestamp = new Date().toISOString()

    const onMessage = (event: MessageEvent) => {
      if (event.source !== window) return
      const data = event.data
      if (!data || data.type !== 'ATTESTTO_AUTH_RESPONSE') return
      if (data.requestId !== requestId) return
      window.removeEventListener('message', onMessage)
      if (data.error) {
        resolve({ ok: false, error: data.error })
        return
      }
      resolve({
        ok: true,
        did: data.did,
        signature: data.signature,
      })
    }

    window.addEventListener('message', onMessage)

    window.postMessage(
      {
        type: 'ATTESTTO_AUTH_REQUEST',
        requestId,
        nonce,
        timestamp,
      },
      window.location.origin,
    )

    setTimeout(() => {
      window.removeEventListener('message', onMessage)
      resolve({ ok: false, error: 'Timeout — la extensión no respondió.' })
    }, 60_000)
  })
}

// ── Bootstrap ──────────────────────────────────────────────────

async function bootstrap(): Promise<void> {
  const { vc, preview } = parseFragment()

  // Render credential card if a fragment was passed in.
  if (preview) {
    renderCredentialCard(preview)
  }

  // Discover wallets via the canonical adapter protocol.
  const wallets: WalletAnnouncement[] = await discoverWallets(800)
  const hasWallet = wallets.length > 0

  if (hasWallet) {
    const names = wallets.map((w) => w.name).join(' · ')
    setStatus('ok', `Extensión detectada: ${names}`)
    enableActions(vc, preview)
  } else {
    setStatus('warn', 'No se detectó ninguna extensión Attestto en este navegador.')
    // Buttons stay disabled. Install hint is already in the markup.
  }
}

function enableActions(vc: string | null, preview: CredentialPreview | null): void {
  // Login button — always available when extension is present
  const loginBtn = $('btn-login') as HTMLButtonElement
  loginBtn.disabled = false
  loginBtn.addEventListener('click', async () => {
    loginBtn.disabled = true
    loginBtn.textContent = 'Esperando consentimiento…'
    const result = await requestLogin()
    loginBtn.disabled = false
    loginBtn.textContent = 'Iniciar sesión con Attestto'

    if (!result.ok) {
      toast(result.error ?? 'Login cancelado', 'err')
      return
    }

    $('login-result').classList.remove('hidden')
    $('login-did').textContent = result.did ?? '—'
    $('login-sig').textContent = result.signature
      ? `${result.signature.slice(0, 32)}…${result.signature.slice(-8)}`
      : '—'
    toast('Sesión verificada', 'ok')
  })

  // Credential push button — only meaningful if a VC was provided
  if (vc) {
    const pushBtn = $('btn-load-cred') as HTMLButtonElement
    pushBtn.disabled = false
    pushBtn.addEventListener('click', async () => {
      pushBtn.disabled = true
      pushBtn.textContent = 'Cargando en la extensión…'
      const result = await pushCredentialToExtension(vc, preview)
      if (result.ok) {
        pushBtn.textContent = '✓ Credencial guardada'
        toast('Credencial guardada en tu extensión', 'ok')
      } else {
        pushBtn.disabled = false
        pushBtn.textContent = 'Cargar en mi extensión'
        toast(result.error ?? 'Error al cargar la credencial', 'err')
      }
    })
  }
}

bootstrap().catch((err) => {
  console.error('[c-page] bootstrap failed', err)
  setStatus('err', 'Error al inicializar la página.')
})

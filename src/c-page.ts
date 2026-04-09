/**
 * /offer/ (alias /c/) — Open Credential Handoff landing page.
 *
 * Reference implementation of the Open Credential Handoff Fragment
 * Protocol v1 (see id-wallet-adapter/docs/credential-handoff-protocol.md).
 *
 * Job: take a #v=1&vc=…&preview=… URL fragment from any issuer and
 * hand the credential to whatever compatible wallet the visitor has.
 *
 *   - Has wallet → render the teaser, push the VC into the wallet on
 *                  user click, done.
 *   - No wallet  → render the teaser anyway, plus an install pitch
 *                  and a link to the adapter spec for site/wallet
 *                  builders. The credential stays in the URL fragment
 *                  for when the user installs and returns.
 *
 * Privacy by construction: the URL fragment never reaches any server
 * (browsers don't transmit anything after `#`). The page is content-
 * blind — it never parses the VC, only the sanitized preview.
 *
 * Issuer-neutral: the page never assumes the issuer is Attestto.
 * Any issuer that produces a v=1 fragment per the spec can land
 * holders here.
 */

import {
  discoverWallets,
  parseCredentialOffer,
  type CredentialOffer,
  type CredentialOfferPreview,
  type WalletAnnouncement,
} from '@attestto/id-wallet-adapter'

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

/**
 * Render the discovered wallet(s) inside the status pill, including the
 * wallet-provided icon. Each wallet announces itself via
 * registerWallet() in @attestto/id-wallet-adapter, including an icon URL
 * (typically a chrome-extension://… URL set via chrome.runtime.getURL).
 */
function renderWalletStatus(wallets: WalletAnnouncement[]): void {
  const el = $('wallet-status')
  el.classList.remove('warn', 'err')
  el.classList.add('ok')
  el.innerHTML = ''

  for (const w of wallets) {
    const icon = document.createElement('img')
    icon.src = w.icon
    icon.alt = w.name
    icon.width = 18
    icon.height = 18
    icon.style.borderRadius = '4px'
    icon.style.display = 'block'
    icon.onerror = () => {
      icon.remove()
      const dot = document.createElement('span')
      dot.className = 'status-dot'
      el.insertBefore(dot, el.firstChild)
    }
    el.appendChild(icon)
  }

  const label = document.createElement('span')
  label.id = 'wallet-status-text'
  label.textContent =
    wallets.length === 1
      ? `Wallet detectada: ${wallets[0].name}`
      : `${wallets.length} wallets detectadas: ${wallets.map((w) => w.name).join(' · ')}`
  el.appendChild(label)
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

// ── Credential teaser render ───────────────────────────────────

function renderCredentialCard(preview: CredentialOfferPreview): void {
  $('credential-card').classList.remove('hidden')

  // Type label — never render PII fields. The issuer is responsible
  // for putting only safe fields into preview. The page is content-blind
  // and renders whatever it gets.
  $('cred-type').textContent = preview.type
  $('cred-issuer').textContent = preview.issuer

  if (preview.level) {
    $('cred-level').textContent = preview.level
    $('cred-level').classList.remove('hidden')
  } else {
    $('cred-level').classList.add('hidden')
  }

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
  } else {
    $('cred-issued').textContent = ''
  }

  $('cred-icon').textContent = preview.icon || '★'

  // Update the page header to make the holder's mental state explicit:
  // they arrived here because an issuer just minted them a credential.
  $('page-title').textContent = 'Recibir credencial'
  $('page-lead').innerHTML =
    'Un emisor te compartió una credencial verificable. Cárgala en tu wallet — cualquier extensión compatible con <a href="https://github.com/Attestto-com/id-wallet-adapter" target="_blank" rel="noopener" style="color: var(--color-accent); font-weight: 600;">@attestto/id-wallet-adapter</a> — para conservarla bajo tu control.'
}

function renderOfferError(code: string, message: string): void {
  // The fragment was present but malformed. Show a friendly error in
  // place of the credential card so the holder isn't left wondering
  // what happened.
  $('credential-card').classList.remove('hidden')
  $('cred-type').textContent = 'Oferta de credencial inválida'
  $('cred-issuer').textContent = `Código: ${code}`
  $('cred-level').classList.add('hidden')
  $('cred-issued').textContent = message
  ;($('btn-load-cred') as HTMLButtonElement).disabled = true
}

// ── Extension handshake — credential push ──────────────────────
// NOTE: this raw postMessage protocol is implemented today by the
// reference Attestto ID extension (CORTEX/extension/src/entrypoints/
// credential-api.content.ts). It will be promoted to a canonical helper
// in @attestto/id-wallet-adapter v0.5 once the wire shape stabilizes.

function pushCredentialToWallet(
  vc: string,
  preview: CredentialOfferPreview,
): Promise<{ ok: boolean; error?: string }> {
  return new Promise((resolve) => {
    const requestId = `offer-push-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`

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
          // Wire format pass-through: page does not parse the VC.
          format: 'jwt-vc',
          raw: vc,
          issuerName: preview.issuer,
          claims: {
            type: preview.type,
            level: preview.level,
            issuedAt: preview.issuedAt,
          },
        },
      },
      window.location.origin,
    )

    // Safety timeout — if the wallet never replies the user must not
    // be stuck on a spinner.
    setTimeout(() => {
      window.removeEventListener('message', onMessage)
      resolve({ ok: false, error: 'Tiempo agotado — la wallet no respondió.' })
    }, 60_000)
  })
}

// ── Bootstrap ──────────────────────────────────────────────────

async function bootstrap(): Promise<void> {
  // Parse the URL fragment via the canonical adapter helper. The page
  // never invents its own format — it consumes the spec.
  const result = parseCredentialOffer(window.location.hash)

  let offer: CredentialOffer | null = null
  if (result.ok) {
    offer = result.offer
    renderCredentialCard(offer.preview)
    renderProvenance()
  } else if (result.error.code !== 'NO_FRAGMENT') {
    // Fragment was present but malformed. Tell the user.
    renderOfferError(result.error.code, result.error.message)
  }
  // If NO_FRAGMENT we leave the credential card hidden and only show
  // the discovery state — visitors who land on /offer/ without an
  // offer URL still get something useful.

  // Discover wallets via the canonical adapter protocol.
  const wallets: WalletAnnouncement[] = await discoverWallets(800)
  const hasWallet = wallets.length > 0

  if (hasWallet) {
    renderWalletStatus(wallets)
    if (offer) enableLoadButton(offer)
  } else {
    setStatus(
      'warn',
      'No se detectó ninguna wallet de credenciales compatible. Instala una extensión que implemente @attestto/id-wallet-adapter.',
    )
    document.getElementById('dev-hint')?.classList.remove('hidden')
  }

  // If we landed without an offer fragment AND without a wallet, the
  // page is being used as a "what is this?" landing — the dev hint
  // already explains the protocol. Nothing more to do.
}

function enableLoadButton(offer: CredentialOffer): void {
  // Two-step confirm flow (ATT-359 security hardening):
  //
  //   click 1 → reveal the "what is going to happen" panel + confirm button
  //   click 2 → actually post the credential to the wallet
  //
  // Reasoning: every credential push goes through an attacker-controllable
  // landing page. A single-click flow trains users to trust unverified
  // teasers. The two-step pattern gives the user a chance to read the
  // trust-ladder explanation BEFORE committing the action, and forces
  // an explicit "I understand my wallet is the verifier" confirmation.
  const reviewBtn = $('btn-load-cred') as HTMLButtonElement
  const confirmPanel = $('confirm-panel')
  const confirmBtn = $('btn-confirm-load') as HTMLButtonElement

  reviewBtn.disabled = false
  reviewBtn.addEventListener('click', () => {
    confirmPanel.classList.remove('hidden')
    reviewBtn.disabled = true
    reviewBtn.textContent = '👇 Lee abajo y confirma'
    confirmBtn.focus()
  })

  confirmBtn.addEventListener('click', async () => {
    confirmBtn.disabled = true
    confirmBtn.textContent = 'Enviando a la wallet…'
    const result = await pushCredentialToWallet(offer.vc, offer.preview)
    if (result.ok) {
      confirmBtn.textContent = '✓ Enviada — revisa tu wallet'
      toast('Credencial enviada a tu wallet — confirma el consentimiento allí', 'ok')
    } else {
      confirmBtn.disabled = false
      confirmBtn.textContent = 'Confirmar y enviar a la wallet'
      toast(result.error ?? 'Error al enviar la credencial', 'err')
    }
  })
}

/**
 * Show a small provenance hint based on document.referrer so the user
 * can sanity-check whether the URL came from a source they recognize.
 * Empty referrer is common (URL pasted, opened from email client, QR
 * scan, link clicked from another tab) and is treated as "unknown
 * origin" — not as suspicious by itself, just unverifiable.
 */
function renderProvenance(): void {
  const block = document.getElementById('provenance')
  const host = document.getElementById('provenance-host')
  if (!block || !host) return

  let label: string
  try {
    if (document.referrer) {
      const u = new URL(document.referrer)
      // Only show host, not path or query — minimize info exposure.
      label = u.host
    } else {
      label = '(origen desconocido)'
    }
  } catch {
    label = '(origen desconocido)'
  }
  host.textContent = label
  block.classList.remove('hidden')
}

bootstrap().catch((err) => {
  console.error('[offer-page] bootstrap failed', err)
  setStatus('err', 'Error al inicializar la página.')
})

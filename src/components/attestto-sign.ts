import { LitElement, html, css } from 'lit'
import { customElement, state } from 'lit/decorators.js'
import { sharedStyles } from '../styles/shared.js'
import { discoverWallets, pickWallet, type WalletAnnouncement } from '@attestto/id-wallet-adapter'

/**
 * <attestto-sign> — Sign a PDF with any DID wallet
 *
 * Uses @attestto/id-wallet-adapter for universal wallet discovery.
 * Any extension that calls registerWallet() will be detected and shown
 * in the wallet picker.
 *
 * Flow:
 *   1. discoverWallets() finds installed credential wallets
 *   2. User picks a wallet (or auto-selects if only one)
 *   3. User drops a PDF
 *   4. CHAPI VP request → wallet signs with DID
 *   5. User downloads signed receipt
 */
@customElement('attestto-sign')
export class AttesttoSign extends LitElement {
  static override styles = [
    sharedStyles,
    css`
      :host {
        display: block;
        font-family: var(--attestto-font, system-ui, -apple-system, sans-serif);
        color: var(--attestto-text, #1a1a2e);
      }

      .drop-zone {
        border: 2px dashed var(--attestto-border, #cbd5e1);
        border-radius: 12px;
        padding: 3rem 2rem;
        text-align: center;
        cursor: pointer;
        transition: all 0.2s ease;
        background: var(--attestto-bg, #f8fafc);
      }

      .drop-zone:hover,
      .drop-zone.dragging {
        border-color: var(--attestto-primary, #594FD3);
        background: var(--attestto-bg-hover, #eef2ff);
      }

      .drop-zone-icon {
        font-size: 2.5rem;
        margin-bottom: 0.75rem;
      }

      input[type='file'] {
        display: none;
      }

      /* ── Wallet Status ──────────────────────────────────── */
      .wallet-status {
        display: flex;
        align-items: center;
        gap: 0.5rem;
        padding: 0.75rem 1rem;
        border-radius: 8px;
        font-size: 0.85rem;
        margin-bottom: 1rem;
      }

      .wallet-connected {
        background: var(--attestto-success-bg, #dcfce7);
        color: var(--attestto-success, #16a34a);
      }

      .wallet-discovering {
        background: var(--attestto-info-bg, #dbeafe);
        color: var(--attestto-info, #2563eb);
      }

      .wallet-missing {
        background: var(--attestto-warning-bg, #fef3c7);
        color: var(--attestto-warning, #d97706);
      }

      .wallet-missing a {
        color: inherit;
        text-decoration: underline;
      }

      /* ── Wallet Card (connected state) ─────────────────── */
      .wallet-card {
        display: flex;
        align-items: center;
        gap: 0.75rem;
        padding: 0.75rem 1rem;
        border: 1px solid var(--attestto-border, #e2e8f0);
        border-radius: 8px;
        background: var(--attestto-bg-card, #ffffff);
        margin-bottom: 1rem;
      }

      .wallet-card-icon {
        width: 32px;
        height: 32px;
        border-radius: 6px;
        object-fit: contain;
      }

      .wallet-card-info {
        flex: 1;
        min-width: 0;
      }

      .wallet-card-name {
        font-size: 0.85rem;
        font-weight: 600;
      }

      .wallet-card-meta {
        font-size: 0.72rem;
        color: var(--attestto-text-muted, #64748b);
      }

      .wallet-card-disconnect {
        background: none;
        border: none;
        color: var(--attestto-text-muted, #94a3b8);
        cursor: pointer;
        font-size: 0.75rem;
        text-decoration: underline;
      }

      /* ── Sign Card ─────────────────────────────────────── */
      .sign-card {
        border: 1px solid var(--attestto-border, #e2e8f0);
        border-radius: 12px;
        padding: 1.5rem;
        background: var(--attestto-bg-card, #ffffff);
      }

      .file-info {
        display: flex;
        align-items: center;
        gap: 0.75rem;
        margin-bottom: 1.25rem;
        font-weight: 600;
      }

      .sign-btn {
        width: 100%;
        padding: 0.75rem;
        border: none;
        border-radius: 8px;
        font-size: 1rem;
        font-weight: 600;
        cursor: pointer;
        transition: background 0.15s;
        background: var(--attestto-primary, #594FD3);
        color: white;
      }

      .sign-btn:hover {
        background: var(--attestto-primary-hover, #7B72ED);
      }

      .sign-btn:disabled {
        opacity: 0.5;
        cursor: not-allowed;
      }

      .connect-btn {
        width: 100%;
        padding: 0.65rem;
        border: 1px solid var(--attestto-primary, #594FD3);
        border-radius: 8px;
        font-size: 0.9rem;
        font-weight: 600;
        cursor: pointer;
        transition: all 0.15s;
        background: transparent;
        color: var(--attestto-primary, #594FD3);
        margin-bottom: 1rem;
      }

      .connect-btn:hover {
        background: var(--attestto-primary, #594FD3);
        color: white;
      }

      .step-indicator {
        display: flex;
        gap: 1rem;
        margin-bottom: 1.5rem;
        font-size: 0.8rem;
        color: var(--attestto-text-muted, #64748b);
      }

      .step {
        display: flex;
        align-items: center;
        gap: 0.35rem;
      }

      .step-active {
        color: var(--attestto-primary, #594FD3);
        font-weight: 600;
      }

      .step-done {
        color: var(--attestto-success, #16a34a);
      }

      .download-link {
        display: block;
        text-align: center;
        margin-top: 1rem;
        padding: 0.75rem;
        background: var(--attestto-success-bg, #dcfce7);
        color: var(--attestto-success, #16a34a);
        border-radius: 8px;
        text-decoration: none;
        font-weight: 600;
      }
    `,
  ]

  @state() private dragging = false
  @state() private file: File | null = null
  @state() private discovering = false
  @state() private wallets: WalletAnnouncement[] = []
  @state() private selectedWallet: WalletAnnouncement | null = null
  @state() private signing = false
  @state() private signed = false
  @state() private signedBlobUrl: string | null = null
  @state() private signedFileName: string | null = null
  @state() private error: string | null = null

  override connectedCallback() {
    super.connectedCallback()
    this.discover()
  }

  override render() {
    return html`
      ${this.renderWalletStatus()}
      ${this.file ? this.renderSignFlow() : this.renderDropZone()}
    `
  }

  // ── Wallet Status ──────────────────────────────────────────────────

  private renderWalletStatus() {
    if (this.discovering) {
      return html`
        <div class="wallet-status wallet-discovering">
          Discovering credential wallets...
        </div>
      `
    }

    if (this.selectedWallet) {
      return html`
        <div class="wallet-card" part="wallet-card">
          <img
            class="wallet-card-icon"
            src=${this.selectedWallet.icon}
            alt=${this.selectedWallet.name}
            @error=${(e: Event) => { (e.target as HTMLImageElement).style.display = 'none' }}
          />
          <div class="wallet-card-info">
            <div class="wallet-card-name">${this.selectedWallet.name}</div>
            <div class="wallet-card-meta">
              by ${this.selectedWallet.maintainer.name}
              ${this.selectedWallet.protocols.length
                ? html` · ${this.selectedWallet.protocols.join(', ')}`
                : ''}
            </div>
          </div>
          <button class="wallet-card-disconnect" @click=${this.disconnect}>Disconnect</button>
        </div>
      `
    }

    if (this.wallets.length > 0) {
      return html`
        <button class="connect-btn" @click=${this.pickFromDiscovered}>
          ${this.wallets.length} wallet${this.wallets.length > 1 ? 's' : ''} found — Connect
        </button>
      `
    }

    return html`
      <div class="wallet-status wallet-missing">
        No DID wallet found —
        <a href="https://attestto.com/wallet" target="_blank">Get Attestto ID</a>
        or use any compatible wallet
        <button
          style="margin-left: auto; background: none; border: 1px solid currentColor; padding: 0.2rem 0.5rem; border-radius: 4px; color: inherit; cursor: pointer; font-size: 0.75rem;"
          @click=${this.discover}
        >Retry</button>
      </div>
    `
  }

  private renderDropZone() {
    return html`
      <div
        class="drop-zone ${this.dragging ? 'dragging' : ''}"
        @click=${this.openFilePicker}
        @dragover=${this.onDragOver}
        @dragleave=${this.onDragLeave}
        @drop=${this.onDrop}
      >
        <div class="drop-zone-icon">${this.selectedWallet ? '✍️' : '📄'}</div>
        <div style="font-size: 1rem; color: var(--attestto-text-muted, #64748b)">
          ${this.selectedWallet
            ? 'Drop a PDF to sign with your DID'
            : 'Drop a PDF to sign'}
        </div>
        <div style="font-size: 0.8rem; color: var(--attestto-text-muted, #94a3b8); margin-top: 0.5rem">
          Your document never leaves your device
        </div>
        <input type="file" @change=${this.onFileSelect} accept=".pdf" />
      </div>
    `
  }

  private renderSignFlow() {
    return html`
      <div class="sign-card">
        <div class="step-indicator">
          <span class="step ${this.file ? 'step-done' : 'step-active'}">1. Select PDF</span>
          <span class="step ${this.signed ? 'step-done' : this.file && !this.signed ? 'step-active' : ''}">2. Sign</span>
          <span class="step ${this.signed ? 'step-done' : ''}">3. Download</span>
        </div>

        <div class="file-info">
          📄 ${this.file!.name}
          <span style="font-weight: 400; font-size: 0.8rem; color: var(--attestto-text-muted, #64748b)">
            ${this.formatSize(this.file!.size)}
          </span>
        </div>

        ${this.error
          ? html`<div style="color: var(--attestto-warning, #d97706); font-size: 0.85rem; margin-bottom: 1rem">${this.error}</div>`
          : ''}

        ${!this.signed
          ? html`
              <button
                class="sign-btn"
                ?disabled=${!this.selectedWallet || this.signing}
                @click=${this.sign}
              >
                ${this.signing
                  ? 'Signing...'
                  : this.selectedWallet
                    ? `Sign with ${this.selectedWallet.name}`
                    : 'Connect wallet first'}
              </button>
            `
          : html`
              <a class="download-link" href=${this.signedBlobUrl!} download=${this.signedFileName!}>
                Download Signed Receipt
              </a>
            `}

        <div style="text-align: center; margin-top: 0.75rem">
          <button
            style="background: none; border: none; color: var(--attestto-text-muted, #94a3b8); cursor: pointer; font-size: 0.8rem"
            @click=${this.reset}
          >
            ${this.signed ? 'Sign another document' : 'Cancel'}
          </button>
        </div>
      </div>
    `
  }

  // ── Wallet Discovery (via @attestto/id-wallet-adapter) ─────────────

  private async discover() {
    this.discovering = true
    try {
      this.wallets = await discoverWallets(1500)
      // Auto-connect if exactly one wallet found
      if (this.wallets.length === 1) {
        this.selectedWallet = this.wallets[0]
      }
    } finally {
      this.discovering = false
    }
  }

  private async pickFromDiscovered() {
    // Use the built-in wallet picker modal
    const wallet = await pickWallet({ timeoutMs: 2000 })
    if (wallet) {
      this.selectedWallet = wallet
    }
  }

  private disconnect() {
    this.selectedWallet = null
  }

  // ── File Handlers ───────────────────────────────────────────────────

  private onDragOver(e: DragEvent) {
    e.preventDefault()
    this.dragging = true
  }

  private onDragLeave() {
    this.dragging = false
  }

  private onDrop(e: DragEvent) {
    e.preventDefault()
    this.dragging = false
    const file = e.dataTransfer?.files[0]
    if (file && file.name.toLowerCase().endsWith('.pdf')) {
      this.file = file
      this.error = null
    } else {
      this.error = 'Only PDF files can be signed'
    }
  }

  private openFilePicker() {
    const input = this.shadowRoot?.querySelector('input[type="file"]') as HTMLInputElement
    input?.click()
  }

  private onFileSelect(e: Event) {
    const input = e.target as HTMLInputElement
    const file = input.files?.[0]
    if (file) {
      this.file = file
      this.error = null
    }
  }

  // ── Signing (CHAPI VP request) ─────────────────────────────────────

  private async sign() {
    if (!this.file || !this.selectedWallet) return

    this.signing = true
    this.error = null

    try {
      // Compute content hash
      const buffer = await this.file.arrayBuffer()
      const hashBuffer = await crypto.subtle.digest('SHA-256', buffer)
      const hashArray = Array.from(new Uint8Array(hashBuffer))
      const contentHash = hashArray.map((b) => b.toString(16).padStart(2, '0')).join('')

      // Request signature from wallet via CHAPI
      const requestId = crypto.randomUUID()
      const response = await this.requestWalletSignature(requestId, contentHash, this.file.name)

      if (!response) {
        this.error = 'Signature request was cancelled or timed out'
        return
      }

      const receipt = {
        version: '1.0',
        document: {
          fileName: this.file.name,
          hash: contentHash,
          hashAlgorithm: 'SHA-256',
          size: this.file.size,
        },
        signature: {
          did: response.did,
          signature: response.signature,
          publicKeyJwk: response.publicKeyJwk,
          timestamp: response.timestamp,
        },
        wallet: {
          name: this.selectedWallet.name,
          did: this.selectedWallet.did,
          protocols: this.selectedWallet.protocols,
        },
        verifyUrl: `https://verify.attestto.com/d/${contentHash}`,
      }

      const blob = new Blob([JSON.stringify(receipt, null, 2)], { type: 'application/json' })
      this.signedBlobUrl = URL.createObjectURL(blob)
      this.signedFileName = this.file.name.replace(/\.pdf$/i, '.attestto-receipt.json')
      this.signed = true
    } catch (err) {
      this.error = err instanceof Error ? err.message : 'Signing failed'
    } finally {
      this.signing = false
    }
  }

  private requestWalletSignature(
    requestId: string,
    contentHash: string,
    title: string
  ): Promise<{ did: string; signature: string; publicKeyJwk: JsonWebKey; timestamp: string } | null> {
    return new Promise((resolve) => {
      const timeout = setTimeout(() => {
        window.removeEventListener('message', handler)
        resolve(null)
      }, 120_000)

      const handler = (event: MessageEvent) => {
        if (event.source !== window) return
        const data = event.data
        if (
          data?.type === 'ATTESTTO_SIGN_RESPONSE' &&
          data?.requestId === requestId
        ) {
          clearTimeout(timeout)
          window.removeEventListener('message', handler)
          if (data.approved) {
            resolve({
              did: data.did,
              signature: data.signature,
              publicKeyJwk: data.publicKeyJwk,
              timestamp: data.timestamp,
            })
          } else {
            resolve(null)
          }
        }
      }

      window.addEventListener('message', handler)
      window.postMessage(
        {
          type: 'ATTESTTO_SIGN_REQUEST',
          requestId,
          signingToken: contentHash,
          documentTitle: title,
        },
        '*'
      )
    })
  }

  private reset() {
    if (this.signedBlobUrl) URL.revokeObjectURL(this.signedBlobUrl)
    this.file = null
    this.signed = false
    this.signing = false
    this.signedBlobUrl = null
    this.signedFileName = null
    this.error = null
  }

  private formatSize(bytes: number): string {
    if (bytes < 1024) return `${bytes} B`
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`
    return `${(bytes / (1024 * 1024)).toFixed(1)} MB`
  }
}

declare global {
  interface HTMLElementTagNameMap {
    'attestto-sign': AttesttoSign
  }
}

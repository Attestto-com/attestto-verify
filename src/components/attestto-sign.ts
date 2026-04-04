import { LitElement, html, css } from 'lit'
import { customElement, state } from 'lit/decorators.js'
import { sharedStyles } from '../styles/shared.js'
import { discoverWallets, pickWallet, type WalletAnnouncement } from '@attestto/id-wallet-adapter'
import {
  hashFile,
  signWithWallet,
  signWithBrowserKey,
  getBrowserKeyPair,
  exportCredentialAsJson,
  type DocumentSignatureCredential,
} from '../composables/document-signer.js'
import { loadPdfJs, formatPdfDate } from '../composables/pdf-verifier.js'

interface PdfMeta {
  title: string | null
  author: string | null
  subject: string | null
  creator: string | null
  producer: string | null
  creationDate: string | null
  modDate: string | null
  pages: number | null
}

/**
 * <attestto-sign> — Sign a PDF with any DID wallet or browser key
 *
 * UI-only component. All crypto and VC construction lives in
 * composables/document-signer.ts — v2 changes touch one file.
 *
 * Flow:
 *   1. discoverWallets() finds installed credential wallets
 *   2. User picks a wallet (or auto-selects, or falls back to browser key)
 *   3. User drops a PDF
 *   4. signWithWallet() or signWithBrowserKey() produces a W3C VC
 *   5. VC pushed to wallet (or exported as JSON)
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
        border-color: var(--attestto-primary, #594fd3);
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
        background: var(--attestto-primary, #594fd3);
        color: white;
      }

      .sign-btn:hover {
        background: var(--attestto-primary-hover, #7b72ed);
      }

      .sign-btn:disabled {
        opacity: 0.5;
        cursor: not-allowed;
      }

      .connect-btn {
        width: 100%;
        padding: 0.65rem;
        border: 1px solid var(--attestto-primary, #594fd3);
        border-radius: 8px;
        font-size: 0.9rem;
        font-weight: 600;
        cursor: pointer;
        transition: all 0.15s;
        background: transparent;
        color: var(--attestto-primary, #594fd3);
        margin-bottom: 1rem;
      }

      .connect-btn:hover {
        background: var(--attestto-primary, #594fd3);
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
        color: var(--attestto-primary, #594fd3);
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
  @state() private useBrowserKey = false
  @state() private signing = false
  @state() private signingStatus = ''
  @state() private signed = false
  @state() private signedCredential: DocumentSignatureCredential | null = null
  @state() private error: string | null = null
  @state() private pdfMeta: PdfMeta | null = null

  override connectedCallback() {
    super.connectedCallback()
    this.discover()
  }

  override render() {
    return html`
      ${this.renderWalletStatus()} ${this.file ? this.renderSignFlow() : this.renderDropZone()}
    `
  }

  // ── Wallet Status ──────────────────────────────────────────────────

  private renderWalletStatus() {
    if (this.discovering) {
      return html`
        <div class="wallet-status wallet-discovering">Discovering credential wallets...</div>
      `
    }

    if (this.selectedWallet) {
      return html`
        <div class="wallet-card" part="wallet-card">
          <img
            class="wallet-card-icon"
            src=${this.selectedWallet.icon}
            alt=${this.selectedWallet.name}
            @error=${(e: Event) => {
              ;(e.target as HTMLImageElement).style.display = 'none'
            }}
          />
          <div class="wallet-card-info">
            <div class="wallet-card-name">${this.selectedWallet.name}</div>
            <div class="wallet-card-meta">by ${this.selectedWallet.maintainer.name}</div>
          </div>
          <button class="wallet-card-disconnect" @click=${this.disconnect}>Change</button>
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

    if (this.useBrowserKey) {
      return html`
        <div class="wallet-card" part="wallet-card">
          <div
            style="width: 32px; height: 32px; border-radius: 6px; background: var(--attestto-primary, #594FD3); display: flex; align-items: center; justify-content: center; color: white; font-size: 0.9rem; font-weight: 700; flex-shrink: 0;"
          >
            &#x1f511;
          </div>
          <div class="wallet-card-info">
            <div class="wallet-card-name">Browser Key</div>
            <div class="wallet-card-meta">self-issued &middot; did:key</div>
          </div>
          <button class="wallet-card-disconnect" @click=${this.disconnect}>Change</button>
        </div>
      `
    }

    return html`
      <div class="wallet-status wallet-missing" style="flex-wrap: wrap; gap: 0.5rem;">
        <span>No DID wallet found</span>
        <span style="display: flex; gap: 0.5rem; margin-left: auto;">
          <button
            style="background: none; border: 1px solid currentColor; padding: 0.25rem 0.6rem; border-radius: 4px; color: inherit; cursor: pointer; font-size: 0.75rem;"
            @click=${this.enableBrowserKey}
          >
            Sign with browser key
          </button>
          <button
            style="background: none; border: 1px solid currentColor; padding: 0.25rem 0.6rem; border-radius: 4px; color: inherit; cursor: pointer; font-size: 0.75rem;"
            @click=${this.discover}
          >
            Retry
          </button>
        </span>
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
        <div class="drop-zone-icon">${this.selectedWallet || this.useBrowserKey ? '✍️' : '📄'}</div>
        <div style="font-size: 1rem; color: var(--attestto-text-muted, #64748b)">
          ${this.selectedWallet
            ? 'Drop a PDF to sign with your DID'
            : this.useBrowserKey
              ? 'Drop a PDF to sign with browser key'
              : 'Drop a PDF to sign'}
        </div>
        <div
          style="font-size: 0.8rem; color: var(--attestto-text-muted, #94a3b8); margin-top: 0.5rem"
        >
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
          <span
            class="step ${this.signed
              ? 'step-done'
              : this.file && !this.signed
                ? 'step-active'
                : ''}"
            >2. Sign</span
          >
          <span class="step ${this.signed ? 'step-done' : ''}">3. Download</span>
        </div>

        <div class="file-info">
          📄 ${this.file!.name}
          <span
            style="font-weight: 400; font-size: 0.8rem; color: var(--attestto-text-muted, #64748b)"
          >
            ${this.formatSize(this.file!.size)}
          </span>
        </div>

        ${this.pdfMeta ? html`
          <div style="display: grid; grid-template-columns: auto 1fr; gap: 0.25rem 0.75rem; font-size: 0.82rem; margin-bottom: 1rem; padding: 0.75rem; background: var(--attestto-bg-code, #f1f5f9); border-radius: 8px;">
            ${this.pdfMeta.title ? html`<span style="color: var(--attestto-text-muted, #64748b); font-weight: 500;">Title</span><span>${this.pdfMeta.title}</span>` : ''}
            ${this.pdfMeta.author ? html`<span style="color: var(--attestto-text-muted, #64748b); font-weight: 500;">Author</span><span>${this.pdfMeta.author}</span>` : ''}
            ${this.pdfMeta.pages ? html`<span style="color: var(--attestto-text-muted, #64748b); font-weight: 500;">Pages</span><span>${this.pdfMeta.pages}</span>` : ''}
            ${this.pdfMeta.creator ? html`<span style="color: var(--attestto-text-muted, #64748b); font-weight: 500;">Creator</span><span>${this.pdfMeta.creator}</span>` : ''}
            ${this.pdfMeta.creationDate ? html`<span style="color: var(--attestto-text-muted, #64748b); font-weight: 500;">Created</span><span>${this.pdfMeta.creationDate}</span>` : ''}
            ${this.pdfMeta.modDate ? html`<span style="color: var(--attestto-text-muted, #64748b); font-weight: 500;">Modified</span><span>${this.pdfMeta.modDate}</span>` : ''}
          </div>
        ` : ''}

        ${this.error
          ? html`<div
              style="color: var(--attestto-warning, #d97706); font-size: 0.85rem; margin-bottom: 1rem"
            >
              ${this.error}
              ${this.selectedWallet && !this.useBrowserKey
                ? html`<br /><button
                    style="background: none; border: none; color: var(--attestto-primary, #594fd3); cursor: pointer; font-size: 0.82rem; text-decoration: underline; padding: 0.25rem 0 0;"
                    @click=${this.enableBrowserKey}
                  >Use browser key instead</button>`
                : ''}
            </div>`
          : ''}
        ${!this.signed
          ? html`
              <button
                class="sign-btn"
                ?disabled=${(!this.selectedWallet && !this.useBrowserKey) || this.signing}
                @click=${this.sign}
              >
                ${this.signing
                  ? this.signingStatus || 'Signing...'
                  : this.selectedWallet
                    ? `Sign with ${this.selectedWallet.name}`
                    : this.useBrowserKey
                      ? 'Sign with browser key'
                      : 'Connect wallet first'}
              </button>
            `
          : html`
              <div class="download-link" style="cursor: default; margin-bottom: 0.75rem;">
                ${this.useBrowserKey
                  ? 'Signed with browser key'
                  : 'Signed — credential stored in your wallet'}
              </div>
              <button
                class="sign-btn"
                style="background: var(--attestto-success, #16a34a);"
                @click=${this.handleExport}
              >
                Download Signed Credential (.json)
              </button>
              <div style="font-size: 0.72rem; color: var(--attestto-text-muted, #94a3b8); text-align: center; margin-top: 0.5rem;">
                This W3C Verifiable Credential can be verified at <a href="/" style="color: var(--attestto-primary, #594fd3); text-decoration: none;">verify.attestto.com</a>
              </div>
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

  // ── Wallet Discovery ──────────────────────────────────────────────

  private async discover() {
    this.discovering = true
    try {
      this.wallets = await discoverWallets(1500)
      if (this.wallets.length === 1) {
        this.selectedWallet = this.wallets[0]
      }
    } finally {
      this.discovering = false
    }
  }

  private async pickFromDiscovered() {
    const wallet = await pickWallet({ timeoutMs: 2000 })
    if (wallet) {
      this.selectedWallet = wallet
    }
  }

  private disconnect() {
    this.selectedWallet = null
    this.useBrowserKey = false
  }

  private async enableBrowserKey() {
    await getBrowserKeyPair()
    this.useBrowserKey = true
  }

  // ── File Handlers ─────────────────────────────────────────────────

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
      this.extractMetadata(file)
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
      this.extractMetadata(file)
    }
  }

  private async extractMetadata(file: File): Promise<void> {
    this.pdfMeta = null
    try {
      const pdfjsLib = await loadPdfJs()
      if (!pdfjsLib) return
      const buffer = await file.arrayBuffer()
      const pdf = await pdfjsLib.getDocument({ data: buffer }).promise
      const meta = await pdf.getMetadata()
      const info = meta?.info as Record<string, unknown> | undefined
      this.pdfMeta = {
        title: (info?.Title as string) || null,
        author: (info?.Author as string) || null,
        subject: (info?.Subject as string) || null,
        creator: (info?.Creator as string) || null,
        producer: (info?.Producer as string) || null,
        creationDate: info?.CreationDate ? formatPdfDate(info.CreationDate as string) : null,
        modDate: info?.ModDate ? formatPdfDate(info.ModDate as string) : null,
        pages: pdf.numPages ?? null,
      }
    } catch {
      // Metadata extraction is best-effort
    }
  }

  // ── Signing (delegates to composable) ─────────────────────────────

  private async sign() {
    if (!this.file) return
    if (!this.selectedWallet && !this.useBrowserKey) return

    this.signing = true
    this.signingStatus = 'Computing hash...'
    this.error = null

    try {
      const hash = await hashFile(this.file)

      if (this.selectedWallet) {
        this.signingStatus = 'Waiting for wallet approval...'
        const result = await signWithWallet(this.selectedWallet, this.file, hash)
        if (!result) {
          this.error =
            'Wallet did not respond in time. Click "Sign" to retry, or try "Sign with browser key" below.'
          return
        }
        this.signedCredential = result.credential
      } else {
        this.signingStatus = 'Signing with browser key...'
        const result = await signWithBrowserKey(this.file, hash)
        this.signedCredential = result.credential
      }

      this.signed = true
    } catch (err) {
      this.error = err instanceof Error ? err.message : 'Signing failed'
    } finally {
      this.signing = false
      this.signingStatus = ''
    }
  }

  private handleExport() {
    if (!this.signedCredential) return
    exportCredentialAsJson(this.signedCredential, this.file?.name)
  }

  private reset() {
    this.file = null
    this.signed = false
    this.signing = false
    this.signedCredential = null
    this.error = null
    this.pdfMeta = null
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

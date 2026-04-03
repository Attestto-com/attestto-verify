import { LitElement, html, css } from 'lit'
import { customElement, property, state } from 'lit/decorators.js'
import { verifyPdf, type PdfVerificationResult } from '../composables/pdf-verifier.js'
import { attesttoPlugins, type VerificationResult } from '../plugins/registry.js'
import { sharedStyles } from '../styles/shared.js'

/**
 * <attestto-verify> — Drop a PDF to verify its integrity and signatures
 *
 * Usage:
 *   <attestto-verify></attestto-verify>
 *   <attestto-verify hash="abc123"></attestto-verify>
 *   <attestto-verify allow-plugins theme="dark" root-ca="Attestto-Root-2026"></attestto-verify>
 *
 * CSS Parts (for external styling without breaking shadow DOM):
 *   ::part(drop-zone)    — the file drop area
 *   ::part(result-card)  — the verification results container
 *   ::part(hash-display) — the SHA-256 hash display
 *   ::part(sig-card)     — each signature card
 *   ::part(badge)        — status badges (Signed, None, Valid, Failed)
 *   ::part(button)       — action buttons
 *
 * Events (composed, cross shadow DOM):
 *   verification-started  — { fileName, fileSize }
 *   verification-complete — { hash, signatures, plugins }
 *
 * No login. No backend. 100% client-side.
 */
@customElement('attestto-verify')
export class AttesttoVerify extends LitElement {
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
        border-color: var(--attestto-primary, #6366f1);
        background: var(--attestto-bg-hover, #eef2ff);
      }

      .drop-zone-icon {
        font-size: 2.5rem;
        margin-bottom: 0.75rem;
      }

      .drop-zone-text {
        font-size: 1rem;
        color: var(--attestto-text-muted, #64748b);
      }

      .drop-zone-hint {
        font-size: 0.8rem;
        color: var(--attestto-text-muted, #64748b);
        margin-top: 0.5rem;
      }

      input[type='file'] {
        display: none;
      }

      .result {
        margin-top: 1.5rem;
      }

      .result-card {
        border: 1px solid var(--attestto-border, #e2e8f0);
        border-radius: 12px;
        padding: 1.5rem;
        background: var(--attestto-bg-card, #ffffff);
      }

      .result-header {
        display: flex;
        align-items: center;
        gap: 0.75rem;
        margin-bottom: 1rem;
        font-size: 1.1rem;
        font-weight: 600;
      }

      .hash-display {
        font-family: 'SF Mono', 'Fira Code', monospace;
        font-size: 0.8rem;
        word-break: break-all;
        background: var(--attestto-bg-code, #f1f5f9);
        padding: 0.75rem 1rem;
        border-radius: 8px;
        cursor: pointer;
        position: relative;
        transition: background 0.15s;
      }

      .hash-display:hover {
        background: var(--attestto-bg-code-hover, #e2e8f0);
      }

      .hash-label {
        font-size: 0.75rem;
        font-weight: 600;
        text-transform: uppercase;
        letter-spacing: 0.05em;
        color: var(--attestto-text-muted, #64748b);
        margin-bottom: 0.25rem;
      }

      .meta-grid {
        display: grid;
        grid-template-columns: auto 1fr;
        gap: 0.35rem 1rem;
        font-size: 0.85rem;
        margin-top: 1rem;
      }

      .meta-label {
        color: var(--attestto-text-muted, #64748b);
        font-weight: 500;
      }

      .sig-card {
        border: 1px solid var(--attestto-border, #e2e8f0);
        border-radius: 8px;
        padding: 1rem;
        margin-top: 0.75rem;
        background: var(--attestto-bg-card, #ffffff);
      }

      .sig-name {
        font-weight: 600;
        display: flex;
        align-items: center;
        gap: 0.5rem;
      }

      .badge {
        display: inline-flex;
        align-items: center;
        gap: 0.25rem;
        padding: 0.15rem 0.5rem;
        border-radius: 999px;
        font-size: 0.7rem;
        font-weight: 600;
        text-transform: uppercase;
      }

      .badge-signed {
        background: var(--attestto-success-bg, #dcfce7);
        color: var(--attestto-success, #16a34a);
      }

      .badge-none {
        background: var(--attestto-warning-bg, #fef3c7);
        color: var(--attestto-warning, #d97706);
      }

      .section-title {
        font-size: 0.85rem;
        font-weight: 600;
        text-transform: uppercase;
        letter-spacing: 0.05em;
        color: var(--attestto-text-muted, #64748b);
        margin-top: 1.25rem;
        margin-bottom: 0.5rem;
      }

      .plugin-results {
        margin-top: 1rem;
      }

      .copied-toast {
        position: fixed;
        bottom: 1.5rem;
        left: 50%;
        transform: translateX(-50%);
        background: var(--attestto-text, #1a1a2e);
        color: white;
        padding: 0.5rem 1rem;
        border-radius: 8px;
        font-size: 0.85rem;
        z-index: 1000;
        animation: fadeInOut 1.5s ease;
      }

      @keyframes fadeInOut {
        0% { opacity: 0; transform: translateX(-50%) translateY(10px); }
        15% { opacity: 1; transform: translateX(-50%) translateY(0); }
        85% { opacity: 1; }
        100% { opacity: 0; }
      }

      .loading {
        display: flex;
        align-items: center;
        gap: 0.5rem;
        color: var(--attestto-text-muted, #64748b);
        padding: 1rem 0;
      }

      .spinner {
        width: 1rem;
        height: 1rem;
        border: 2px solid var(--attestto-border, #e2e8f0);
        border-top-color: var(--attestto-primary, #6366f1);
        border-radius: 50%;
        animation: spin 0.6s linear infinite;
      }

      @keyframes spin {
        to { transform: rotate(360deg); }
      }
    `,
  ]

  /** Pre-filled hash for deep-link mode (/d/{hash}) */
  @property({ type: String }) hash = ''

  @state() private dragging = false
  @state() private verifying = false
  @state() private result: PdfVerificationResult | null = null
  @state() private pluginResults: Map<string, VerificationResult> | null = null
  @state() private showCopied = false

  override render() {
    return html`
      ${this.result ? this.renderResult() : this.renderDropZone()}
      ${this.showCopied ? html`<div class="copied-toast">Hash copied to clipboard</div>` : ''}
    `
  }

  private renderDropZone() {
    return html`
      <div
        class="drop-zone ${this.dragging ? 'dragging' : ''}" part="drop-zone"
        @click=${this.openFilePicker}
        @dragover=${this.onDragOver}
        @dragleave=${this.onDragLeave}
        @drop=${this.onDrop}
      >
        <div class="drop-zone-icon">📄</div>
        <div class="drop-zone-text">
          ${this.dragging ? 'Drop file here' : 'Drop a document to verify'}
        </div>
        <div class="drop-zone-hint">
          PDF, Word, or any file — never leaves your device
        </div>
        <input type="file" @change=${this.onFileSelect} accept=".pdf,.doc,.docx,.txt,.json" />
      </div>
    `
  }

  private renderResult() {
    const r = this.result!
    return html`
      <div class="result">
        <div class="result-card" part="result-card">
          <div class="result-header">
            📄 ${r.fileName}
            <span style="font-size: 0.8rem; font-weight: 400; color: var(--attestto-text-muted, #64748b)">
              ${this.formatSize(r.fileSize)}
            </span>
          </div>

          <div class="hash-label">SHA-256 Hash</div>
          <div class="hash-display" part="hash-display" @click=${this.copyHash} title="Click to copy">
            ${r.hash}
          </div>

          ${r.isPdf && r.signatures.length > 0
            ? html`
                <div class="section-title">Digital Signatures</div>
                ${r.signatures.map(
                  (sig) => html`
                    <div class="sig-card" part="sig-card">
                      <div class="sig-name">
                        <span class="badge badge-signed">Signed</span>
                        ${sig.name}
                      </div>
                      <div class="meta-grid">
                        ${sig.reason ? html`<span class="meta-label">Reason</span><span>${sig.reason}</span>` : ''}
                        ${sig.location ? html`<span class="meta-label">Location</span><span>${sig.location}</span>` : ''}
                        ${sig.contactInfo ? html`<span class="meta-label">Contact</span><span>${sig.contactInfo}</span>` : ''}
                        ${sig.signDate ? html`<span class="meta-label">Signed</span><span>${sig.signDate}</span>` : ''}
                      </div>
                    </div>
                  `
                )}
              `
            : r.isPdf
              ? html`
                  <div class="section-title">Digital Signatures</div>
                  <div class="sig-card" part="sig-card">
                    <div class="sig-name">
                      <span class="badge badge-none">None</span>
                      No digital signatures found
                    </div>
                  </div>
                `
              : ''}

          ${r.isPdf && r.metadata
            ? html`
                <div class="section-title">Document Metadata</div>
                <div class="meta-grid">
                  ${r.metadata.title ? html`<span class="meta-label">Title</span><span>${r.metadata.title}</span>` : ''}
                  ${r.metadata.author ? html`<span class="meta-label">Author</span><span>${r.metadata.author}</span>` : ''}
                  ${r.metadata.creator ? html`<span class="meta-label">Creator</span><span>${r.metadata.creator}</span>` : ''}
                  ${r.metadata.producer ? html`<span class="meta-label">Producer</span><span>${r.metadata.producer}</span>` : ''}
                  ${r.metadata.creationDate ? html`<span class="meta-label">Created</span><span>${r.metadata.creationDate}</span>` : ''}
                  ${r.metadata.modDate ? html`<span class="meta-label">Modified</span><span>${r.metadata.modDate}</span>` : ''}
                </div>
              `
            : ''}

          ${this.pluginResults && this.pluginResults.size > 0
            ? html`
                <div class="section-title">Extended Verification</div>
                <div class="plugin-results">
                  ${Array.from(this.pluginResults.entries()).map(
                    ([name, result]) => html`
                      <div class="sig-card" part="sig-card">
                        <div class="sig-name">
                          <span class="badge ${result.valid ? 'badge-signed' : 'badge-none'}">
                            ${result.valid ? 'Valid' : 'Failed'}
                          </span>
                          ${attesttoPlugins.get(name)?.label ?? name}
                        </div>
                        ${result.error ? html`<div style="color: var(--attestto-warning, #d97706); font-size: 0.85rem; margin-top: 0.5rem">${result.error}</div>` : ''}
                      </div>
                    `
                  )}
                </div>
              `
            : ''}
        </div>

        <div style="text-align: center; margin-top: 1rem">
          <button
            style="
              background: none;
              border: 1px solid var(--attestto-border, #cbd5e1);
              padding: 0.5rem 1.25rem;
              border-radius: 8px;
              cursor: pointer;
              font-size: 0.85rem;
              color: var(--attestto-text-muted, #64748b);
            "
            @click=${this.reset}
          >
            Verify another document
          </button>
        </div>
      </div>
    `
  }

  // ── Event handlers ──────────────────────────────────────────────────

  private onDragOver(e: DragEvent) {
    e.preventDefault()
    this.dragging = true
  }

  private onDragLeave() {
    this.dragging = false
  }

  private async onDrop(e: DragEvent) {
    e.preventDefault()
    this.dragging = false
    const file = e.dataTransfer?.files[0]
    if (file) await this.verify(file)
  }

  private openFilePicker() {
    const input = this.shadowRoot?.querySelector('input[type="file"]') as HTMLInputElement
    input?.click()
  }

  private async onFileSelect(e: Event) {
    const input = e.target as HTMLInputElement
    const file = input.files?.[0]
    if (file) await this.verify(file)
  }

  private async verify(file: File) {
    this.verifying = true
    this.result = null
    this.pluginResults = null

    // Dispatch composed event (crosses shadow DOM for external listeners)
    this.dispatchEvent(
      new CustomEvent('verification-started', {
        detail: { fileName: file.name, fileSize: file.size },
        composed: true,
        bubbles: true,
      })
    )

    try {
      // 1. Core integrity check (always runs — the "sandwich" base layer)
      this.result = await verifyPdf(file)

      // 2. Run registered verifier plugins (can only ADD trust, never bypass core)
      const verifiers = attesttoPlugins.getByType('verifier')
      if (verifiers.length > 0) {
        this.pluginResults = await attesttoPlugins.runVerifiers(this.result.hash, {
          fileName: this.result.fileName,
          signatures: this.result.signatures,
        })
      }

      // Dispatch result event
      this.dispatchEvent(
        new CustomEvent('verification-complete', {
          detail: {
            hash: this.result.hash,
            signatures: this.result.signatures.length,
            plugins: this.pluginResults ? Object.fromEntries(this.pluginResults) : {},
          },
          composed: true,
          bubbles: true,
        })
      )
    } finally {
      this.verifying = false
    }
  }

  private async copyHash() {
    if (!this.result?.hash) return
    try {
      await navigator.clipboard.writeText(this.result.hash)
      this.showCopied = true
      setTimeout(() => { this.showCopied = false }, 1500)
    } catch {
      // Clipboard API not available
    }
  }

  private reset() {
    this.result = null
    this.pluginResults = null
  }

  private formatSize(bytes: number): string {
    if (bytes < 1024) return `${bytes} B`
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`
    return `${(bytes / (1024 * 1024)).toFixed(1)} MB`
  }
}

declare global {
  interface HTMLElementTagNameMap {
    'attestto-verify': AttesttoVerify
  }
}

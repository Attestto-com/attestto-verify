import { LitElement, html, css } from 'lit'
import { customElement, property, state } from 'lit/decorators.js'

/**
 * <attestto-consent> — Cookie consent banner + GA4 loader
 *
 * Usage:
 *   <attestto-consent ga="G-JCE4RZ8CCC"></attestto-consent>
 *
 * Drops into any HTML page. Shows a minimal consent banner on first visit.
 * Only loads Google Analytics AFTER the user accepts. Consent stored in
 * localStorage so the banner only appears once.
 *
 * Attributes:
 *   ga        — GA4 measurement ID (e.g. G-JCE4RZ8CCC)
 *   position  — 'bottom' (default) or 'top'
 *
 * Events:
 *   consent-accepted  — fired when user accepts
 *   consent-rejected  — fired when user rejects
 */
@customElement('attestto-consent')
export class AttesttoConsent extends LitElement {
  static override styles = css`
    :host {
      display: block;
      font-family: system-ui, -apple-system, sans-serif;
    }

    .banner {
      position: fixed;
      left: 0;
      right: 0;
      z-index: 99999;
      background: #0f172a;
      border-top: 1px solid #334155;
      padding: 0.75rem 1.5rem;
      display: flex;
      align-items: center;
      justify-content: center;
      gap: 1rem;
      font-size: 0.82rem;
      color: #94a3b8;
      animation: slideUp 0.3s ease;
    }

    .banner.bottom { bottom: 0; }
    .banner.top { top: 0; border-top: none; border-bottom: 1px solid #334155; }

    @keyframes slideUp {
      from { transform: translateY(100%); opacity: 0; }
      to { transform: translateY(0); opacity: 1; }
    }

    .banner.top {
      animation-name: slideDown;
    }

    @keyframes slideDown {
      from { transform: translateY(-100%); opacity: 0; }
      to { transform: translateY(0); opacity: 1; }
    }

    .text {
      flex: 1;
      min-width: 0;
    }

    .text a {
      color: #594fd3;
      text-decoration: none;
    }

    .buttons {
      display: flex;
      gap: 0.5rem;
      flex-shrink: 0;
    }

    button {
      padding: 0.4rem 0.9rem;
      border-radius: 6px;
      font-size: 0.78rem;
      font-weight: 600;
      cursor: pointer;
      border: none;
      transition: all 0.15s;
    }

    .accept {
      background: #594fd3;
      color: #fff;
    }

    .accept:hover {
      background: #7b72ed;
    }

    .reject {
      background: transparent;
      color: #64748b;
      border: 1px solid #334155;
    }

    .reject:hover {
      color: #94a3b8;
      border-color: #475569;
    }

    @media (max-width: 600px) {
      .banner {
        flex-direction: column;
        text-align: center;
        padding: 1rem;
        gap: 0.75rem;
      }
    }
  `

  @property({ type: String }) ga = ''
  @property({ type: String }) position: 'bottom' | 'top' = 'bottom'

  @state() private visible = false

  private static STORAGE_KEY = 'attestto-consent'

  override connectedCallback() {
    super.connectedCallback()
    const stored = localStorage.getItem(AttesttoConsent.STORAGE_KEY)
    if (stored === 'accepted') {
      this.loadGA()
    } else if (stored !== 'rejected') {
      this.visible = true
    }
  }

  override render() {
    if (!this.visible) return html``
    return html`
      <div class="banner ${this.position}">
        <div class="text">
          We use anonymous analytics to understand how our tools are used. No personal data is collected.
          Your files never leave your device.
        </div>
        <div class="buttons">
          <button class="reject" @click=${this.reject}>Decline</button>
          <button class="accept" @click=${this.accept}>Accept</button>
        </div>
      </div>
    `
  }

  private accept() {
    localStorage.setItem(AttesttoConsent.STORAGE_KEY, 'accepted')
    this.visible = false
    this.loadGA()
    this.dispatchEvent(new CustomEvent('consent-accepted', { composed: true, bubbles: true }))
  }

  private reject() {
    localStorage.setItem(AttesttoConsent.STORAGE_KEY, 'rejected')
    this.visible = false
    this.dispatchEvent(new CustomEvent('consent-rejected', { composed: true, bubbles: true }))
  }

  private loadGA() {
    if (!this.ga || document.querySelector(`script[src*="googletagmanager"]`)) return
    const script = document.createElement('script')
    script.async = true
    script.src = `https://www.googletagmanager.com/gtag/js?id=${this.ga}`
    document.head.appendChild(script)

    const inline = document.createElement('script')
    inline.textContent = `
      window.dataLayer = window.dataLayer || [];
      function gtag(){dataLayer.push(arguments);}
      gtag('js', new Date());
      gtag('config', '${this.ga}', { anonymize_ip: true });
    `
    document.head.appendChild(inline)
  }
}

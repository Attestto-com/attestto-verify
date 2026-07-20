/**
 * <attestto-signature-card> — the ONE standardized signature card, shared by
 * the website (attestto-verify) and the desktop station (Vue/Quasar embeds it
 * as a custom element). Both feed it the same `SignatureCardModel`.
 *
 * Design intent: the FRONT is for professionals — notaries, accountants,
 * banking officials — plain language, trust + long-term-validity signals, no
 * dev jargon. A small "see data" link opens the full DARK, tabbed, icon'd
 * internals for developers / IT. Cards use a diagonal gradient to black.
 * Theme hooks via ::part(card | avatar | status | capability | ...).
 */

import { LitElement, html, css } from 'lit'
import { customElement, property, state } from 'lit/decorators.js'
import { t, currentLang, type Lang } from '../i18n.js'
import type { SignatureCardModel, SignatureStatus, SignatureLtv } from '../model/signature-card.js'
import { initialsFor } from '../model/signature-card.js'

const STATUS_COLOR: Record<SignatureStatus, string> = {
  verified: '#22c55e',
  'structure-only': '#f59e0b',
  'self-attested': '#a78bfa',
  tampered: '#ef4444',
  unknown: '#9ca3af',
}

const STATUS_TEXT: Record<Lang, Record<SignatureStatus, { label: string; desc: string }>> = {
  en: {
    verified: {
      label: 'Verified',
      desc: 'Certificate chain validated to a trusted root and the content matches the signed hash — identity proven, document intact.',
    },
    'structure-only': {
      label: 'Structure only',
      desc: 'Signature structure was parsed, but its chain does not link to any trusted root — it may be forged, self-signed, or from a CA we don’t trust.',
    },
    'self-attested': {
      label: 'Self-attested',
      desc: 'The signer’s key proved ownership of their Attestto vault and the content matches byte-for-byte — trust anchors in verified KYC, not a third-party CA.',
    },
    tampered: {
      label: 'Tampered',
      desc: 'The document was modified after it was signed — do not trust this signature.',
    },
    unknown: {
      label: 'Unknown',
      desc: 'The integrity check could not be run on this signature. This is not a tamper signal — the state is unknown.',
    },
  },
  es: {
    verified: {
      label: 'Verificado',
      desc: 'Cadena validada contra una raíz de confianza y el contenido coincide con el hash firmado — identidad probada, documento íntegro.',
    },
    'structure-only': {
      label: 'Solo estructura',
      desc: 'Se analizó la estructura de la firma, pero su cadena no enlaza con ninguna raíz de confianza — podría ser falsificada, autofirmada o de una CA no confiable.',
    },
    'self-attested': {
      label: 'Auto-atestada',
      desc: 'La clave del firmante probó propiedad de su bóveda Attestto y el contenido coincide byte a byte — la confianza se ancla en el KYC verificado, no en una CA de terceros.',
    },
    tampered: {
      label: 'Alterada',
      desc: 'El documento fue modificado después de firmarse — no confíe en esta firma.',
    },
    unknown: {
      label: 'Desconocido',
      desc: 'No se pudo ejecutar la verificación de integridad. No es una señal de alteración — el estado es desconocido.',
    },
  },
}

type LtvTone = 'good' | 'warn' | 'neutral'

/** Professional-facing long-term-validity summary (plain language, no jargon). */
function ltvFace(
  ltv: SignatureLtv | null | undefined,
  status: SignatureStatus,
  lang: Lang,
): { label: string; detail: string; tone: LtvTone } | null {
  const es = lang === 'es'
  if (status === 'self-attested') {
    return {
      tone: 'neutral',
      label: es ? 'Anclada en el tiempo' : 'Point-in-time anchored',
      detail: es
        ? 'Validez anclada al hash del documento y al KYC del firmante en el momento de firmar.'
        : 'Validity anchored to the document hash and the signer’s KYC at signing time.',
    }
  }
  if (!ltv || ltv.tier === 'none' || ltv.tier === 'B') {
    return {
      tone: 'warn',
      label: es ? 'Sin validez a largo plazo' : 'No long-term validation',
      detail: es
        ? 'La validez depende de que el Banco Central (BCCR) siga disponible en línea.'
        : 'Validity depends on Banco Central (BCCR) staying reachable online.',
    }
  }
  const ts = ltv.timestampAt ? (es ? ` · sellada ${ltv.timestampAt}` : ` · timestamped ${ltv.timestampAt}`) : ''
  if (ltv.revocationSource === 'embedded') {
    return {
      tone: 'good',
      label: es ? `Validez a largo plazo (${ltv.tier})` : `Long-term valid (${ltv.tier})`,
      detail:
        (es
          ? 'Autocontenida — no depende de que la CA siga en línea'
          : 'Self-contained — does not depend on the CA staying online') + ts,
    }
  }
  return {
    tone: 'neutral',
    label: es ? 'Con sellado de tiempo' : 'Timestamped',
    detail:
      (es ? 'Sellada, pero sin evidencia de revocación incrustada' : 'Timestamped, but no embedded revocation evidence') +
      ts,
  }
}

const LTV_TONE_COLOR: Record<LtvTone, string> = {
  good: '#22c55e',
  warn: '#f59e0b',
  neutral: '#93c5fd',
}

function flagEmoji(code: string | null): string {
  if (!code || code.length !== 2) return '\u{1F310}'
  const u = code.toUpperCase()
  return String.fromCodePoint(0x1f1e6 + u.charCodeAt(0) - 65, 0x1f1e6 + u.charCodeAt(1) - 65)
}

function chainIcon(i: number, last: number): string {
  if (i === 0) return '\u{1F3DB}\u{FE0F}' // 🏛️ root
  if (i === last) return '\u{270D}\u{FE0F}' // ✍️ leaf
  return '\u{1F517}' // 🔗 intermediate
}

/** Icon for a capability pill, matched loosely by label. */
function capIcon(label: string): string {
  const l = label.toLowerCase()
  if (l.includes('non-repud')) return '\u{2696}\u{FE0F}' // ⚖️
  if (l.includes('digital signature')) return '\u{270D}\u{FE0F}' // ✍️
  if (l.includes('email')) return '\u{2709}\u{FE0F}' // ✉️
  if (l.includes('key')) return '\u{1F511}' // 🔑
  if (l.includes('certificate signing')) return '\u{1F4DC}' // 📜
  if (l.includes('client auth')) return '\u{1F464}' // 👤
  if (l.includes('vault')) return '\u{1F510}' // 🔐
  if (l.includes('kyc') || l.includes('padr')) return '\u{1FAAA}' // 🪪
  if (l.includes('countersign') || l.includes('open')) return '\u{2795}' // ➕
  if (l.includes('not third') || l.includes('no ') || l.includes('sin ')) return '\u{1F6AB}' // 🚫
  if (l.includes('timestamp') || l.includes('time')) return '\u{23F1}\u{FE0F}' // ⏱️
  return '\u{2022}' // •
}

/**
 * Plain-language explanation for a capability pill, in relying-party terms
 * (what the signature can *do* — not how it works internally). Keyword-matched
 * so every pill with the same meaning gets the same tooltip everywhere.
 */
function capTooltip(label: string, kind: string, lang: Lang): string {
  const l = label.toLowerCase()
  const es = lang === 'es'
  const D = (en: string, s: string) => (es ? s : en)
  if (l.includes('non-repud'))
    return D(
      'A legally binding signature — the signer cannot later deny having signed.',
      'Firma con valor legal — el firmante no puede negar después haber firmado.',
    )
  if (l.includes('document signing') || l.includes('firma de documentos'))
    return D('Authorized to sign documents.', 'Autorizada para firmar documentos.')
  if (l.includes('digital signature'))
    return D(
      'May sign data to prove its integrity and origin.',
      'Puede firmar datos para probar su integridad y origen.',
    )
  if (l.includes('identity assertion') || l.includes('aserción') || l.includes('asercion'))
    return D(
      'May assert verified identity claims to a relying party.',
      'Puede afirmar datos de identidad verificados ante un tercero.',
    )
  if (l.includes('authentication') || l.includes('autenticación') || l.includes('autenticacion'))
    return D(
      'The holder can prove control of this identity.',
      'El titular puede probar el control de esta identidad.',
    )
  if (l.includes('email'))
    return D('Authorized to sign or encrypt email (S/MIME).', 'Autorizada para firmar o cifrar correo (S/MIME).')
  if (l.includes('key'))
    return D('May establish encryption keys.', 'Puede establecer claves de cifrado.')
  if (l.includes('certificate signing'))
    return D(
      'A Certificate Authority key — it can issue certificates.',
      'Una clave de Autoridad Certificadora — puede emitir certificados.',
    )
  if (kind === 'eku')
    return D('Extended key usage declared by the issuer.', 'Uso extendido de clave declarado por el emisor.')
  return D('Declared in the certificate by the issuer.', 'Declarado en el certificado por el emisor.')
}

/** Professional cert-validity summary (vigente / vence / vencido). */
function certFace(
  cert: SignatureCardModel['cert'],
  lang: Lang,
  now: Date,
): { text: string; color: string } | null {
  if (!cert || !cert.validTo) return null
  const es = lang === 'es'
  const expired = new Date(cert.validTo).getTime() < now.getTime()
  return {
    color: expired ? '#f59e0b' : '#22c55e',
    text: expired ? (es ? `Vencido ${cert.validTo}` : `Expired ${cert.validTo}`) : (es ? `Vigente · vence ${cert.validTo}` : `Valid · exp. ${cert.validTo}`),
  }
}

@customElement('attestto-signature-card')
export class AttesttoSignatureCard extends LitElement {
  @property({ attribute: false }) signature!: SignatureCardModel
  @state() private _lang: Lang = currentLang()
  @state() private _revealed = false
  @state() private _dataOpen = false
  @state() private _tab: 'chain' | 'sig' | 'trust' = 'chain'
  @state() private _copied: string | null = null

  private _onLang = () => {
    this._lang = currentLang()
  }
  connectedCallback() {
    super.connectedCallback()
    window.addEventListener('attestto-lang-change', this._onLang)
  }
  disconnectedCallback() {
    window.removeEventListener('attestto-lang-change', this._onLang)
    super.disconnectedCallback()
  }

  private async copy(text: string, tag: string) {
    try {
      await navigator.clipboard.writeText(text)
      this._copied = tag
      setTimeout(() => {
        if (this._copied === tag) this._copied = null
      }, 1200)
    } catch {
      /* clipboard blocked */
    }
  }

  private debugJson(s: SignatureCardModel) {
    return {
      signer: s.signerName,
      status: s.status,
      country: s.country,
      method: s.method,
      subFilter: s.methodTech,
      signedAt: s.signedAt,
      nationalId: s.nationalId?.full ?? null,
      handle: s.handle,
      capabilities: s.capabilities.map((c) => c.label),
      ltv: s.ltv ?? null,
      tech: { ...s.tech, pkcs7Hex: s.tech.pkcs7Hex ? `${s.tech.pkcs7Hex.slice(0, 16)}… (${s.tech.pkcs7Hex.length} chars)` : null },
    }
  }

  static styles = css`
    :host {
      display: block;
      --radius: 16px;
      font-family: system-ui, -apple-system, 'Segoe UI', Roboto, sans-serif;
    }
    .card {
      display: flex;
      gap: 16px;
    }
    .rail {
      display: flex;
      flex-direction: column;
      align-items: center;
      flex-shrink: 0;
      padding-top: 4px;
    }
    .avatar {
      width: 48px;
      height: 48px;
      border-radius: 50%;
      display: flex;
      align-items: center;
      justify-content: center;
      font-weight: 700;
      font-size: 0.9rem;
      color: #e5e7eb;
      background: #1a1d27;
      border: 2px solid var(--status-color, #9ca3af);
    }
    .idx {
      margin-top: 8px;
      width: 22px;
      height: 22px;
      border-radius: 50%;
      border: 1px solid #333a49;
      color: #8b90a0;
      font-size: 0.7rem;
      display: flex;
      align-items: center;
      justify-content: center;
    }
    /* Diagonal gradient to black — professional, not pure white. */
    .body {
      flex: 1;
      min-width: 0;
      background: linear-gradient(135deg, #1b1f2b 0%, #0a0b0f 100%);
      border: 1px solid #2a2f3c;
      border-radius: var(--radius);
      padding: 20px 22px;
      box-shadow: 0 6px 20px rgba(0, 0, 0, 0.25);
    }
    .name-row {
      display: flex;
      align-items: center;
      gap: 10px;
      flex-wrap: wrap;
    }
    .name {
      font-size: 1.05rem;
      font-weight: 700;
      color: #f3f4f6;
    }
    .name-badge {
      display: inline-flex;
      align-items: center;
      gap: 5px;
      font-size: 0.7rem;
      font-weight: 600;
      padding: 3px 9px;
      border-radius: 999px;
      color: var(--status-color);
      background: color-mix(in srgb, var(--status-color) 16%, transparent);
      border: 1px solid color-mix(in srgb, var(--status-color) 40%, transparent);
      white-space: nowrap;
    }
    .name-badge .dot {
      width: 6px;
      height: 6px;
      border-radius: 50%;
      background: var(--status-color);
    }
    .subtitle {
      font-size: 0.82rem;
      color: #9198a8;
      margin: 3px 0 0;
    }
    .head {
      display: flex;
      align-items: flex-start;
      justify-content: space-between;
      gap: 12px;
    }
    /* Official third-party verifier — top-right, squared flag + name + ↗. */
    .official-tr {
      flex-shrink: 0;
      display: inline-flex;
      align-items: center;
      gap: 7px;
      font-size: 0.8rem;
      color: #7aa2ff;
      text-decoration: none;
      padding: 5px 10px;
      border: 1px solid #2b3a5e;
      border-radius: 10px;
      background: #141a2b;
      white-space: nowrap;
    }
    .official-tr:hover {
      background: #1a2136;
    }
    .official-tr .ext {
      opacity: 0.85;
    }
    .flag-sq {
      display: inline-flex;
      align-items: center;
      justify-content: center;
      width: 22px;
      height: 16px;
      border-radius: 4px;
      overflow: hidden;
      font-size: 13px;
      line-height: 1;
      background: #fff;
      border: 1px solid #2a2f3c;
    }
    .desc {
      font-size: 0.85rem;
      line-height: 1.5;
      color: #c3c9d4;
      margin: 12px 0 0;
    }
    hr {
      border: none;
      border-top: 1px solid #232834;
      margin: 16px 0;
    }
    .grid {
      display: grid;
      grid-template-columns: repeat(4, minmax(0, 1fr));
      gap: 18px 24px;
    }
    @media (max-width: 620px) {
      .grid {
        grid-template-columns: repeat(2, minmax(0, 1fr));
      }
    }
    .meta-label {
      display: block;
      font-size: 0.66rem;
      letter-spacing: 0.05em;
      text-transform: uppercase;
      color: #7d8494;
      margin-bottom: 4px;
    }
    .meta-value {
      font-size: 0.84rem;
      color: #e5e7eb;
      word-break: break-word;
    }
    .jur {
      display: inline-flex;
      align-items: center;
    }
    .flag-circle {
      display: inline-flex;
      align-items: center;
      justify-content: center;
      width: 22px;
      height: 22px;
      border-radius: 50%;
      background: #fff;
      border: 1px solid #2a2f3c;
      font-size: 13px;
      line-height: 1;
      margin-right: 7px;
    }
    .id-row {
      display: flex;
      align-items: center;
      gap: 8px;
      flex-wrap: wrap;
    }
    .reveal {
      font-size: 0.72rem;
      color: var(--status-color, #a78bfa);
      background: transparent;
      border: 1px solid currentColor;
      border-radius: 8px;
      padding: 3px 8px;
      cursor: pointer;
    }
    /* Long-term validity — the professional trust signal. */
    .ltv {
      display: flex;
      gap: 10px;
      align-items: flex-start;
      margin-top: 16px;
      padding: 10px 12px;
      border-radius: 10px;
      background: color-mix(in srgb, var(--ltv-color) 10%, transparent);
      border: 1px solid color-mix(in srgb, var(--ltv-color) 28%, transparent);
    }
    .ltv .ico {
      color: var(--ltv-color);
      font-weight: 700;
    }
    .ltv .l1 {
      font-size: 0.82rem;
      font-weight: 600;
      color: var(--ltv-color);
    }
    .ltv .l2 {
      font-size: 0.76rem;
      color: #aeb4c0;
      margin-top: 1px;
    }
    .caps {
      display: flex;
      flex-wrap: wrap;
      gap: 6px;
      margin-top: 4px;
    }
    .cap {
      display: inline-flex;
      align-items: center;
      gap: 6px;
      font-size: 0.75rem;
      padding: 4px 10px 4px 8px;
      border-radius: 999px;
      background: #20242f;
      color: #d4d9e2;
      border: 1px solid #313745;
    }
    .cap-ico {
      filter: grayscale(1) opacity(0.85);
      font-size: 0.82rem;
      line-height: 1;
    }
    /* Reusable tooltip — any pill with [data-tip] gets the same styled hover. */
    .cap[data-tip] {
      position: relative;
      cursor: help;
    }
    .cap[data-tip]:hover::after {
      content: attr(data-tip);
      position: absolute;
      bottom: calc(100% + 8px);
      left: 50%;
      transform: translateX(-50%);
      width: max-content;
      max-width: 240px;
      background: #05060a;
      color: #e5e7eb;
      border: 1px solid #2a2f3c;
      border-radius: 8px;
      padding: 8px 10px;
      font-size: 0.72rem;
      line-height: 1.4;
      white-space: normal;
      text-align: left;
      z-index: 20;
      box-shadow: 0 8px 24px rgba(0, 0, 0, 0.5);
      pointer-events: none;
    }
    .cap[data-tip]:hover::before {
      content: '';
      position: absolute;
      bottom: calc(100% + 3px);
      left: 50%;
      transform: translateX(-50%);
      border: 5px solid transparent;
      border-top-color: #2a2f3c;
      z-index: 20;
    }
    .seal {
      margin-top: 4px;
      max-height: 90px;
      max-width: 240px;
      border-radius: 8px;
      background: #fff;
      padding: 6px;
      object-fit: contain;
    }
    .cap-link {
      color: #7aa2ff;
      background: #141a2b;
      border-color: #2b3a5e;
      text-decoration: none;
      cursor: pointer;
    }
    .cap-link:hover {
      background: #1a2136;
    }
    .cap-link .ext {
      margin-left: 5px;
      opacity: 0.85;
    }
    .footer {
      display: flex;
      justify-content: flex-end;
      margin-top: 14px;
    }
    .see-data {
      background: transparent;
      border: none;
      color: #7d8494;
      font-size: 0.75rem;
      cursor: pointer;
      font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
      padding: 4px 6px;
    }
    .see-data:hover {
      color: #c3c9d4;
    }
    /* ── Dev internals: dark, tabbed, grayscale icons ── */
    .internals {
      margin-top: 12px;
      background: #06070a;
      border: 1px solid #1c2029;
      border-radius: 12px;
      overflow: hidden;
    }
    .tabs {
      display: flex;
      gap: 2px;
      background: #0c0e13;
      border-bottom: 1px solid #1c2029;
      padding: 6px 6px 0;
    }
    .tab {
      background: transparent;
      border: none;
      color: #7d8494;
      font-size: 0.76rem;
      padding: 8px 14px;
      cursor: pointer;
      border-bottom: 2px solid transparent;
    }
    .tab.active {
      color: #e5e7eb;
      border-bottom-color: #5b6472;
    }
    .pane {
      padding: 14px 16px;
    }
    .chain-node {
      font-size: 0.75rem;
      color: #aeb4c0;
      padding: 3px 0;
      white-space: nowrap;
      overflow: hidden;
      text-overflow: ellipsis;
    }
    .chain-node .ico {
      filter: grayscale(1) opacity(0.85);
      margin-right: 6px;
    }
    .chain-node.leaf {
      color: #f3f4f6;
      font-weight: 600;
    }
    .chain-node .sub {
      color: #6b7280;
      font-weight: 400;
      font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
      font-size: 0.7rem;
    }
    .kv {
      display: grid;
      grid-template-columns: max-content 1fr;
      gap: 4px 18px;
      font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
      font-size: 0.73rem;
    }
    .kv .k {
      color: #6b7280;
    }
    .kv .v {
      color: #cbd0d8;
      word-break: break-all;
    }
    .copy-row {
      display: flex;
      gap: 8px;
      margin-top: 14px;
      flex-wrap: wrap;
    }
    .copy-btn {
      font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
      font-size: 0.72rem;
      padding: 5px 10px;
      border-radius: 8px;
      border: 1px solid #2a2f3c;
      background: #12151c;
      color: #aeb4c0;
      cursor: pointer;
    }
    .copy-btn:hover {
      background: #1a1e27;
      color: #e5e7eb;
    }
    .trust-intro {
      font-size: 0.76rem;
      color: #8b90a0;
      margin: 0 0 12px;
      line-height: 1.5;
    }
    .trust-links {
      display: flex;
      flex-direction: column;
      gap: 9px;
    }
    .trust-link {
      font-size: 0.78rem;
      color: #7aa2ff;
      text-decoration: none;
    }
    .trust-link:hover {
      text-decoration: underline;
    }
  `

  render() {
    const s = this.signature
    if (!s) return html``
    const color = STATUS_COLOR[s.status]
    const st = STATUS_TEXT[this._lang][s.status]
    const initials = s.initials || initialsFor(s.signerName)
    const ltv = ltvFace(s.ltv, s.status, this._lang)
    const cf = certFace(s.cert, this._lang, new Date())
    const unknownDate = this._lang === 'es' ? 'Desconocido' : 'Unknown'

    return html`
      <div class="card" part="card" style="--status-color:${color}">
        <div class="rail">
          <div class="avatar" part="avatar"><span>${initials}</span></div>
          <div class="idx">${s.index}</div>
        </div>

        <div class="body">
          <div class="head">
            <div>
              <div class="name-row">
                <span class="name" part="name">${s.signerName}</span>
                <span class="name-badge" part="status"><span class="dot"></span>${st.label}</span>
              </div>
              <p class="subtitle">${s.subtitle}</p>
            </div>
            ${s.officialVerifier
              ? html`<a
                  class="official-tr"
                  part="official-link"
                  href=${s.officialVerifier.url}
                  target="_blank"
                  rel="noopener noreferrer"
                  title=${t('comp.verify.verifyOfficial')}
                  >${s.country ? html`<span class="flag-sq">${flagEmoji(s.country)}</span>` : ''}${s.officialVerifier.name}<span
                    class="ext"
                    >↗</span
                  ></a
                >`
              : ''}
          </div>

          <p class="desc">${st.desc}</p>
          <hr />

          <div class="grid">
            <div>
              <span class="meta-label">${t('comp.verify.jurisdiction')}</span>
              <span class="meta-value jur"
                >${s.country ? html`<span class="flag-circle" part="flag">${flagEmoji(s.country)}</span>` : ''}${s.jurisdiction || '—'}</span
              >
            </div>
            <div>
              <span class="meta-label">${t('comp.verify.signed')}</span>
              <span class="meta-value">${s.signedAt || unknownDate}</span>
            </div>
            <div>
              <span class="meta-label">${t('comp.verify.certificate')}</span>
              ${cf
                ? html`<span class="meta-value" style="color:${cf.color}">${cf.text}</span>`
                : html`<span class="meta-value">—</span>`}
            </div>
            <div>
              <span class="meta-label">${t('comp.verify.nationalId')}</span>
              ${this.renderId(s)}
            </div>
          </div>

          ${ltv
            ? html`<div class="ltv" part="ltv" style="--ltv-color:${LTV_TONE_COLOR[ltv.tone]}">
                <span class="ico">◷</span>
                <div>
                  <div class="l1">${ltv.label}</div>
                  <div class="l2">${ltv.detail}</div>
                </div>
              </div>`
            : ''}
          ${s.capabilities.length
            ? html`<div style="margin-top:16px">
                <span class="meta-label">${t('comp.verify.capabilities')}</span>
                <div class="caps" part="capabilities">
                  ${s.capabilities.map(
                    (c) =>
                      html`<span class="cap" part="capability" data-tip=${capTooltip(c.label, c.kind, this._lang)}
                        ><span class="cap-ico">${capIcon(c.label)}</span>${c.label}</span
                      >`,
                  )}
                </div>
              </div>`
            : ''}
          ${s.signatureImage
            ? html`<div style="margin-top:16px">
                <span class="meta-label">${t('comp.verify.trustPermissions')}</span>
                <img class="seal" src=${s.signatureImage} alt="signature" />
              </div>`
            : ''}

          <div class="footer">
            <button class="see-data" @click=${() => (this._dataOpen = !this._dataOpen)}>
              ${this._dataOpen ? '▾' : '⌗'} ${this._lang === 'es' ? 'Datos avanzados' : 'Advanced data'}
            </button>
          </div>
          ${this._dataOpen ? this.renderInternals(s) : ''}
        </div>
      </div>
    `
  }

  private renderId(s: SignatureCardModel) {
    if (!s.nationalId) {
      return html`<span class="meta-value">${s.handle || '—'}</span>`
    }
    return html`<div class="id-row">
      <span class="meta-value">${this._revealed ? s.nationalId.full : s.nationalId.masked}</span>
      ${this._revealed
        ? ''
        : html`<button class="reveal" @click=${() => (this._revealed = true)}>${t('comp.verify.reveal')}</button>`}
    </div>`
  }

  private renderInternals(s: SignatureCardModel) {
    const chain = s.tech.chain ?? []
    const es = this._lang === 'es'
    return html`
      <div class="internals" part="internals">
        <div class="tabs">
          <button class="tab ${this._tab === 'chain' ? 'active' : ''}" @click=${() => (this._tab = 'chain')}>
            ${t('comp.verify.certChain')}
          </button>
          <button class="tab ${this._tab === 'sig' ? 'active' : ''}" @click=${() => (this._tab = 'sig')}>
            ${es ? 'Firma' : 'Signature'}
          </button>
          <button class="tab ${this._tab === 'trust' ? 'active' : ''}" @click=${() => (this._tab = 'trust')}>
            ${es ? 'Confianza' : 'Trust'}
          </button>
        </div>
        <div class="pane">
          ${this._tab === 'chain'
            ? this.renderChain(chain)
            : this._tab === 'sig'
              ? this.renderSigTab(s)
              : this.renderTrust(s)}
        </div>
      </div>
    `
  }

  private renderChain(chain: NonNullable<SignatureCardModel['tech']['chain']>) {
    if (!chain.length) return html`<span class="kv"><span class="k">no chain</span></span>`
    const last = chain.length - 1
    return html`${chain.map(
      (c, i) => html`<div class="chain-node ${i === last ? 'leaf' : ''}" style="padding-left:${i * 14}px" title=${c.name}>
        <span class="ico">${chainIcon(i, last)}</span>${c.name}<span class="sub">
          ${c.issuer ? ` · ${c.issuer}` : ''}${c.from ? ` · ${c.from}–${c.to}` : ''}${c.country ? ` · ${c.country}` : ''}</span
        >
      </div>`,
    )}`
  }

  private renderSigTab(s: SignatureCardModel) {
    const kv: Array<[string, string]> = []
    if (s.method) kv.push(['method', s.method])
    if (s.tech.standard) kv.push(['standard', s.tech.standard])
    if (s.cert?.validFrom || s.cert?.validTo) kv.push(['cert valid', `${s.cert?.validFrom ?? '?'} – ${s.cert?.validTo ?? '?'}`])
    if (s.tech.digestAlgorithm) kv.push(['digest', s.tech.digestAlgorithm])
    if (s.tech.byteRange) kv.push(['byte range', `[${s.tech.byteRange.join(', ')}]`])
    if (s.tech.pkcs7Size) kv.push(['PKCS#7 size', `${s.tech.pkcs7Size} bytes`])
    if (s.tech.keyId) kv.push(['key id', s.tech.keyId])
    if (s.handle) kv.push(['handle', s.handle])
    if (s.tech.location) kv.push(['location', s.tech.location])
    if (s.ltv) {
      kv.push(['LTV tier', s.ltv.tier])
      kv.push(['timestamp', s.ltv.hasTimestamp ? `${s.ltv.timestampAt ?? 'yes'}${s.ltv.timestampAuthority ? ` · ${s.ltv.timestampAuthority}` : ''}` : 'none'])
      kv.push(['revocation', s.ltv.revocationSource])
    }
    return html`
      <div class="kv">${kv.map(([k, v]) => html`<span class="k">${k}</span><span class="v">${v}</span>`)}</div>
      <div class="copy-row">
        ${s.tech.pkcs7Hex
          ? html`<button class="copy-btn" @click=${() => this.copy(s.tech.pkcs7Hex!, 'pkcs7')}>
              ${this._copied === 'pkcs7' ? '✓ copied' : '⧉ Copy PKCS#7'}
            </button>`
          : ''}
        <button class="copy-btn" @click=${() => this.copy(JSON.stringify(this.debugJson(s), null, 2), 'json')}>
          ${this._copied === 'json' ? '✓ copied' : '⧉ Copy details (JSON)'}
        </button>
      </div>
    `
  }

  private renderTrust(s: SignatureCardModel) {
    const es = this._lang === 'es'
    // Signature-specific provenance (did:pki resolver, OCSP…) from the mapper,
    // plus the canonical Attestto trust registry + anchors repo.
    const links = [
      ...(s.trustLinks ?? []),
      {
        label: es ? 'Anclas de confianza (repositorio)' : 'Trust anchors (repository)',
        url: 'https://github.com/Attestto-com/attestto-trust',
      },
      { label: es ? 'Resolver de confianza' : 'Trust resolver', url: 'https://resolver.attestto.com' },
    ]
    return html`
      <p class="trust-intro">
        ${es
          ? 'Verifica de forma independiente el origen de las raíces de confianza usadas para validar esta firma.'
          : 'Independently check where the trust roots used to validate this signature come from.'}
      </p>
      <div class="trust-links">
        ${links.map(
          (l) => html`<a class="trust-link" href=${l.url} target="_blank" rel="noopener noreferrer">↗ ${l.label}</a>`,
        )}
      </div>
    `
  }
}

declare global {
  interface HTMLElementTagNameMap {
    'attestto-signature-card': AttesttoSignatureCard
  }
}

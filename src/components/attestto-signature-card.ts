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
import type {
  SignatureCardModel,
  SignatureStatus,
  SignatureLtv,
  SignatureTrustMark,
} from '../model/signature-card.js'
import { initialsFor } from '../model/signature-card.js'

const MARK_COLOR: Record<SignatureTrustMark['scheme'], string> = {
  qualified: '#3b82f6', // EU blue
  'trusted-list': '#2563eb',
  'cr-firma': '#16a34a',
  attestto: '#a78bfa',
  untrusted: '#9ca3af',
  other: '#9ca3af',
}

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
      desc: 'Se analizó la estructura de la firma, pero su cadena no enlaza con ninguna raíz de confianza (podría ser falsificada, autofirmada o de una CA no confiable).',
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
    // No CA and no TSA here, so the ONLY honest "anchored in time" claim is a
    // verifiable on-chain anchor. When one exists, the ledger's block time proves
    // the signature existed before T. Without it, the signing date is the
    // signer's own asserted clock — the signature is bound to content + KYC, but
    // NOT anchored in time. Deriving from `ltv.anchor` keeps the badge honest.
    if (ltv?.anchor) {
      const at = ltv.anchor.anchoredAt ? ` · ${ltv.anchor.anchoredAt}` : ''
      return {
        tone: 'good',
        label: es ? 'Anclada en el tiempo' : 'Point-in-time anchored',
        detail:
          (es
            ? `Anclada en ${ltv.anchor.network}: su existencia antes de esa fecha es verificable en cadena, sin depender de ninguna CA.`
            : `Anchored on ${ltv.anchor.network}: existence before that time is verifiable on-chain, independent of any CA.`) +
          at,
      }
    }
    return {
      tone: 'neutral',
      label: es ? 'Vinculada al contenido y KYC' : 'Bound to content + KYC',
      detail: es
        ? 'Prueba propiedad de la bóveda del firmante y que el contenido no cambió, pero la fecha es la declarada por el firmante — sin anclaje de tiempo verificable.'
        : 'Proves the signer’s vault ownership and that the content is unchanged, but the date is the signer’s own — no verifiable time anchor.',
    }
  }
  if (!ltv || ltv.tier === 'none' || ltv.tier === 'B') {
    return {
      tone: 'warn',
      label: es ? 'Sin validez a largo plazo' : 'No long-term validation',
      detail: es
        ? 'La firma no incluye su propia prueba de revocación, así que volver a verificarla más adelante depende de que el servicio de revocación del emisor siga en línea.'
        : 'The signature does not embed its own revocation proof, so re-verifying it later depends on the issuer’s revocation service staying online.',
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

/**
 * Format any user-facing date as a clean, locale-short, date-only string
 * (no time, no trailing Z), e.g. "11 mar 2028" (es) / "Mar 11, 2028" (en).
 * Returns null when the value is not a parseable date (e.g. a raw serial/DN
 * reference), so callers can decide to hide it rather than print garbage.
 */
function fmtDate(value: string | null | undefined, lang: Lang): string | null {
  if (!value) return null
  const d = new Date(value)
  if (isNaN(d.getTime())) return null
  return d.toLocaleDateString(lang === 'es' ? 'es-ES' : 'en-US', {
    year: 'numeric',
    month: 'short',
    day: 'numeric',
  })
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
  const when = fmtDate(cert.validTo, lang) ?? cert.validTo
  return {
    color: expired ? '#f59e0b' : '#22c55e',
    text: expired
      ? es
        ? `Vencido ${when}`
        : `Expired ${when}`
      : es
        ? `Vigente, vence ${when}`
        : `Valid, exp. ${when}`,
  }
}

@customElement('attestto-signature-card')
export class AttesttoSignatureCard extends LitElement {
  @property({ attribute: false }) signature!: SignatureCardModel
  /** When false, the national-ID match check is not offered — masked, no interaction. */
  @property({ type: Boolean, attribute: 'allow-id-check' }) allowIdCheck = true
  @state() private _lang: Lang = currentLang()
  @state() private _dataOpen = false
  @state() private _idOpen = false
  @state() private _idInput = ''
  @state() private _idResult: 'idle' | 'match' | 'nomatch' = 'idle'

  // Confirm-not-disclose: the verifier types the ID they already hold; we answer
  // match / no-match and NEVER display the full value. Someone who doesn't
  // already know the ID can't harvest it from a document they merely possess.
  private checkId(index: number, full: string) {
    const norm = (x: string) => x.replace(/[^0-9a-z]/gi, '').toLowerCase()
    const match = norm(this._idInput).length > 0 && norm(this._idInput) === norm(full)
    this._idResult = match ? 'match' : 'nomatch'
    if (match) {
      this.dispatchEvent(
        new CustomEvent('id-confirmed', { detail: { index }, bubbles: true, composed: true }),
      )
    }
  }
  @state() private _tab: 'chain' | 'sig' | 'trust' = 'chain'
  @state() private _copied: string | null = null
  /** Opt-in online revocation: whether the pre-check warning is expanded. */
  @state() private _onlineRevOpen = false

  /**
   * Ask the host to run a LIVE OCSP check for this signature. Strictly opt-in:
   * this only fires from the user's explicit "Confirm and check" click. The
   * host (attestto-verify.ts) owns the raw certs and performs the fetch, then
   * feeds the result back through the model so this card re-renders.
   */
  private requestOnlineRevocation(index: number) {
    this._onlineRevOpen = false
    this.dispatchEvent(
      new CustomEvent('request-online-revocation', {
        detail: { index },
        bubbles: true,
        composed: true,
      }),
    )
  }

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
      // Never export raw PII: the tool never displays the full national ID
      // (renderId only confirms it), and the handle may embed the cédula.
      nationalId: s.nationalId?.masked ?? null,
      handle: s.handle ? this.maskHandle(s.handle) : null,
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
    .signals {
      display: flex;
      flex-wrap: wrap;
      gap: 8px;
      margin-top: 14px;
    }
    .tmark {
      display: inline-flex;
      align-items: center;
      gap: 6px;
      font-size: 0.75rem;
      font-weight: 600;
      padding: 4px 10px;
      border-radius: 8px;
      color: var(--m);
      background: color-mix(in srgb, var(--m) 14%, transparent);
      border: 1px solid color-mix(in srgb, var(--m) 34%, transparent);
    }
    .tmark-ico {
      font-size: 0.82rem;
      filter: grayscale(0.2);
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
    .id-col {
      display: flex;
      flex-direction: column;
      gap: 6px;
    }
    .id-badge {
      font-size: 0.72rem;
      font-weight: 600;
      padding: 2px 8px;
      border-radius: 999px;
    }
    .id-match {
      color: #22c55e;
      background: rgba(34, 197, 94, 0.12);
      border: 1px solid rgba(34, 197, 94, 0.35);
    }
    .id-nomatch {
      color: #ef4444;
      background: rgba(239, 68, 68, 0.12);
      border: 1px solid rgba(239, 68, 68, 0.35);
    }
    .id-check {
      display: flex;
      flex-direction: column;
      gap: 7px;
      padding: 8px 10px;
      border-radius: 8px;
      background: #0e1420;
      border: 1px solid #22314a;
    }
    .rc-note {
      font-size: 0.7rem;
      color: #9db4d8;
      line-height: 1.4;
    }
    .id-check-row {
      display: flex;
      gap: 6px;
    }
    .id-input {
      flex: 1;
      min-width: 0;
      background: #05070c;
      border: 1px solid #2a3550;
      border-radius: 7px;
      padding: 5px 8px;
      color: #e5e7eb;
      font-size: 0.78rem;
      font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
    }
    .id-input:focus {
      outline: none;
      border-color: #3b5aa8;
    }
    .rc-yes {
      font-size: 0.72rem;
      padding: 5px 12px;
      border-radius: 7px;
      cursor: pointer;
      color: #e5e7eb;
      background: #1c2740;
      border: 1px solid #2f4066;
    }
    .rc-yes:hover {
      background: #24304d;
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
    /* Reusable tooltip — any pill with .has-tip[data-tip] gets the same hover.
       Anchored to the pill's LEFT edge (grows right) so left-edge pills don't
       clip; the last pill in a row anchors right (grows left). */
    .has-tip[data-tip] {
      position: relative;
      cursor: help;
    }
    .has-tip[data-tip]:hover::after {
      content: attr(data-tip);
      position: absolute;
      bottom: calc(100% + 8px);
      left: 0;
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
    .has-tip[data-tip]:hover::before {
      content: '';
      position: absolute;
      bottom: calc(100% + 3px);
      left: 14px;
      border: 5px solid transparent;
      border-top-color: #2a2f3c;
      z-index: 20;
    }
    /* Last pill in a row grows leftward so it can't clip off the right edge. */
    .caps .has-tip:last-child[data-tip]:hover::after,
    .signals .has-tip:last-child[data-tip]:hover::after {
      left: auto;
      right: 0;
    }
    .caps .has-tip:last-child[data-tip]:hover::before,
    .signals .has-tip:last-child[data-tip]:hover::before {
      left: auto;
      right: 14px;
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
      /* overflow visible (not hidden) so row tooltips can escape the panel
         bounds; no child paints into the rounded corners, so the frame is safe. */
    }
    .internals-desc {
      font-size: 0.8rem;
      line-height: 1.5;
      color: #aeb4c0;
      margin: 0;
      padding: 12px 14px;
      border-bottom: 1px solid #1c2029;
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
    .chain-node .src {
      display: inline-block;
      margin-left: 6px;
      padding: 0 5px;
      border-radius: 3px;
      font-size: 0.62rem;
      font-weight: 500;
      line-height: 1.5;
      color: #9aa3b2;
      background: rgba(255, 255, 255, 0.06);
      border: 1px solid rgba(255, 255, 255, 0.08);
      vertical-align: middle;
    }
    .kv {
      display: grid;
      grid-template-columns: max-content 1fr;
      gap: 4px 18px;
      font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
      font-size: 0.73rem;
    }
    .kv .k {
      color: #8b93a4;
    }
    .kv .hint {
      position: relative;
      display: inline-flex;
      align-items: center;
      justify-content: center;
      width: 14px;
      height: 14px;
      margin-left: 6px;
      border: 1px solid #3a4150;
      border-radius: 50%;
      font-size: 9px;
      line-height: 1;
      color: #aeb4c0;
      cursor: help;
      vertical-align: middle;
      user-select: none;
    }
    .kv .hint:hover,
    .kv .hint:focus {
      color: #ffffff;
      border-color: #5b6472;
      background: #1a1e27;
      outline: none;
    }
    .kv .hint .tip {
      position: absolute;
      left: 0;
      bottom: calc(100% + 8px);
      width: max-content;
      max-width: 280px;
      padding: 8px 11px;
      background: #1b1f2a;
      border: 1px solid #333a48;
      border-radius: 8px;
      color: #e8eaef;
      font-family: system-ui, -apple-system, 'Segoe UI', Roboto, sans-serif;
      font-size: 0.72rem;
      font-weight: 400;
      line-height: 1.45;
      text-align: left;
      white-space: normal;
      opacity: 0;
      visibility: hidden;
      transform: translateY(3px);
      transition:
        opacity 0.12s ease,
        transform 0.12s ease;
      z-index: 50;
      pointer-events: none;
      box-shadow: 0 8px 24px rgba(0, 0, 0, 0.55);
    }
    .kv .hint:hover .tip,
    .kv .hint:focus .tip {
      opacity: 1;
      visibility: visible;
      transform: translateY(0);
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
    /* ── Opt-in online revocation ── */
    .online-rev {
      margin-top: 12px;
      display: flex;
      flex-direction: column;
      gap: 8px;
    }
    .online-rev-btn {
      align-self: flex-start;
      display: inline-flex;
      align-items: center;
      gap: 6px;
      font-size: 0.74rem;
      color: #9db4d8;
      background: #0e1420;
      border: 1px solid #22314a;
      border-radius: 8px;
      padding: 5px 11px;
      cursor: pointer;
    }
    .online-rev-btn:hover {
      background: #141c2c;
      color: #cdd9ea;
    }
    .online-rev-warn {
      display: flex;
      flex-direction: column;
      gap: 9px;
      padding: 10px 12px;
      border-radius: 8px;
      background: #0e1420;
      border: 1px solid #22314a;
    }
    .online-rev-warn .rc-note {
      color: #d9b48a;
    }
    .online-rev-actions {
      display: flex;
      gap: 8px;
      flex-wrap: wrap;
    }
    .online-rev-go {
      font-size: 0.72rem;
      padding: 5px 12px;
      border-radius: 7px;
      cursor: pointer;
      color: #e5e7eb;
      background: #1c2740;
      border: 1px solid #2f4066;
    }
    .online-rev-go:hover {
      background: #24304d;
    }
    .online-rev-cancel {
      font-size: 0.72rem;
      padding: 5px 12px;
      border-radius: 7px;
      cursor: pointer;
      color: #9198a8;
      background: transparent;
      border: 1px solid #313745;
    }
    .online-rev-result {
      display: inline-flex;
      align-items: center;
      gap: 7px;
      font-size: 0.75rem;
      line-height: 1.4;
      padding: 7px 11px;
      border-radius: 8px;
      color: var(--rev, #93c5fd);
      background: color-mix(in srgb, var(--rev, #93c5fd) 12%, transparent);
      border: 1px solid color-mix(in srgb, var(--rev, #93c5fd) 34%, transparent);
    }
    .online-rev-checking {
      font-size: 0.74rem;
      color: #9198a8;
      display: inline-flex;
      align-items: center;
      gap: 7px;
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
    // Only show a clean human date on the main face. A raw serial/DN/reference
    // (unparseable) is relocated to the advanced "Firma" tab, never shown here.
    const signedDisplay = fmtDate(s.signedAt, this._lang)

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

          ${s.trustMarks?.length || ltv
            ? html`<div class="signals" part="signals">
                ${(s.trustMarks ?? []).map(
                  (m) =>
                    html`<span class="tmark" style="--m:${MARK_COLOR[m.scheme]}"
                      ><span class="tmark-ico">🛡</span>${m.label}</span
                    >`,
                )}
                ${ltv
                  ? html`<span
                      class="tmark has-tip"
                      part="ltv"
                      data-tip=${ltv.detail}
                      style="--m:${LTV_TONE_COLOR[ltv.tone]}"
                      ><span class="tmark-ico">◷</span>${ltv.label}</span
                    >`
                  : ''}
              </div>`
            : ''}
          ${this.renderOnlineRevocation(s)}
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
              <span class="meta-value">${signedDisplay || unknownDate}</span>
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

          ${s.capabilities.length
            ? html`<div style="margin-top:16px">
                <span class="meta-label">${t('comp.verify.capabilities')}</span>
                <div class="caps" part="capabilities">
                  ${s.capabilities.map(
                    (c) =>
                      html`<span class="cap has-tip" part="capability" data-tip=${capTooltip(c.label, c.kind, this._lang)}
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

  /**
   * OPT-IN online revocation. OFF by default: shows a small button only when an
   * OCSP responder URL is available. Clicking reveals a plain-language warning
   * that a network request will leave the device; the check runs only after the
   * user confirms. Nothing here fires automatically.
   */
  private renderOnlineRevocation(s: SignatureCardModel) {
    const rev = s.onlineRevocation
    if (!rev || !rev.available) return ''
    const es = this._lang === 'es'
    const D = (en: string, str: string) => (es ? str : en)

    if (rev.checking) {
      return html`<div class="online-rev" part="online-revocation">
        <span class="online-rev-checking"
          >◷ ${D('Checking revocation online…', 'Revisando revocación en línea…')}</span
        >
      </div>`
    }

    if (rev.result) {
      const r = rev.result
      const color =
        r.status === 'good' ? '#22c55e' : r.status === 'revoked' ? '#ef4444' : '#93c5fd'
      const icon =
        r.status === 'good' ? '✓' : r.status === 'revoked' ? '✗' : r.status === 'unknown' ? '?' : '⚠'
      const heading =
        r.status === 'good'
          ? D('Not revoked', 'No revocado')
          : r.status === 'revoked'
            ? D('Revoked', 'Revocado')
            : r.status === 'unknown'
              ? D('Unknown', 'Desconocido')
              : D('Responder unreachable', 'Servicio no disponible')
      const when = fmtDate(r.checkedAt, this._lang)
      return html`<div class="online-rev" part="online-revocation">
        <span class="online-rev-result" style="--rev:${color}"
          >${icon} <strong>${heading}.</strong> ${r.message}${when
            ? html` <span style="opacity:0.7"
                >${D('Checked', 'Revisado')} ${when}</span
              >`
            : ''}</span
        >
      </div>`
    }

    if (!this._onlineRevOpen) {
      return html`<div class="online-rev" part="online-revocation">
        <button class="online-rev-btn" @click=${() => (this._onlineRevOpen = true)}>
          🌐 ${D('Check revocation online', 'Revisar revocación en línea')}
        </button>
      </div>`
    }

    return html`<div class="online-rev" part="online-revocation">
      <div class="online-rev-warn">
        <span class="rc-note"
          >⚠ ${D(
            'This sends the certificate serial to the issuer’s revocation server. It leaves your device.',
            'Esto envía el número de serie del certificado al servidor de revocación del emisor. Sale de tu dispositivo.',
          )}</span
        >
        <div class="online-rev-actions">
          <button class="online-rev-go" @click=${() => this.requestOnlineRevocation(s.index)}>
            ${D('Confirm and check', 'Confirmar y revisar')}
          </button>
          <button class="online-rev-cancel" @click=${() => (this._onlineRevOpen = false)}>
            ${D('Cancel', 'Cancelar')}
          </button>
        </div>
      </div>
    </div>`
  }

  /**
   * Mask long digit runs inside a handle so an identifier that embeds a national
   * ID (e.g. `cr-111290877.attestto.id`) does not broadcast the number on every
   * verification. Keeps the first and last two digits for recognizability. The
   * full handle stays available under "advanced details" behind an explicit
   * expand. This is a display-side defense; the real fix is the signer minting a
   * handle without PII (see public-identifier-no-pii design).
   */
  private maskHandle(handle: string): string {
    return handle.replace(/\d{6,}/g, (run) => run.slice(0, 2) + '•'.repeat(run.length - 4) + run.slice(-2))
  }

  /**
   * Plain-language definition for a technical Firma-tab row label, so a `?`
   * marker can explain the jargon on hover. Returns null for self-evident rows.
   */
  private techHint(label: string): string | null {
    const es = this._lang === 'es'
    // [es, en] per label key.
    const g: Record<string, [string, string]> = {
      signed: [
        'Fecha y hora de firma declaradas por el firmante. No prueban el momento real salvo que exista un sello de tiempo.',
        'Signing date and time as declared by the signer. Not proof of the actual moment unless a timestamp is present.',
      ],
      commitment: [
        'Motivo o compromiso declarado de la firma (por ejemplo aprobación o autoría).',
        'The declared reason or commitment of the signature (for example approval or authorship).',
      ],
      method: [
        'Mecanismo técnico de la firma: el subtipo del PDF (/SubFilter) o el esquema Attestto.',
        "The signature's technical mechanism: the PDF /SubFilter or the Attestto scheme.",
      ],
      standard: [
        'Norma que implementa la firma (por ejemplo PAdES para PDF, o PKCS#7).',
        'The standard the signature implements (for example PAdES for PDF, or PKCS#7).',
      ],
      'key id': [
        'Identificador de la clave pública del firmante (por ejemplo un did:key). No contiene datos personales.',
        "Identifier of the signer's public key (for example a did:key). Contains no personal data.",
      ],
      handle: [
        'Identificador legible del firmante. Se enmascara si incluye un dato personal como la cédula.',
        'Human-readable identifier of the signer. Masked when it embeds personal data such as a national ID.',
      ],
      location: [
        'Lugar de firma declarado por el firmante. Es autoafirmado y no se verifica.',
        'Signing location declared by the signer. Self-asserted and not verified.',
      ],
      'cert valid': [
        'Periodo de validez del certificado del firmante (desde y hasta).',
        "Validity period of the signer's certificate (from and to).",
      ],
      digest: [
        'Algoritmo de hash usado al calcular la firma.',
        'Hash algorithm used when computing the signature.',
      ],
      'byte range': [
        'Rango de bytes del documento que cubre la firma. Un cambio fuera de ese rango la invalida.',
        'Byte range of the document covered by the signature. A change outside it breaks the signature.',
      ],
      'PKCS#7 size': [
        'Tamaño del contenedor criptográfico (PKCS#7/CMS) que envuelve la firma.',
        'Size of the cryptographic container (PKCS#7/CMS) that wraps the signature.',
      ],
      'LTV tier': [
        'Nivel de validación a largo plazo: evidencia embebida para poder verificar años después.',
        'Long-term validation tier: embedded evidence so the signature can be verified years later.',
      ],
      timestamp: [
        'Sello de tiempo de confianza que prueba cuándo existió la firma.',
        'Trusted timestamp proving when the signature existed.',
      ],
      revocation: [
        'Origen de la evidencia de revocación (OCSP/CRL) que se consultó.',
        'Source of the revocation evidence (OCSP/CRL) that was checked.',
      ],
    }
    const entry = g[label]
    if (entry) return es ? entry[0] : entry[1]
    // The raw-reference fallback labels mean the same as "signed".
    if (label.startsWith('firma (ref') || label.startsWith('signed (raw'))
      return es ? g.signed[0] : g.signed[1]
    return null
  }

  private renderId(s: SignatureCardModel) {
    const es = this._lang === 'es'
    if (!s.nationalId) {
      return html`<span class="meta-value">${s.handle ? this.maskHandle(s.handle) : '—'}</span>`
    }
    // Masked always. The user CONFIRMS by typing what they already know; the
    // full value is never displayed by the tool.
    const badge =
      this._idResult === 'match'
        ? html`<span class="id-badge id-match">✓ ${es ? 'Coincide' : 'Matches'}</span>`
        : this._idResult === 'nomatch'
          ? html`<span class="id-badge id-nomatch">✗ ${es ? 'No coincide' : 'No match'}</span>`
          : ''
    const showCheckBtn = this.allowIdCheck && this._idResult !== 'match' && !this._idOpen
    return html`<div class="id-col">
      <div class="id-row">
        <span class="meta-value" part="national-id">${s.nationalId.masked}</span>
        ${badge}
        ${showCheckBtn
          ? html`<button class="reveal" @click=${() => (this._idOpen = true)}>${es ? 'Comprobar' : 'Check'}</button>`
          : ''}
      </div>
      ${this.allowIdCheck && this._idOpen && this._idResult !== 'match'
        ? html`<div class="id-check" part="id-check">
            <span class="rc-note"
              >🔒 ${es
                ? 'Escribe la identificación que ya conoces para confirmar. Nunca mostramos el dato completo.'
                : 'Type the ID you already know to confirm. We never display the full value.'}</span
            >
            <div class="id-check-row">
              <input
                class="id-input"
                .value=${this._idInput}
                @input=${(e: Event) => (this._idInput = (e.target as HTMLInputElement).value)}
                @keydown=${(e: KeyboardEvent) => {
                  if (e.key === 'Enter') this.checkId(s.index, s.nationalId!.full)
                }}
                placeholder=${s.nationalId.masked}
              />
              <button class="rc-yes" @click=${() => this.checkId(s.index, s.nationalId!.full)}>
                ${es ? 'Comprobar' : 'Check'}
              </button>
            </div>
          </div>`
        : ''}
    </div>`
  }

  private renderInternals(s: SignatureCardModel) {
    const chain = s.tech.chain ?? []
    const es = this._lang === 'es'
    const desc = STATUS_TEXT[this._lang][s.status].desc
    return html`
      <div class="internals" part="internals">
        <p class="internals-desc">${desc}</p>
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
    const es = this._lang === 'es'
    const trustStoreLabel = es ? 'del trust store' : 'from trust store'
    return html`${chain.map((c, i) => {
      const from = fmtDate(c.from, this._lang) ?? c.from
      const to = fmtDate(c.to, this._lang) ?? c.to
      const range = c.from ? ` · ${from}–${to}` : ''
      // Provenance badge: only on certs the trust store supplied (not embedded
      // in the PDF), so the display stays honest without cluttering every row.
      const srcBadge =
        c.source === 'trust-store'
          ? html`<span class="src" title=${trustStoreLabel}>${trustStoreLabel}</span>`
          : ''
      return html`<div class="chain-node ${i === last ? 'leaf' : ''}" style="padding-left:${i * 14}px" title=${c.name}>
        <span class="ico">${chainIcon(i, last)}</span>${c.name}${srcBadge}<span class="sub">
          ${c.issuer ? ` · ${c.issuer}` : ''}${range}${c.country ? ` · ${c.country}` : ''}</span
        >
      </div>`
    })}`
  }

  private renderSigTab(s: SignatureCardModel) {
    const es = this._lang === 'es'
    const kv: Array<[string, string]> = []
    if (s.tech.signedAtISO) kv.push(['signed (UTC, ms)', s.tech.signedAtISO])
    else if (s.signedAt) {
      // If the value is a clean date it already shows on the main face; if it's
      // a raw serial/DN/reference we relocate it HERE (raw, clearly labeled).
      const clean = fmtDate(s.signedAt, this._lang)
      kv.push([clean ? 'signed' : (es ? 'firma (ref. sin procesar)' : 'signed (raw reference)'), s.signedAt])
    }
    if (s.tech.reason) kv.push(['commitment', s.tech.reason])
    if (s.method) kv.push(['method', s.method])
    if (s.tech.standard) kv.push(['standard', s.tech.standard])
    // `pdf producer` (PDF /Producer) is just the last app that wrote the file
    // bytes, not the signing authority — noise in a signature card, so it is
    // intentionally NOT displayed. It stays in tech.producer for the JSON export.
    if (s.cert?.validFrom || s.cert?.validTo) kv.push(['cert valid', `${s.cert?.validFrom ?? '?'} – ${s.cert?.validTo ?? '?'}`])
    if (s.tech.digestAlgorithm) kv.push(['digest', s.tech.digestAlgorithm])
    if (s.tech.byteRange) kv.push(['byte range', `[${s.tech.byteRange.join(', ')}]`])
    if (s.tech.pkcs7Size) kv.push(['PKCS#7 size', `${s.tech.pkcs7Size} bytes`])
    if (s.tech.keyId) kv.push(['key id', s.tech.keyId])
    // Mask the handle: it may embed a national ID (cr-<cédula>.attestto.id).
    // The tool never displays that PII in cleartext (see renderId).
    if (s.handle) kv.push(['handle', this.maskHandle(s.handle)])
    if (s.tech.location) kv.push(['location', s.tech.location])
    if (s.ltv) {
      kv.push(['LTV tier', s.ltv.tier])
      kv.push(['timestamp', s.ltv.hasTimestamp ? `${s.ltv.timestampAt ?? 'yes'}${s.ltv.timestampAuthority ? ` · ${s.ltv.timestampAuthority}` : ''}` : 'none'])
      kv.push(['revocation', s.ltv.revocationSource])
    }
    return html`
      <div class="kv">
        ${kv.map(([k, v]) => {
          const hint = this.techHint(k)
          return html`<span class="k"
              >${k}${hint
                ? html`<span class="hint" tabindex="0" role="button" aria-label=${hint}
                    >?<span class="tip">${hint}</span></span
                  >`
                : ''}</span
            ><span class="v">${v}</span>`
        })}
      </div>
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

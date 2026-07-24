import { LitElement, html, css } from 'lit'
import { customElement, property, state } from 'lit/decorators.js'
import {
  verifyPdf,
  type PdfVerificationResult,
  type PdfSignatureInfo,
} from '../composables/pdf-verifier.js'
import { attesttoPlugins, type VerificationResult } from '../plugins/registry.js'
import { sharedStyles } from '../styles/shared.js'
import { t, currentLang, type Lang } from '../i18n.js'
import './attestto-signature-card.js'
import {
  capabilitiesFromCert,
  countryName,
  officialVerifierFor,
  signatureStandard,
  type SignatureCardModel,
  type SignatureStatus,
  type SignatureTrustMark,
} from '../model/signature-card.js'
import { checkOcspOnline, type OnlineOcspResult } from '../composables/online-ocsp.js'
import {
  checkRevocationViaResolver,
  crSinpeCaFromIssuer,
  type ResolverRevocationResult,
} from '../composables/resolver-revocation.js'

/** Per-signature state for the opt-in online revocation check (keyed by index). */
interface OnlineRevState {
  checking: boolean
  result: OnlineOcspResult | ResolverRevocationResult | null
}

/**
 * Persisted preference: when enabled, the CR revocation check runs automatically
 * on every verification (leveraging the browser-cached CRL). Default OFF, so the
 * out-of-the-box behavior performs no surprise network fetch. Stored in
 * localStorage so the choice is remembered across visits.
 */
const AUTO_REVOCATION_KEY = 'attestto:autoRevocation'

/**
 * <attestto-verify> — Drop a PDF to verify its integrity and signatures
 *
 * Usage:
 *   <attestto-verify></attestto-verify>
 *   <attestto-verify hash="abc123"></attestto-verify>
 *   <attestto-verify allow-plugins theme="dark" root-ca="Attestto-Root-2026"></attestto-verify>
 *
 * CSS Parts (for external styling without breaking shadow DOM):
 *   ::part(drop-zone)      — the file drop area
 *   ::part(result-card)    — the verification results container
 *   ::part(hash-display)   — the SHA-256 hash display
 *   ::part(sig-card)       — each signature card
 *   ::part(status-badge)   — verification level badge (detected/verified/trusted/qualified)
 *   ::part(signer-name)    — the signer's display name
 *   ::part(did-link)       — the DID URI (clickable, resolves to DID Document)
 *   ::part(vlei-badge)     — vLEI corporate identity container (GLEIF logo + LEI + role)
 *   ::part(corporate-info) — organization info row (non-vLEI)
 *   ::part(trust-level)    — the level hint text explaining verification depth
 *   ::part(button)         — action buttons
 *
 * Events (composed, cross shadow DOM):
 *   verification-started  — { fileName, fileSize }
 *   verification-complete — { hash, signatures, plugins, audit }
 *   identity-challenged  — { signerIndex, idType, action: 'revealed' }
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
        border-color: var(--attestto-primary, #594fd3);
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
      .file-error {
        margin-top: 0.9rem;
        padding: 0.7rem 1rem;
        border: 1px solid rgba(255, 107, 107, 0.45);
        border-radius: 10px;
        background: rgba(255, 107, 107, 0.08);
        color: #ff8f8f;
        font-size: 0.85rem;
        text-align: center;
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

      /* Wrapper for each <attestto-signature-card>. The card carries its own
         dark gradient body, so the slot only provides vertical spacing. */
      .sig-card-slot {
        margin-top: 1rem;
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

      /* ── Verification Level Badges ─────────────────────────── */
      .badge-detected {
        background: var(--attestto-warning-bg, #fef3c7);
        color: var(--attestto-warning, #d97706);
      }

      .badge-parsed,
      .badge-signed {
        background: var(--attestto-success-bg, #dcfce7);
        color: var(--attestto-success, #16a34a);
      }

      .badge-trusted {
        background: var(--attestto-info-bg, #dbeafe);
        color: var(--attestto-info, #2563eb);
      }

      .badge-qualified {
        background: linear-gradient(135deg, #fef3c7, #fde68a);
        color: #92400e;
        border: 1px solid #f59e0b;
      }

      .badge-none {
        background: var(--attestto-muted-bg, #f1f5f9);
        color: var(--attestto-text-muted, #64748b);
      }

      .badge-valid {
        background: var(--attestto-success-bg, #dcfce7);
        color: var(--attestto-success, #16a34a);
      }

      .badge-failed {
        background: var(--attestto-error-bg, #fee2e2);
        color: var(--attestto-error, #dc2626);
      }

      /* TAMPERED — overrides everything else. The chain may be valid but
         the document was modified after signing (Phase A — ATT-309). */
      .badge-tampered {
        background: #dc2626;
        color: #ffffff;
        border: 1px solid #7f1d1d;
        font-weight: 700;
        animation: tampered-pulse 1.6s ease-in-out infinite;
      }
      @keyframes tampered-pulse {
        0%,
        100% {
          box-shadow: 0 0 0 0 rgba(220, 38, 38, 0.5);
        }
        50% {
          box-shadow: 0 0 0 6px rgba(220, 38, 38, 0);
        }
      }
      .badge-verified {
        background: #0a2818;
        color: #69f0ae;
        border: 1px solid #00c853;
      }

      /* UNKNOWN — integrity check could NOT run (runtime/parser error).
         NOT a tamper signal. Neutral amber, no animation. (ATT-357) */
      .badge-unknown {
        background: #3a2f00;
        color: #ffe48a;
        border: 1px solid #d4a017;
        font-weight: 600;
      }

      /* ── DID & Corporate Identity Rows ─────────────────────── */
      .signer-did {
        font-family: 'SF Mono', 'Fira Code', monospace;
        font-size: 0.78rem;
        color: var(--attestto-primary, #594fd3);
        margin-top: 0.35rem;
        cursor: pointer;
        word-break: break-all;
      }

      .signer-did:hover {
        text-decoration: underline;
      }

      .corporate-row {
        display: flex;
        align-items: center;
        gap: 0.5rem;
        margin-top: 0.5rem;
        padding: 0.5rem 0.75rem;
        background: var(--attestto-bg-code, #f1f5f9);
        border-radius: 6px;
        font-size: 0.82rem;
      }

      .corporate-row .gleif-icon {
        font-weight: 700;
        font-size: 0.7rem;
        padding: 0.1rem 0.35rem;
        border-radius: 3px;
        background: #1e40af;
        color: white;
        letter-spacing: 0.03em;
      }

      .level-hint {
        font-size: 0.72rem;
        color: var(--attestto-text-muted, #64748b);
        margin-top: 0.25rem;
        font-style: italic;
      }

      .sub-filter-tag {
        font-size: 0.68rem;
        font-family: 'SF Mono', 'Fira Code', monospace;
        color: var(--attestto-text-muted, #64748b);
        padding: 0.1rem 0.4rem;
        background: var(--attestto-bg-code, #f1f5f9);
        border-radius: 3px;
      }

      /* ── PKI Identity Badge ────────────────────────────────── */
      .pki-badge {
        display: flex;
        align-items: center;
        gap: 0.5rem;
        margin-top: 0.5rem;
        padding: 0.5rem 0.75rem;
        border-radius: 8px;
        font-size: 0.875rem;
        background: var(--attestto-info-bg, #dbeafe);
        border: 1px solid var(--attestto-info, #2563eb);
      }

      .pki-badge .pki-flag {
        font-size: 1.25rem;
      }

      .pki-badge .pki-name {
        font-weight: 700;
        font-size: 0.95rem;
        color: var(--attestto-info, #2563eb);
      }

      .pki-badge .pki-type {
        font-size: 0.8rem;
        color: var(--attestto-text-muted, #64748b);
        font-weight: 500;
      }

      /* ── Certificate Chain ──────────────────────────────────── */
      .cert-expired {
        color: var(--attestto-error, #dc2626);
        font-weight: 600;
      }

      .expiry-warning {
        display: flex;
        align-items: center;
        gap: 0.4rem;
        padding: 0.5rem 0.75rem;
        margin-top: 0.5rem;
        background: var(--attestto-warning-bg, #fef3c7);
        color: var(--attestto-warning-text, #92400e);
        border-radius: 6px;
        font-size: 0.78rem;
        line-height: 1.4;
      }

      .revocation-status {
        display: flex;
        align-items: center;
        gap: 0.4rem;
        padding: 0.4rem 0.75rem;
        margin-top: 0.5rem;
        border-radius: 6px;
        font-size: 0.78rem;
      }
      .revocation-good {
        background: var(--attestto-success-bg, #dcfce7);
        color: var(--attestto-success-text, #166534);
      }
      .revocation-revoked {
        background: var(--attestto-error-bg, #fee2e2);
        color: var(--attestto-error-text, #991b1b);
      }
      .revocation-unknown,
      .revocation-parse-error {
        background: var(--attestto-warning-bg, #fef3c7);
        color: var(--attestto-warning-text, #92400e);
      }

      /* ── Document-level revocation controls (one opt-in, all cards) ── */
      .revocation-controls {
        display: flex;
        flex-direction: column;
        gap: 0.5rem;
        margin-top: 0.5rem;
        padding: 0.75rem 1rem;
        border: 1px solid var(--attestto-border, #e2e8f0);
        border-radius: 8px;
        background: var(--attestto-bg-code, #f1f5f9);
      }
      .revocation-controls-row {
        display: flex;
        align-items: center;
        gap: 0.75rem;
        flex-wrap: wrap;
      }
      .revocation-all-btn {
        display: inline-flex;
        align-items: center;
        gap: 0.4rem;
        font-size: 0.8rem;
        font-weight: 500;
        padding: 0.4rem 0.85rem;
        border-radius: 8px;
        cursor: pointer;
        color: var(--attestto-info, #2563eb);
        background: var(--attestto-info-bg, #dbeafe);
        border: 1px solid color-mix(in srgb, var(--attestto-info, #2563eb), transparent 55%);
      }
      .revocation-all-btn:hover:not(:disabled) {
        background: var(--attestto-bg-hover, #e2e8f0);
      }
      .revocation-all-btn:disabled {
        opacity: 0.55;
        cursor: default;
      }
      .revocation-fetch-note {
        font-size: 0.72rem;
        color: var(--attestto-text-muted, #64748b);
      }
      .revocation-auto {
        display: inline-flex;
        align-items: center;
        gap: 0.45rem;
        font-size: 0.78rem;
        color: var(--attestto-text-muted, #64748b);
        cursor: pointer;
      }
      .revocation-auto input {
        cursor: pointer;
      }

      .pkcs7-surface {
        display: flex;
        align-items: center;
        gap: 0.5rem;
        margin-top: 0.5rem;
      }
      .pkcs7-copy-btn {
        font-size: 0.7rem;
        padding: 0.2rem 0.5rem;
        border: 1px solid var(--attestto-border, #e2e8f0);
        border-radius: 4px;
        background: var(--attestto-bg-code, #f1f5f9);
        color: var(--attestto-text-muted, #64748b);
        cursor: pointer;
      }
      .pkcs7-copy-btn:hover {
        background: var(--attestto-bg-hover, #e2e8f0);
      }
      .pkcs7-size {
        font-size: 0.7rem;
        color: var(--attestto-text-muted, #64748b);
      }

      .cert-chain {
        margin-top: 0.75rem;
        padding: 0.75rem;
        background: var(--attestto-bg-code, #f1f5f9);
        border-radius: 6px;
        font-size: 0.78rem;
      }

      .cert-chain-title {
        font-size: 0.7rem;
        font-weight: 600;
        text-transform: uppercase;
        letter-spacing: 0.05em;
        color: var(--attestto-text-muted, #64748b);
        margin-bottom: 0.5rem;
      }

      .cert-node {
        display: flex;
        align-items: flex-start;
        gap: 0.4rem;
        padding: 0.25rem 0;
        padding-left: calc(var(--depth, 0) * 1rem);
      }

      .cert-icon {
        flex-shrink: 0;
        width: 1rem;
        text-align: center;
      }

      .cert-details {
        flex: 1;
        min-width: 0;
      }

      .cert-cn {
        font-weight: 600;
        color: var(--attestto-text, #1e293b);
      }

      .cert-org {
        color: var(--attestto-text-muted, #64748b);
        font-size: 0.72rem;
      }

      .cert-meta {
        display: flex;
        gap: 0.75rem;
        margin-top: 0.15rem;
        font-size: 0.68rem;
        color: var(--attestto-text-muted, #64748b);
      }

      .cert-id {
        font-family: 'SF Mono', 'Fira Code', monospace;
        color: var(--attestto-primary, #594fd3);
      }

      /* ── Identity Challenge ─────────────────────────────────── */
      .id-masked {
        display: flex;
        align-items: center;
        gap: 0.5rem;
        margin-top: 0.5rem;
      }

      .id-masked-value {
        font-family: 'SF Mono', 'Fira Code', monospace;
        color: var(--attestto-text-muted, #64748b);
        font-size: 0.82rem;
        letter-spacing: 0.04em;
      }

      .id-reveal-btn {
        display: inline-flex;
        align-items: center;
        gap: 0.3rem;
        padding: 0.25rem 0.65rem;
        font-size: 0.72rem;
        font-weight: 600;
        cursor: pointer;
        color: var(--attestto-primary, #594fd3);
        background: none;
        border: 1px solid var(--attestto-primary, #594fd3);
        border-radius: 6px;
        transition: all 0.15s;
      }

      .id-reveal-btn:hover {
        background: var(--attestto-primary, #594fd3);
        color: white;
      }

      .id-challenge {
        margin-top: 0.5rem;
        padding: 0.75rem;
        background: var(--attestto-bg-code, #f1f5f9);
        border: 1px solid var(--attestto-border, #e2e8f0);
        border-radius: 8px;
        font-size: 0.78rem;
      }

      .id-challenge p {
        color: var(--attestto-text-muted, #64748b);
        margin-bottom: 0.5rem;
        line-height: 1.4;
      }

      .id-challenge-actions {
        display: flex;
        gap: 0.5rem;
      }

      .id-challenge-confirm {
        padding: 0.3rem 0.75rem;
        font-size: 0.72rem;
        font-weight: 600;
        cursor: pointer;
        background: var(--attestto-primary, #594fd3);
        color: white;
        border: none;
        border-radius: 6px;
        transition: opacity 0.15s;
      }

      .id-challenge-confirm:hover {
        opacity: 0.85;
      }

      .id-challenge-cancel {
        padding: 0.3rem 0.75rem;
        font-size: 0.72rem;
        cursor: pointer;
        background: none;
        color: var(--attestto-text-muted, #64748b);
        border: 1px solid var(--attestto-border, #e2e8f0);
        border-radius: 6px;
        transition: all 0.15s;
      }

      .id-challenge-cancel:hover {
        border-color: var(--attestto-text-muted, #64748b);
      }

      .id-revealed {
        font-family: 'SF Mono', 'Fira Code', monospace;
        color: var(--attestto-primary, #594fd3);
        font-size: 0.82rem;
      }

      .id-cta {
        font-size: 0.68rem;
        color: var(--attestto-text-muted, #64748b);
        margin-top: 0.35rem;
        font-style: italic;
      }

      .id-cta a {
        color: var(--attestto-primary, #594fd3);
        text-decoration: none;
      }

      .id-cta a:hover {
        text-decoration: underline;
      }

      .id-challenge-options {
        display: flex;
        flex-direction: column;
        gap: 0.5rem;
        margin-bottom: 0.75rem;
      }

      .id-option-btn {
        display: flex;
        flex-direction: column;
        align-items: flex-start;
        gap: 0.15rem;
        padding: 0.6rem 0.75rem;
        background: var(--attestto-bg-card, #ffffff);
        border: 1px solid var(--attestto-border, #e2e8f0);
        border-radius: 8px;
        cursor: pointer;
        text-align: left;
        transition: all 0.15s;
        font-size: 0.82rem;
        font-weight: 600;
        color: var(--attestto-text, #1e293b);
      }

      .id-option-btn:hover {
        border-color: var(--attestto-primary, #594fd3);
        background: var(--attestto-bg-code, #f1f5f9);
      }

      .id-option-icon {
        font-size: 1rem;
      }

      .id-option-hint {
        font-size: 0.7rem;
        font-weight: 400;
        color: var(--attestto-text-muted, #64748b);
      }

      .id-challenge-input-row {
        display: flex;
        gap: 0.4rem;
        margin-bottom: 0.5rem;
      }

      .id-challenge-input {
        flex: 1;
        padding: 0.4rem 0.6rem;
        font-size: 0.78rem;
        font-family: 'SF Mono', 'Fira Code', monospace;
        border: 1px solid var(--attestto-border, #e2e8f0);
        border-radius: 6px;
        background: var(--attestto-bg-card, #ffffff);
        color: var(--attestto-text, #1e293b);
        outline: none;
        transition: border-color 0.15s;
      }

      .id-challenge-input:focus {
        border-color: var(--attestto-primary, #594fd3);
      }

      .id-challenge-input::placeholder {
        color: var(--attestto-text-muted, #94a3b8);
        font-style: italic;
      }

      .id-challenge-error {
        font-size: 0.72rem;
        color: var(--attestto-error, #dc2626);
        margin: 0 0 0.35rem;
      }

      /* ── Tooltips ────────────────────────────────────────────── */
      .has-tooltip {
        position: relative;
        cursor: help;
      }

      .has-tooltip .tooltip-text {
        visibility: hidden;
        opacity: 0;
        position: absolute;
        bottom: calc(100% + 6px);
        left: 50%;
        transform: translateX(-50%);
        background: var(--attestto-bg-elevated, #1e293b);
        color: var(--attestto-text, #e2e8f0);
        padding: 0.45rem 0.65rem;
        border-radius: 6px;
        font-size: 0.72rem;
        font-weight: 400;
        line-height: 1.4;
        text-transform: none;
        letter-spacing: normal;
        white-space: normal;
        width: max-content;
        max-width: 280px;
        z-index: 10;
        pointer-events: none;
        transition:
          opacity 0.15s ease,
          visibility 0.15s ease;
        box-shadow: 0 4px 12px rgba(0, 0, 0, 0.3);
        border: 1px solid var(--attestto-border, #334155);
      }

      .has-tooltip .tooltip-text::after {
        content: '';
        position: absolute;
        top: 100%;
        left: 50%;
        transform: translateX(-50%);
        border: 5px solid transparent;
        border-top-color: var(--attestto-bg-elevated, #1e293b);
      }

      .has-tooltip:hover .tooltip-text,
      .has-tooltip:focus .tooltip-text {
        visibility: visible;
        opacity: 1;
      }

      /* Tooltip anchored to the left for badges near the right edge */
      .has-tooltip.tooltip-left .tooltip-text {
        left: 0;
        transform: none;
      }
      .has-tooltip.tooltip-left .tooltip-text::after {
        left: 12px;
        transform: none;
      }

      /* Section title with info icon */
      .section-title-row {
        display: flex;
        align-items: center;
        gap: 0.35rem;
      }

      .info-icon {
        display: inline-flex;
        align-items: center;
        justify-content: center;
        width: 15px;
        height: 15px;
        border-radius: 50%;
        background: var(--attestto-border, #334155);
        color: var(--attestto-text-muted, #94a3b8);
        font-size: 0.6rem;
        font-weight: 700;
        cursor: help;
        flex-shrink: 0;
      }

      /* ── Trust Permissions ───────────────────────────────────── */
      .trust-permissions {
        margin-top: 0.75rem;
      }

      .permission-grid {
        display: flex;
        flex-wrap: wrap;
        gap: 0.35rem;
      }

      .permission-badge {
        display: inline-block;
        padding: 0.2rem 0.5rem;
        font-size: 0.68rem;
        font-weight: 500;
        border-radius: 4px;
        text-transform: uppercase;
        letter-spacing: 0.03em;
      }

      .permission-key {
        background: var(--attestto-success-bg, #dcfce7);
        color: var(--attestto-success, #16a34a);
        border: 1px solid color-mix(in srgb, var(--attestto-success, #16a34a), transparent 70%);
      }

      .permission-ext {
        background: var(--attestto-info-bg, #dbeafe);
        color: var(--attestto-info, #2563eb);
        border: 1px solid color-mix(in srgb, var(--attestto-info, #2563eb), transparent 70%);
      }

      /* ── Card Flip ──────────────────────────────────────────── */
      .card-flip-tab {
        position: absolute;
        top: -1px;
        right: 1rem;
        z-index: 2;
        padding: 0.4rem 1rem;
        font-size: 0.72rem;
        font-weight: 600;
        cursor: pointer;
        color: var(--attestto-text-muted, #64748b);
        background: var(--attestto-bg-code, #1e293b);
        border: 1px solid var(--attestto-border, #334155);
        border-bottom: none;
        border-radius: 8px 8px 0 0;
        transition: all 0.2s;
        transform: translateY(-100%);
      }

      .card-flip-tab:hover {
        color: var(--attestto-text, #e2e8f0);
        background: var(--attestto-bg-code-hover, #334155);
      }

      .card-back-btn {
        display: inline-flex;
        align-items: center;
        gap: 0.4rem;
        padding: 0.4rem 0.85rem;
        font-size: 0.78rem;
        font-weight: 600;
        cursor: pointer;
        color: #0f172a;
        background: #e2e8f0;
        border: none;
        border-radius: 6px;
        margin-bottom: 1rem;
        transition: all 0.2s;
      }

      .card-back-btn:hover {
        background: #ffffff;
      }

      .card-flipper {
        perspective: 1200px;
        position: relative;
      }

      .card-inner {
        position: relative;
        transition: transform 0.6s cubic-bezier(0.4, 0, 0.2, 1);
        transform-style: preserve-3d;
      }

      .card-inner.flipped {
        transform: rotateY(180deg);
      }

      .card-front,
      .card-back {
        backface-visibility: hidden;
        -webkit-backface-visibility: hidden;
      }

      .card-back {
        position: absolute;
        top: 0;
        left: 0;
        width: 100%;
        transform: rotateY(180deg);
        background: var(--attestto-bg-card, #0f172a);
        border-radius: 12px;
        padding: 1.25rem;
        border: 1px solid var(--attestto-border, #334155);
      }

      /* ── Forensic Audit Section ────────────────────────────── */

      .audit-grid {
        padding: 1rem;
        display: grid;
        gap: 0.75rem;
      }

      .audit-group {
        border-bottom: 1px solid var(--attestto-border, #e2e8f0);
        padding-bottom: 0.75rem;
      }

      .audit-group:last-child {
        border-bottom: none;
        padding-bottom: 0;
      }

      .audit-group-title {
        font-size: 0.75rem;
        font-weight: 600;
        text-transform: uppercase;
        letter-spacing: 0.05em;
        color: var(--attestto-text-muted, #64748b);
        margin-bottom: 0.5rem;
      }

      .audit-item {
        display: flex;
        align-items: center;
        gap: 0.5rem;
        font-size: 0.82rem;
        padding: 0.25rem 0;
      }

      .audit-item strong {
        min-width: 120px;
        color: var(--attestto-text-muted, #64748b);
        font-weight: 500;
      }

      .audit-item code {
        font-family: 'SF Mono', 'Fira Code', monospace;
        font-size: 0.78rem;
        padding: 0.15rem 0.4rem;
        border-radius: 4px;
        background: var(--attestto-bg-code, #f1f5f9);
      }

      .audit-safe {
        color: var(--attestto-success, #16a34a);
      }

      .audit-warn {
        color: var(--attestto-warning, #d97706);
      }

      .audit-danger {
        color: var(--attestto-error, #dc2626);
      }

      .audit-info {
        color: var(--attestto-info, #2563eb);
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
        0% {
          opacity: 0;
          transform: translateX(-50%) translateY(10px);
        }
        15% {
          opacity: 1;
          transform: translateX(-50%) translateY(0);
        }
        85% {
          opacity: 1;
        }
        100% {
          opacity: 0;
        }
      }

      /* ── Loading Card with Animated Beans ──────────────────── */
      .loading-card {
        display: flex;
        flex-direction: column;
        align-items: center;
        justify-content: center;
        padding: 3rem 2rem;
        text-align: center;
        min-height: 200px;
      }

      .loading-beans {
        display: flex;
        gap: 0.5rem;
        margin-bottom: 1.5rem;
      }

      .bean {
        width: 12px;
        height: 12px;
        border-radius: 50%;
        background: var(--attestto-primary, #594fd3);
        animation: bean-bounce 1.4s ease-in-out infinite;
      }

      .bean-1 {
        animation-delay: 0s;
      }
      .bean-2 {
        animation-delay: 0.16s;
      }
      .bean-3 {
        animation-delay: 0.32s;
      }

      @keyframes bean-bounce {
        0%,
        80%,
        100% {
          transform: scale(0.6);
          opacity: 0.4;
        }
        40% {
          transform: scale(1);
          opacity: 1;
        }
      }

      .loading-step {
        font-size: 0.9rem;
        font-weight: 500;
        color: var(--attestto-text, #1e293b);
        margin-bottom: 0.5rem;
      }

      .loading-hint {
        font-size: 0.72rem;
        color: var(--attestto-text-muted, #64748b);
      }

      /* ── Share & Hash Match ──────────────────────────────── */
      .share-actions {
        display: flex;
        justify-content: center;
        gap: 0.75rem;
        margin-top: 1.25rem;
      }

      .share-btn {
        background: var(--attestto-primary, #594fd3);
        color: white;
        border: none;
        padding: 0.5rem 1.25rem;
        border-radius: 8px;
        cursor: pointer;
        font-size: 0.85rem;
        font-weight: 500;
        transition: background 0.15s;
      }

      .share-btn:hover {
        background: var(--attestto-primary-hover, #7b72ed);
      }

      .reset-btn {
        background: none;
        border: 1px solid var(--attestto-border, #cbd5e1);
        padding: 0.5rem 1.25rem;
        border-radius: 8px;
        cursor: pointer;
        font-size: 0.85rem;
        color: var(--attestto-text-muted, #64748b);
      }

      .share-hint {
        text-align: center;
        font-size: 0.75rem;
        color: var(--attestto-text-muted, #64748b);
        margin-top: 0.5rem;
      }

      .hash-match {
        display: flex;
        gap: 0.75rem;
        align-items: flex-start;
        padding: 1rem;
        border-radius: 8px;
        margin-top: 1rem;
      }

      .hash-match-ok {
        background: var(--attestto-success-bg, #f0fdf4);
        border: 1px solid var(--attestto-success, #16a34a);
      }

      .hash-match-fail {
        background: var(--attestto-warning-bg, #fefce8);
        border: 1px solid var(--attestto-warning, #d97706);
      }

      .hash-match-icon {
        font-size: 1.25rem;
        flex-shrink: 0;
        margin-top: 0.1rem;
      }

      .hash-match-ok .hash-match-icon {
        color: var(--attestto-success, #16a34a);
      }

      .hash-match-fail .hash-match-icon {
        color: var(--attestto-warning, #d97706);
      }

      .hash-match-title {
        font-weight: 600;
        font-size: 0.95rem;
        margin-bottom: 0.25rem;
      }

      .hash-match-detail {
        font-size: 0.82rem;
        color: var(--attestto-text-muted, #64748b);
        line-height: 1.4;
      }

      .hash-match-cta {
        display: inline-block;
        margin-top: 0.5rem;
        font-size: 0.82rem;
        font-weight: 500;
        color: var(--attestto-primary, #594fd3);
        text-decoration: none;
      }

      .hash-match-cta:hover {
        text-decoration: underline;
      }

      /* ── Summary banner (ATT-203) ───────────────────── */
      .summary-banner {
        display: flex;
        align-items: center;
        gap: 1rem;
        padding: 1rem 1.25rem;
        border-radius: 10px;
        margin-bottom: 1rem;
      }

      .summary-banner-verified {
        background: var(--attestto-success-bg, #052e16);
        border: 1px solid var(--attestto-success, #16a34a);
      }

      .summary-banner-tampered {
        background: #450a0a;
        border: 1px solid #dc2626;
      }

      .summary-banner-partial {
        background: var(--attestto-warning-bg, #422006);
        border: 1px solid var(--attestto-warning, #d97706);
      }

      .summary-banner-none {
        background: var(--attestto-muted-bg, #1e293b);
        border: 1px solid var(--attestto-border, #334155);
      }

      .summary-icon {
        font-size: 2rem;
        flex-shrink: 0;
      }

      .summary-content {
        flex: 1;
        min-width: 0;
      }

      .summary-title {
        font-size: 1.1rem;
        font-weight: 700;
      }

      .summary-banner-verified .summary-title {
        color: var(--attestto-success, #4ade80);
      }
      .summary-banner-tampered .summary-title {
        color: #f87171;
      }
      .summary-banner-partial .summary-title {
        color: var(--attestto-warning, #fbbf24);
      }
      .summary-banner-none .summary-title {
        color: var(--attestto-text-muted, #94a3b8);
      }

      .summary-detail {
        font-size: 0.82rem;
        color: var(--attestto-text-muted, #94a3b8);
        margin-top: 0.2rem;
      }

      .summary-meta {
        font-size: 0.72rem;
        color: var(--attestto-text-muted, #64748b);
        margin-top: 0.35rem;
      }

      .summary-actions {
        display: flex;
        flex-shrink: 0;
      }

      .copy-summary-btn {
        background: none;
        border: 1px solid var(--attestto-border, #334155);
        color: var(--attestto-text-muted, #94a3b8);
        padding: 0.35rem 0.7rem;
        border-radius: 6px;
        cursor: pointer;
        font-size: 0.75rem;
        transition: all 0.15s;
        white-space: nowrap;
      }

      .copy-summary-btn:hover {
        border-color: var(--attestto-primary, #594fd3);
        color: var(--attestto-text, #e2e8f0);
      }
    `,
  ]

  /** Pre-filled hash for deep-link mode (/d/{hash}) */
  @property({ type: String }) hash = ''
  /** Expected hash from a shared verification link (#sha256=...) */
  @property({ type: String, attribute: 'expected-hash' }) expectedHash = ''
  /** Non-PDF rejection message (verifier only supports PDFs). */
  @state() private _fileError: string | null = null
  /** Whether the summary text was just copied */
  @state() private showSummaryCopied = false
  /** Timestamp of when verification completed */
  @state() private verifiedAt: string | null = null

  @state() private dragging = false
  @state() private verifying = false
  @state() private verifyStep = ''
  @state() private result: PdfVerificationResult | null = null
  @state() private pluginResults: Map<string, VerificationResult> | null = null
  @state() private showCopied = false
  @state() private _lang: Lang = currentLang()
  /**
   * Opt-in online revocation results, keyed by signature index. Empty by default
   * and only ever written when the user clicks "Check revocation online" on a
   * card. Nothing here runs on load or on verify, so the no-network default is
   * unchanged.
   */
  @state() private _onlineRev = new Map<number, OnlineRevState>()

  /**
   * Remembered "check revocation automatically" preference. Read from
   * localStorage on connect; default OFF. When ON, verify() triggers the same
   * batch check the user could run by hand — never a surprise fetch, because the
   * user opted in and the choice persists.
   */
  @state() private _autoRevocation = false

  private _onLangChange = (e: Event) => {
    this._lang = (e as CustomEvent).detail.lang
  }

  /** Read the persisted auto-revocation preference (safe if storage is blocked). */
  private readAutoRevocationPref(): boolean {
    try {
      return localStorage.getItem(AUTO_REVOCATION_KEY) === '1'
    } catch {
      return false
    }
  }

  private toggleAutoRevocation(on: boolean) {
    this._autoRevocation = on
    try {
      if (on) localStorage.setItem(AUTO_REVOCATION_KEY, '1')
      else localStorage.removeItem(AUTO_REVOCATION_KEY)
    } catch {
      /* storage blocked — keep the in-memory choice for this session */
    }
    // Turning it on after a result is already shown should honor the intent now.
    if (on && this.result) void this.runAllCrRevocation()
  }

  override connectedCallback() {
    super.connectedCallback()
    window.addEventListener('attestto-lang-change', this._onLangChange)
    this._autoRevocation = this.readAutoRevocationPref()
  }

  override disconnectedCallback() {
    super.disconnectedCallback()
    window.removeEventListener('attestto-lang-change', this._onLangChange)
  }

  override render() {
    return html`
      ${
        this.verifying
          ? this.renderLoading()
          : this.result
            ? this.renderResult()
            : this.renderDropZone()
      }
      ${this.showCopied ? html`<div class="copied-toast">${t('comp.verify.hashCopied')}</div>` : ''}
    `
  }

  private renderLoading() {
    return html`
      <div class="loading-card" part="loading">
        <div class="loading-beans">
          <span class="bean bean-1"></span>
          <span class="bean bean-2"></span>
          <span class="bean bean-3"></span>
        </div>
        <div class="loading-step">${this.verifyStep}</div>
        <div class="loading-hint">${t('comp.verify.loading.hint')}</div>
      </div>
    `
  }

  private renderDropZone() {
    const hasExpected = !!this.expectedHash
    return html`
      <div
        class="drop-zone ${this.dragging ? 'dragging' : ''}"
        part="drop-zone"
        @click=${this.openFilePicker}
        @dragover=${this.onDragOver}
        @dragleave=${this.onDragLeave}
        @drop=${this.onDrop}
      >
        <div class="drop-zone-icon">${hasExpected ? '🔗' : '📄'}</div>
        <div class="drop-zone-text">
          ${
            this.dragging
              ? t('comp.verify.dropFile')
              : hasExpected
                ? t('comp.verify.dropShared')
                : t('comp.verify.dropVerify')
          }
        </div>
        <div class="drop-zone-hint">
          ${hasExpected ? t('comp.verify.dropHintShared') : t('comp.verify.dropHint')}
        </div>
        <input type="file" @change=${this.onFileSelect} accept=".pdf,application/pdf" />
      </div>
      ${this._fileError ? html`<div class="file-error" part="file-error">${this._fileError}</div>` : ''}
    `
  }

  private renderSummaryBanner() {
    const r = this.result!
    const sigs = r.signatures
    const sigCount = sigs.length
    const hasTampered = sigs.some((s) => s.level === 'tampered')
    const allVerified =
      sigCount > 0 &&
      sigs.every((s) => s.level === 'verified' || s.level === 'trusted' || s.level === 'qualified')
    const someVerified =
      sigCount > 0 &&
      sigs.some((s) => s.level === 'verified' || s.level === 'trusted' || s.level === 'qualified')

    let bannerClass: string
    let icon: string
    let title: string
    let detail: string

    if (hasTampered) {
      bannerClass = 'summary-banner-tampered'
      icon = '⛔'
      title = t('comp.verify.summary.tampered')
      detail = t('comp.verify.summary.modified')
    } else if (allVerified) {
      bannerClass = 'summary-banner-verified'
      icon = '✓'
      title = t('comp.verify.summary.verified')
      detail = `${sigCount} ${t('comp.verify.summary.sigCount')} · ${t('comp.verify.summary.intact')}`
    } else if (someVerified) {
      bannerClass = 'summary-banner-partial'
      icon = '◐'
      title = t('comp.verify.summary.partial')
      detail = `${sigCount} ${t('comp.verify.summary.sigCount')}`
    } else if (sigCount === 0) {
      bannerClass = 'summary-banner-none'
      icon = '○'
      title = t('comp.verify.summary.noSigs')
      detail = r.isPdf ? 'PDF' : r.fileName.split('.').pop()?.toUpperCase() || ''
    } else {
      bannerClass = 'summary-banner-partial'
      icon = '◐'
      title = t('comp.verify.summary.partial')
      detail = `${sigCount} ${t('comp.verify.summary.sigCount')}`
    }

    // Collect PKI names for display
    const pkiNames = [...new Set(sigs.map((s) => s.certChain?.pki?.name).filter(Boolean))]

    return html`
      <div class="summary-banner ${bannerClass}" part="summary-banner">
        <span class="summary-icon">${icon}</span>
        <div class="summary-content">
          <div class="summary-title">${title}</div>
          <div class="summary-detail">
            ${detail}${pkiNames.length > 0 ? ` · ${pkiNames.join(', ')}` : ''}
          </div>
          ${
            this.verifiedAt
              ? html`
                  <div class="summary-meta">
                    ${t('comp.verify.summary.verifiedAt')} ${this.verifiedAt} ·
                    ${t('comp.verify.summary.verifiedVia')}
                  </div>
                `
              : ''
          }
        </div>
        <div class="summary-actions">
          <button class="copy-summary-btn" @click=${this.copySummary}>
            ${
              this.showSummaryCopied
                ? t('comp.verify.summary.summaryCopied')
                : t('comp.verify.summary.copySummary')
            }
          </button>
        </div>
      </div>
    `
  }

  private renderResult() {
    const r = this.result!
    return html`
      <div class="result">
        ${r.isPdf ? this.renderSummaryBanner() : ''}
        <div class="result-card" part="result-card">
          <div>
            <div class="result-header">
              <span class="meta-label">${t('comp.verify.filename')}</span>
              📄 ${r.fileName}
              <span
                style="font-size: 0.8rem; font-weight: 400; color: var(--attestto-text-muted, #64748b)"
              >
                ${this.formatSize(r.fileSize)}
              </span>
            </div>

            ${
              r.isPdf && r.metadata
                ? html`
                    <div class="section-title">${t('comp.verify.metadata')}</div>
                    <div class="meta-grid">
                      ${
                      r.metadata.title
                        ? html`<span class="meta-label">${t('comp.verify.title')}</span
                            ><span>${r.metadata.title}</span>`
                        : ''
                    }
                      ${
                      r.metadata.author
                        ? html`<span class="meta-label">${t('comp.verify.author')}</span
                            ><span>${r.metadata.author}</span>`
                        : ''
                    }
                      ${
                      r.metadata.subject
                        ? html`<span class="meta-label">${t('comp.verify.subject')}</span
                            ><span>${r.metadata.subject}</span>`
                        : ''
                    }
                      ${
                      r.metadata.creator
                        ? html`<span class="meta-label">${t('comp.verify.creator')}</span
                            ><span>${r.metadata.creator}</span>`
                        : ''
                    }
                      ${
                      r.metadata.producer
                        ? html`<span class="meta-label">${t('comp.verify.producer')}</span
                            ><span>${r.metadata.producer}</span>`
                        : ''
                    }
                      ${
                      r.metadata.creationDate
                        ? html`<span class="meta-label">${t('comp.verify.created')}</span
                            ><span>${r.metadata.creationDate}</span>`
                        : ''
                    }
                      ${
                      r.metadata.modDate
                        ? html`<span class="meta-label">${t('comp.verify.modified')}</span
                            ><span>${r.metadata.modDate}</span>`
                        : ''
                    }
                    </div>
                  `
                : ''
            }
            ${
              r.isPdf && r.signatures.length > 0
                ? html`
                    <div class="section-title">${t('comp.verify.digitalSigs')}</div>
                    ${this.renderRevocationControls()}
                    ${r.signatures.map(
                    (sig, i) => html`
                      <div class="sig-card-slot" part="sig-card">
                        <attestto-signature-card
                          exportparts="card,avatar,status,name,official-link,signals,ltv,flag,national-id,id-check,capabilities,capability,internals,online-revocation"
                          .signature=${this.buildSignatureCardModel(sig, i)}
                          @id-confirmed=${(e: Event) =>
                            this.emitChallengeEvent(
                              (e as CustomEvent).detail.index,
                              'knowledge',
                              'revealed',
                            )}
                          @request-online-revocation=${(e: Event) =>
                            this.runOnlineRevocation((e as CustomEvent).detail.index)}
                        ></attestto-signature-card>
                      </div>
                    `,
                  )}
                  `
                : r.isPdf
                  ? html`
                      <div class="section-title">${t('comp.verify.digitalSigs')}</div>
                      <div class="sig-card" part="sig-card">
                        <div class="sig-name">
                          <span class="badge badge-none">${t('comp.verify.badge.none')}</span>
                          ${t('comp.verify.noSigs')}
                        </div>
                      </div>
                    `
                  : ''
            }
          </div>
          ${
            this.pluginResults && this.pluginResults.size > 0
              ? html`
                  <div class="section-title">${t('comp.verify.extVerification')}</div>
                  <div class="plugin-results">
                    ${Array.from(this.pluginResults.entries()).map(
                    ([name, result]) => html`
                      <div class="sig-card" part="sig-card">
                        <div class="sig-name">
                          <span class="badge ${result.valid ? 'badge-valid' : 'badge-failed'}">
                            ${result.valid ? t('comp.verify.valid') : t('comp.verify.failed')}
                          </span>
                          ${attesttoPlugins.get(name)?.label ?? name}
                        </div>
                        ${
                          result.error
                            ? html`<div
                                style="color: var(--attestto-warning, #d97706); font-size: 0.85rem; margin-top: 0.5rem"
                              >
                                ${result.error}
                              </div>`
                            : ''
                        }
                      </div>
                    `,
                  )}
                  </div>
                `
              : ''
          }
        </div>

        ${this.expectedHash ? this.renderHashMatch() : ''}

        <div class="share-actions">
          <button class="reset-btn" @click=${this.reset}>${t('comp.verify.verifyAnother')}</button>
        </div>
      </div>
    `
  }

  /**
   * Map a parsed PDF signature (`PdfSignatureInfo`) onto the presentational
   * `SignatureCardModel` consumed by <attestto-signature-card>. This is the
   * website's tiny mapper — the card stays decoupled from verify's types.
   */
  private buildSignatureCardModel(sig: PdfSignatureInfo, index: number): SignatureCardModel {
    const es = this._lang === 'es'
    const cc = sig.certChain
    const pki = cc?.pki ?? null
    const attestto = sig.attesttoMeta
    const isSelfAttested = sig.subFilter === 'attestto.self-attested.v1'

    // Status: mirror the old badge logic exactly.
    let status: SignatureStatus
    if (sig.level === 'tampered') status = 'tampered'
    else if (sig.level === 'unknown') status = 'unknown'
    else if (sig.level === 'verified' && isSelfAttested) status = 'self-attested'
    else if (sig.level === 'verified' || sig.level === 'trusted' || sig.level === 'qualified')
      status = 'verified'
    else status = 'structure-only'

    const country = pki?.country ?? attestto?.country ?? cc?.signer?.country ?? null

    // Subtitle: PKI type + name, else self-attested descriptor, else org.
    let subtitle: string
    if (pki) {
      subtitle = [pki.certificateType, pki.name].filter(Boolean).join(' · ')
    } else if (isSelfAttested) {
      subtitle = es ? 'Attestto · auto-atestada' : 'Attestto · self-attested'
    } else if (sig.organization) {
      subtitle = sig.organization
    } else {
      subtitle = es ? 'Firma digital' : 'Digital signature'
    }

    // National ID: masked for display + full for the confirm-not-disclose check.
    const nationalId = cc?.nationalId
      ? { masked: this.maskNationalId(cc.nationalId), full: cc.nationalId }
      : null

    const capabilities = capabilitiesFromCert(cc?.keyUsage ?? [], cc?.extKeyUsage ?? [])

    // Trust marks — styled badges only, never third-party logos.
    const trustMarks: SignatureTrustMark[] = []
    if (isSelfAttested) {
      trustMarks.push({
        label: es ? 'Attestto auto-atestada' : 'Attestto self-attested',
        scheme: 'attestto',
      })
    } else if (pki?.country === 'CR') {
      trustMarks.push({ label: 'CR Firma Digital', scheme: 'cr-firma' })
    } else if (pki) {
      trustMarks.push({ label: pki.name, scheme: 'other' })
    } else if (status === 'structure-only') {
      trustMarks.push({
        label: es ? 'Sin raíz de confianza' : 'No trusted root',
        scheme: 'untrusted',
      })
    }

    // Cert chain, root-first (the card renders root → leaf top to bottom).
    const chain = (cc?.chain ?? [])
      .slice()
      .reverse()
      .map((c) => ({
        name: c.commonName,
        issuer: c.issuerCommonName || undefined,
        from: c.validFrom ? c.validFrom.split('T')[0] : undefined,
        to: c.validTo ? c.validTo.split('T')[0] : undefined,
        country: c.country || undefined,
        source: c.source ?? 'embedded',
      }))

    const officialVerifier = officialVerifierFor({
      country,
      status,
      methodTech: sig.subFilter,
    })

    const handle = attestto?.issuerHandle ?? sig.did ?? null

    return {
      index: index + 1,
      signerName: cc?.signerDisplayName || sig.name,
      country,
      status,
      subtitle,
      // Prefer the bundled PKI's human name; otherwise fall back to the
      // country name so the JURISDICTION label matches its flag (bug: ES
      // eIDAS certs resolve a flag but had no PKI → empty em-dash).
      jurisdiction: pki?.fullName ?? pki?.name ?? countryName(country, es ? 'es' : 'en'),
      method: sig.subFilter || (isSelfAttested ? 'Ed25519 · self-attested' : '—'),
      methodTech: sig.subFilter,
      signedAt: sig.signDate,
      cert: cc?.signer ? { validFrom: cc.signer.validFrom, validTo: cc.signer.validTo } : null,
      nationalId,
      capabilities,
      officialVerifier,
      // GAP: verify does not surface per-signature trust-provenance URLs; the
      // card falls back to its canonical Attestto trust-registry links.
      trustLinks: null,
      // GAP: verify does not extract a visible signature/seal appearance image.
      signatureImage: null,
      handle,
      // GAP: verify does not yet parse PAdES-LTV (timestamp tier / embedded
      // revocation) for X.509 signatures, nor an on-chain anchor for Attestto
      // self-attested ones, so this is left null. The card then shows the honest
      // face — "no long-term validation" for X.509, "bound to content + KYC"
      // (NOT "anchored in time") for self-attested — instead of inventing proof.
      // When self-sign starts anchoring, populate ltv.anchor here.
      ltv: null,
      // OPT-IN online revocation. Offered only when an OCSP responder URL is
      // known (from the signer cert AIA) AND the issuer cert is present so a
      // valid CertID can be built. The check itself runs ONLY on user action.
      onlineRevocation: this.onlineRevocationModel(cc, index + 1),
      trustMarks: trustMarks.length ? trustMarks : null,
      tech: {
        // The standard FAMILY (PAdES, PKCS#7, …), not a duplicate of `method`
        // which already carries the raw subFilter.
        standard:
          signatureStandard(sig.subFilter) ?? (isSelfAttested ? 'Attestto self-attested' : null),
        reason: sig.reason,
        producer: this.result?.metadata?.producer ?? null,
        location: sig.location,
        pkcs7Hex: sig.pkcs7Hex,
        pkcs7Size: sig.pkcs7Hex ? Math.round(sig.pkcs7Hex.length / 2) : null,
        keyId: sig.did,
        chain,
      },
    }
  }

  /**
   * Build the opt-in online-revocation slice of the card model for one
   * signature. `available` is true only when we have both an OCSP responder URL
   * (from the signer cert AIA) and the issuer cert DER (to build the CertID).
   * `result`/`checking` reflect any check the user has already run for this
   * card index. Returns null when no responder URL exists, so the card shows
   * nothing (the default no-network behavior is untouched).
   */
  private onlineRevocationModel(
    cc: PdfSignatureInfo['certChain'],
    cardIndex: number,
  ): SignatureCardModel['onlineRevocation'] {
    // CR Firma Digital certs are checked via our resolver CRL endpoint (no OCSP
    // URL / issuer DER needed); everything else needs the direct-OCSP inputs.
    const isCrSinpe = crSinpeCaFromIssuer(cc?.signer?.issuerCommonName) !== null
    const available =
      isCrSinpe || Boolean(cc?.signerOcspUrl && cc?.issuerDerHex && cc?.signer?.rawDerHex)
    if (!available) return null
    const st = this._onlineRev.get(cardIndex)
    return {
      available: true,
      checking: st?.checking ?? false,
      result: st?.result
        ? {
            status: st.result.status,
            message: st.result.message,
            checkedAt: st.result.checkedAt,
            // Only the resolver CRL path carries cachedUntil; OCSP results omit it.
            cachedUntil: 'cachedUntil' in st.result ? st.result.cachedUntil : null,
          }
        : null,
    }
  }

  /**
   * Run a LIVE OCSP check for the signature at `cardIndex` (1-based, matches the
   * card's own index). Fired ONLY from the card's `request-online-revocation`
   * event, which itself only fires after the user confirms the "leaves your
   * device" warning. Never runs automatically.
   */
  private async runOnlineRevocation(cardIndex: number) {
    const sig = this.result?.signatures?.[cardIndex - 1]
    const cc = sig?.certChain
    if (!cc) return
    if (this._onlineRev.get(cardIndex)?.checking) return

    const crCa = crSinpeCaFromIssuer(cc.signer?.issuerCommonName)
    // Non-CR certs need the direct-OCSP prerequisites; CR uses the resolver CRL.
    if (!crCa && (!cc.signerOcspUrl || !cc.issuerDerHex || !cc.signer?.rawDerHex)) return

    this._onlineRev = new Map(this._onlineRev).set(cardIndex, { checking: true, result: null })

    let result: OnlineOcspResult | ResolverRevocationResult
    if (crCa && cc.signer?.serialNumber) {
      // CR Firma Digital: our resolver CRL endpoint (HTTPS + CORS) instead of the
      // SINPE OCSP responder, which the browser blocks (mixed content + CORS).
      result = await checkRevocationViaResolver(crCa, cc.signer.serialNumber, this._lang)
    } else {
      result = await checkOcspOnline(
        cc.signer!.rawDerHex,
        cc.issuerDerHex!,
        cc.signerOcspUrl!,
        this._lang,
      )
    }

    this._onlineRev = new Map(this._onlineRev).set(cardIndex, { checking: false, result })
  }

  /**
   * The 1-based card indices whose signature is a CR Firma Digital SINPE cert
   * (the only path served by the resolver CRL, which one opt-in can batch).
   */
  private crRevocationIndices(): number[] {
    const sigs = this.result?.signatures ?? []
    const out: number[] = []
    sigs.forEach((sig, i) => {
      if (crSinpeCaFromIssuer(sig.certChain?.signer?.issuerCommonName) !== null) out.push(i + 1)
    })
    return out
  }

  /** How many DISTINCT CRLs a batch check would fetch (one per distinct CA). */
  private crDistinctCaCount(): number {
    const sigs = this.result?.signatures ?? []
    const cas = new Set<string>()
    for (const sig of sigs) {
      const ca = crSinpeCaFromIssuer(sig.certChain?.signer?.issuerCommonName)
      if (ca) cas.add(ca)
    }
    return cas.size
  }

  /** 1-based indices of CR cards that have not yet been checked or are mid-check. */
  private crUncheckedIndices(): number[] {
    return this.crRevocationIndices().filter((idx) => {
      const st = this._onlineRev.get(idx)
      return !st || (!st.checking && !st.result)
    })
  }

  /**
   * Run the resolver CRL revocation check for EVERY CR signature card. Same
   * explicit-action path as the per-card button — still user-triggered (from the
   * document-level control or the persisted auto preference), never a silent
   * fetch. Cards that share a CA reuse the single cached+deduped CRL, so N
   * same-CA cards cost one network round-trip at most.
   */
  private async runAllCrRevocation() {
    const indices = this.crUncheckedIndices()
    await Promise.all(indices.map((idx) => this.runOnlineRevocation(idx)))
  }

  /**
   * Document-level revocation control shown above the signature cards when the
   * document has CR Firma Digital signatures. Offers a single opt-in that checks
   * every CR card, honestly stating how many revocation lists it will fetch when
   * the document mixes CAs, plus the remembered auto-check preference.
   */
  private renderRevocationControls() {
    const total = this.crRevocationIndices().length
    if (total === 0) return ''
    const es = this._lang === 'es'
    const D = (en: string, str: string) => (es ? str : en)
    const distinctCas = this.crDistinctCaCount()
    const unchecked = this.crUncheckedIndices().length
    const anyChecking = this.crRevocationIndices().some((i) => this._onlineRev.get(i)?.checking)

    // Honest network cost: one CRL per distinct CA. If cards share a CA it is a
    // single fetch; a mixed-CA document fetches one list per CA.
    const fetchNote =
      distinctCas <= 1
        ? D(
            'Fetches one revocation list, reused across all cards.',
            'Descarga una lista de revocación, reutilizada en todas las tarjetas.',
          )
        : D(
            `Fetches ${distinctCas} revocation lists (one per certificate authority).`,
            `Descarga ${distinctCas} listas de revocación (una por autoridad certificadora).`,
          )

    const allBtnLabel =
      unchecked === total
        ? D(
            `Check revocation for all ${total} signatures`,
            `Revisar la revocación de las ${total} firmas`,
          )
        : unchecked > 0
          ? D(`Check the remaining ${unchecked}`, `Revisar las ${unchecked} restantes`)
          : D('All signatures checked', 'Todas las firmas revisadas')

    return html`
      <div class="revocation-controls" part="revocation-controls">
        <div class="revocation-controls-row">
          <button
            class="revocation-all-btn"
            ?disabled=${unchecked === 0 || anyChecking}
            @click=${() => this.runAllCrRevocation()}
          >
            🌐 ${anyChecking ? D('Checking…', 'Revisando…') : allBtnLabel}
          </button>
          <span class="revocation-fetch-note">${fetchNote}</span>
        </div>
        <label class="revocation-auto">
          <input
            type="checkbox"
            .checked=${this._autoRevocation}
            @change=${(e: Event) => this.toggleAutoRevocation((e.target as HTMLInputElement).checked)}
          />
          ${D('Check revocation automatically', 'Revisar la revocación automáticamente')}
        </label>
      </div>
    `
  }

  private renderHashMatch() {
    if (!this.result || !this.expectedHash) return ''
    const match = this.result.hash === this.expectedHash
    return html`
      <div class="hash-match ${match ? 'hash-match-ok' : 'hash-match-fail'}">
        <span class="hash-match-icon">${match ? '✓' : '✗'}</span>
        <div>
          <div class="hash-match-title">
            ${match ? t('comp.verify.docMatches') : t('comp.verify.docNoMatch')}
          </div>
          <div class="hash-match-detail">
            ${match ? t('comp.verify.matchDetail') : t('comp.verify.noMatchDetail')}
          </div>
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
    // The verifier only supports PDFs. Reject anything else up front with a
    // clear message instead of running a doomed signature parse.
    const isPdf = file.type === 'application/pdf' || /\.pdf$/i.test(file.name)
    if (!isPdf) {
      this._fileError = t('comp.verify.pdfOnly')
      this.verifying = false
      this.result = null
      return
    }
    this._fileError = null
    this.verifying = true
    this.verifyStep = t('comp.verify.readingFile')
    this.result = null
    this.pluginResults = null
    this._onlineRev = new Map()

    // Dispatch composed event (crosses shadow DOM for external listeners)
    this.dispatchEvent(
      new CustomEvent('verification-started', {
        detail: { fileName: file.name, fileSize: file.size },
        composed: true,
        bubbles: true,
      }),
    )

    try {
      this.verifyStep = t('comp.verify.computingHash')
      // Small delay to let the UI render the loading state
      await new Promise((r) => setTimeout(r, 50))

      // 1. Core integrity check (always runs — the "sandwich" base layer)
      this.result = await verifyPdf(file, (step, detail) => {
        if (step === 'loading-pdfjs') {
          this.verifyStep = detail || t('comp.verify.loadingPdf')
        } else if (step === 'pdfjs-ready') {
          this.verifyStep = t('comp.verify.extractingMeta')
        }
      })

      // Record verification timestamp
      this.verifiedAt = new Date().toLocaleTimeString(currentLang() === 'es' ? 'es-CR' : 'en-US', {
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit',
      })

      // Revocation is opt-in for ALL certs (CR included): the signature card
      // shows a "Check revocation online" control, plus a document-level control
      // that checks every CR card at once. By DEFAULT we do not auto-fetch the CR
      // CRL on verify — it is a network fetch without a user gesture. The ONLY
      // exception is when the user has explicitly turned on the remembered
      // "Check revocation automatically" preference (attestto:autoRevocation);
      // then we trigger the same batch check, reusing the browser-cached CRL.
      if (this._autoRevocation) {
        // Fire-and-forget: don't block the verify UI on the network round-trip.
        void this.runAllCrRevocation()
      }

      // 2. Run registered verifier plugins (can only ADD trust, never bypass core)
      const verifiers = attesttoPlugins.getByType('verifier')
      if (verifiers.length > 0) {
        this.pluginResults = await attesttoPlugins.runVerifiers(this.result.hash, {
          fileName: this.result.fileName,
          signatures: this.result.signatures,
        })
      }

      // ATT-361: derive locking state from signatures so the audit
      // badge panel knows when to flip EDITABLE → LOCKED and hide
      // CAN SIGN. A document is "locked" when at least one verified
      // signature with mode='final' (Attestto self-attested) or any
      // PAdES sig is present — modifying the bytes would break the
      // /ByteRange digest or the embedded documentHash.
      const sigList = this.result.signatures
      const hasPadesSig = sigList.some(
        (s) => s.subFilter !== null && !s.subFilter.startsWith('attestto.'),
      )
      const hasAttesttoFinal = sigList.some(
        (s) =>
          s.subFilter === 'attestto.self-attested.v1' &&
          s.attesttoMeta?.mode === 'final' &&
          (s.level === 'verified' || s.level === 'parsed'),
      )
      const documentLocked = hasPadesSig || hasAttesttoFinal

      // Overall verdict for the live-status chip on the landing page.
      // Honest: a tampered/unknown signature or active content is an issue;
      // "verified" requires at least one cryptographically verified signature.
      const anyBadSig = sigList.some((s) => s.level === 'tampered' || s.level === 'unknown')
      const hasActiveContent = !!(
        this.result.audit?.hasJavaScript || this.result.audit?.hasOpenAction
      )
      const issue = anyBadSig || hasActiveContent
      const verified = !issue && sigList.some((s) => s.level === 'verified')

      // Dispatch result event
      this.dispatchEvent(
        new CustomEvent('verification-complete', {
          detail: {
            hash: this.result.hash,
            signatures: this.result.signatures.length,
            plugins: this.pluginResults ? Object.fromEntries(this.pluginResults) : {},
            audit: this.result.audit ?? null,
            /** ATT-361 — true when any signature locks the document. */
            documentLocked,
            /** ATT-361 — true when the current sig set still allows another sig. */
            canCounterSign: !documentLocked && !this.result.audit?.encrypted,
            /** Landing live-status verdict: a real problem was detected. */
            issue,
            /** Landing live-status verdict: at least one verified signature, no issue. */
            verified,
          },
          composed: true,
          bubbles: true,
        }),
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
      setTimeout(() => {
        this.showCopied = false
      }, 1500)
    } catch {
      // Clipboard API not available
    }
  }

  private async copySummary() {
    if (!this.result) return
    const r = this.result
    const sigs = r.signatures
    const hasTampered = sigs.some((s) => s.level === 'tampered')
    const allVerified =
      sigs.length > 0 &&
      sigs.every((s) => s.level === 'verified' || s.level === 'trusted' || s.level === 'qualified')

    let verdict: string
    if (hasTampered) verdict = t('comp.verify.summary.tampered').toUpperCase()
    else if (allVerified) verdict = t('comp.verify.summary.verified').toUpperCase()
    else if (sigs.length > 0) verdict = t('comp.verify.summary.partial').toUpperCase()
    else verdict = t('comp.verify.summary.noSigs').toUpperCase()

    const signerNames = sigs.map((s) => s.name).filter(Boolean)
    const pkiNames = [...new Set(sigs.map((s) => s.certChain?.pki?.name).filter(Boolean))]
    const url = `${window.location.origin}${window.location.pathname}#sha256=${r.hash}`

    const lines = [
      `${verdict} — ${r.fileName}`,
      `SHA-256: ${r.hash}`,
      sigs.length > 0 ? `${sigs.length} ${t('comp.verify.summary.sigCount')}` : '',
      signerNames.length > 0 ? `Signers: ${signerNames.join(', ')}` : '',
      pkiNames.length > 0 ? `PKI: ${pkiNames.join(', ')}` : '',
      this.verifiedAt ? `${t('comp.verify.summary.verifiedAt')} ${this.verifiedAt}` : '',
      `${t('comp.verify.summary.verifiedVia')}`,
      url,
    ].filter(Boolean)

    try {
      await navigator.clipboard.writeText(lines.join('\n'))
      this.showSummaryCopied = true
      setTimeout(() => {
        this.showSummaryCopied = false
      }, 2000)
    } catch {
      // Clipboard not available
    }
  }

  private reset() {
    this._fileError = null
    this.result = null
    this.pluginResults = null
    this.verifiedAt = null
    this._onlineRev = new Map()
    // Clear expected hash and URL fragment on reset
    this.expectedHash = ''
    if (window.location.hash) history.replaceState(null, '', window.location.pathname)
  }

  private emitChallengeEvent(sigIndex: number, method: string, action: string) {
    this.dispatchEvent(
      new CustomEvent('identity-challenged', {
        detail: { signerIndex: sigIndex, method, action },
        composed: true,
        bubbles: true,
      }),
    )
  }

  /** Mask a national ID, preserving prefix and showing last 3 chars */
  private maskNationalId(id: string): string {
    const dashIdx = id.indexOf('-')
    if (dashIdx === -1 || dashIdx >= id.length - 4) return '•••••••'
    const prefix = id.slice(0, dashIdx + 1)
    const digits = id.slice(dashIdx + 1)
    if (digits.length <= 3) return `${prefix}${'•'.repeat(digits.length)}`
    const visible = digits.slice(-3)
    const hidden = '•'.repeat(digits.length - 3)
    return `${prefix}${hidden}${visible}`
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

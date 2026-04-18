import { LitElement, html, css } from 'lit'
import { customElement, property, state } from 'lit/decorators.js'
import { verifyPdf, type PdfVerificationResult } from '../composables/pdf-verifier.js'
import { attesttoPlugins, type VerificationResult } from '../plugins/registry.js'
import { sharedStyles } from '../styles/shared.js'
import { t, currentLang, type Lang } from '../i18n.js'

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
        0%, 100% { box-shadow: 0 0 0 0 rgba(220, 38, 38, 0.5); }
        50% { box-shadow: 0 0 0 6px rgba(220, 38, 38, 0); }
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
        gap: 0.75rem;
        margin-top: 0.75rem;
        padding: 1rem 1.25rem;
        border-radius: 10px;
        font-size: 1rem;
        background: var(--attestto-info-bg, #dbeafe);
        border: 1px solid var(--attestto-info, #2563eb);
      }

      .pki-badge .pki-flag {
        font-size: 2rem;
      }

      .pki-badge .pki-name {
        font-weight: 700;
        font-size: 1.15rem;
        color: var(--attestto-info, #2563eb);
      }

      .pki-badge .pki-type {
        font-size: 0.85rem;
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
      .revocation-unknown, .revocation-parse-error {
        background: var(--attestto-warning-bg, #fef3c7);
        color: var(--attestto-warning-text, #92400e);
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

      .id-challenge-confirm:hover { opacity: 0.85; }

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

      .id-cta a:hover { text-decoration: underline; }

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
        transition: opacity 0.15s ease, visibility 0.15s ease;
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

      .bean-1 { animation-delay: 0s; }
      .bean-2 { animation-delay: 0.16s; }
      .bean-3 { animation-delay: 0.32s; }

      @keyframes bean-bounce {
        0%, 80%, 100% {
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
        background: var(--attestto-primary-hover, #7B72ED);
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
    `,
  ]

  /** Pre-filled hash for deep-link mode (/d/{hash}) */
  @property({ type: String }) hash = ''
  /** Expected hash from a shared verification link (#sha256=...) */
  @property({ type: String, attribute: 'expected-hash' }) expectedHash = ''
  /** Whether the share link was just copied */
  @state() private showShareCopied = false

  @state() private dragging = false
  @state() private verifying = false
  @state() private verifyStep = ''
  @state() private result: PdfVerificationResult | null = null
  @state() private pluginResults: Map<string, VerificationResult> | null = null
  @state() private showCopied = false
  /** Tracks which signature indexes have had their national ID revealed */
  @state() private revealedIds = new Set<number>()
  /** Which signature index is showing the challenge panel */
  @state() private challengeTarget: number | null = null
  /** Challenge input value (email or national ID) */
  @state() private challengeInput = ''
  /** Challenge error message */
  @state() private challengeError = ''
  /** Which challenge method is active: 'email' | 'knowledge' | null */
  @state() private challengeMethod: 'email' | 'knowledge' | null = null
  @state() private _lang: Lang = currentLang()

  private _onLangChange = (e: Event) => {
    this._lang = (e as CustomEvent).detail.lang
  }

  override connectedCallback() {
    super.connectedCallback()
    window.addEventListener('attestto-lang-change', this._onLangChange)
  }

  override disconnectedCallback() {
    super.disconnectedCallback()
    window.removeEventListener('attestto-lang-change', this._onLangChange)
  }

  override render() {
    return html`
      ${this.verifying
        ? this.renderLoading()
        : this.result
          ? this.renderResult()
          : this.renderDropZone()}
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
          ${this.dragging
            ? t('comp.verify.dropFile')
            : hasExpected
              ? t('comp.verify.dropShared')
              : t('comp.verify.dropVerify')}
        </div>
        <div class="drop-zone-hint">
          ${hasExpected
            ? t('comp.verify.dropHintShared')
            : t('comp.verify.dropHint')}
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

          ${r.isPdf && r.metadata
            ? html`
                <div class="section-title">${t('comp.verify.metadata')}</div>
                <div class="meta-grid">
                  ${r.metadata.title
                    ? html`<span class="meta-label">${t('comp.verify.title')}</span><span>${r.metadata.title}</span>`
                    : ''}
                  ${r.metadata.author
                    ? html`<span class="meta-label">${t('comp.verify.author')}</span><span>${r.metadata.author}</span>`
                    : ''}
                  ${r.metadata.subject
                    ? html`<span class="meta-label">${t('comp.verify.subject')}</span><span>${r.metadata.subject}</span>`
                    : ''}
                  ${r.metadata.creator
                    ? html`<span class="meta-label">${t('comp.verify.creator')}</span><span>${r.metadata.creator}</span>`
                    : ''}
                  ${r.metadata.producer
                    ? html`<span class="meta-label">${t('comp.verify.producer')}</span><span>${r.metadata.producer}</span>`
                    : ''}
                  ${r.metadata.creationDate
                    ? html`<span class="meta-label">${t('comp.verify.created')}</span><span>${r.metadata.creationDate}</span>`
                    : ''}
                  ${r.metadata.modDate
                    ? html`<span class="meta-label">${t('comp.verify.modified')}</span><span>${r.metadata.modDate}</span>`
                    : ''}
                </div>
              `
            : ''}

          ${r.isPdf && r.signatures.length > 0
            ? html`
                <div class="section-title">${t('comp.verify.digitalSigs')}</div>
                ${r.signatures.map(
                  (sig) => html`
                    <div class="sig-card" part="sig-card">
                      <div class="sig-name">
                        <span
                          class="badge badge-${sig.level === 'tampered'
                            ? 'tampered'
                            : sig.level === 'verified'
                              ? 'verified'
                              : sig.level === 'unknown'
                                ? 'unknown'
                                : sig.certChain?.cryptographicallyVerified
                                  ? 'parsed'
                                  : 'detected'}"
                          part="status-badge trust-level"
                          title=${sig.level === 'tampered'
                            ? 'DOCUMENT TAMPERED — content was modified after signing'
                            : sig.level === 'verified'
                              ? 'Chain cryptographically verified AND document content matches signature'
                              : sig.level === 'unknown'
                                ? 'Integrity check could not run — verification incomplete (NOT a tamper signal)'
                                : sig.certChain?.cryptographicallyVerified
                                  ? 'Chain cryptographically verified — integrity not yet confirmed'
                                  : 'Structure parsed only — chain NOT cryptographically verified'}
                        >
                          ${sig.level === 'tampered'
                            ? '⚠ TAMPERED'
                            : sig.level === 'verified'
                              ? 'CRYPTOGRAPHICALLY VERIFIED'
                              : sig.level === 'unknown'
                                ? '◌ INTEGRITY UNKNOWN'
                                : sig.certChain?.cryptographicallyVerified
                                  ? 'CHAIN VERIFIED'
                                  : 'STRUCTURE PARSED'}
                        </span>
                        <span part="signer-name">${sig.name}</span>
                        ${sig.subFilter
                          ? html`<span class="sub-filter-tag has-tooltip tooltip-left">${sig.subFilter}${this.sigFormatTooltip(sig.subFilter) ? html`<span class="tooltip-text">${this.sigFormatTooltip(sig.subFilter)}</span>` : ''}</span>`
                          : ''}
                      </div>
                      ${sig.level === 'tampered'
                        ? html`
                            <div
                              class="integrity-tampered"
                              part="integrity-tampered"
                              style="background:#450a0a;border:2px solid #dc2626;color:#fecaca;
                                     padding:12px 14px;border-radius:6px;margin:8px 0;font-size:13px;
                                     line-height:1.5;font-weight:500;"
                            >
                              ⚠ <strong>DOCUMENT TAMPERED.</strong>
                              The bytes covered by this signature do not match the value the
                              signer signed. The PDF was modified after it was signed and
                              <strong>must not be trusted</strong>, even if the certificate
                              chain itself is valid.
                              ${sig.integrityError
                                ? html`<div style="margin-top:6px;font-size:12px;opacity:0.85;">
                                    Reason: ${sig.integrityError}
                                  </div>`
                                : ''}
                            </div>
                          `
                        : ''}
                      ${sig.level === 'unknown'
                        ? html`
                            <div
                              class="integrity-unknown"
                              part="integrity-unknown"
                              style="background:#3a2f00;border:1px solid #d4a017;color:#ffe48a;
                                     padding:12px 14px;border-radius:6px;margin:8px 0;font-size:13px;
                                     line-height:1.5;font-weight:500;"
                            >
                              ◌ <strong>Integrity check could not be completed.</strong>
                              The verifier was unable to run the cryptographic
                              integrity check on this signature (loader, parser
                              or runtime error). This is <strong>not</strong> a
                              tamper signal — the document state is unknown.
                              Please retry, hard-reload, or report the issue
                              with the reason below.
                              ${sig.integrityError
                                ? html`<div style="margin-top:6px;font-size:12px;opacity:0.85;font-family:monospace;word-break:break-all;">
                                    Reason: ${sig.integrityError}
                                  </div>`
                                : ''}
                            </div>
                          `
                        : ''}
                      ${sig.certChain && !sig.certChain.cryptographicallyVerified && sig.level !== 'tampered' && sig.level !== 'unknown'
                        ? html`
                            <div
                              class="crypto-warning"
                              part="crypto-warning"
                              style="background:#3a1f00;border:1px solid #ff9500;color:#ffb84d;
                                     padding:10px 12px;border-radius:6px;margin:8px 0;font-size:13px;
                                     line-height:1.45;"
                            >
                              ⚠
                              <strong>Structure parsed only.</strong>
                              ${sig.certChain.cryptoVerificationWarning ||
                              'The certificate chain has not been cryptographically verified.'}
                            </div>
                          `
                        : ''}
                      ${sig.level === 'verified' && sig.subFilter === 'attestto.self-attested.v1'
                        ? html`
                            <div
                              class="crypto-verified"
                              part="crypto-verified"
                              style="background:#0a2818;border:1px solid #00c853;color:#69f0ae;
                                     padding:10px 12px;border-radius:6px;margin:8px 0;font-size:13px;
                                     line-height:1.45;"
                            >
                              ✓
                              <strong>${t('comp.verify.attestto.verified')}</strong>
                              ${t('comp.verify.attestto.verifiedBody')}
                            </div>
                          `
                        : sig.level === 'verified'
                          ? html`
                              <div
                                class="crypto-verified"
                                part="crypto-verified"
                                style="background:#0a2818;border:1px solid #00c853;color:#69f0ae;
                                       padding:10px 12px;border-radius:6px;margin:8px 0;font-size:13px;
                                       line-height:1.45;"
                              >
                                ✓
                                <strong>Cryptographically verified.</strong>
                                The certificate chain has been validated end-to-end against a
                                bundled trust anchor, AND the document content matches the
                                signed hash exactly. The signer's identity is cryptographically
                                proven and the document is intact.
                              </div>
                            `
                          : ''}

                      ${sig.attesttoMeta && sig.subFilter === 'attestto.self-attested.v1'
                        ? html`
                            <div
                              class="attestto-provenance"
                              part="attestto-provenance"
                              style="background:#0d1f24;border:1px solid #1f4855;border-radius:6px;
                                     padding:10px 12px;margin:8px 0;font-size:12px;line-height:1.5;
                                     color:#9fcfd9;"
                            >
                              <div style="display:flex;align-items:center;gap:8px;margin-bottom:6px;font-weight:600;color:#cfe9ef;">
                                ${sig.attesttoMeta.country
                                  ? html`<span style="font-size:16px;">${this.countryFlag(sig.attesttoMeta.country)}</span>`
                                  : ''}
                                <span>${t('comp.verify.attestto.title')}</span>
                              </div>
                              ${sig.attesttoMeta.country === 'CR'
                                ? html`<div style="margin:4px 0;">
                                    <strong style="color:#cfe9ef;">${t('comp.verify.attestto.kycSource')}:</strong>
                                    ${t('comp.verify.attestto.padronCR')}
                                  </div>`
                                : ''}
                              <div style="margin:4px 0;">
                                <strong style="color:#cfe9ef;">${t('comp.verify.attestto.proofType')}:</strong>
                                VC · ${sig.attesttoMeta.proofType}
                              </div>
                              <div style="margin:4px 0;">
                                ${sig.attesttoMeta.mode === 'final'
                                  ? html`<span style="color:#69f0ae;">🔒 ${t('comp.verify.attestto.modeFinal')}</span>`
                                  : html`<span style="color:#ffb84d;">${t('comp.verify.attestto.modeOpen')}</span>`}
                              </div>
                              ${sig.attesttoMeta.mock
                                ? html`<div style="margin-top:6px;padding:6px 8px;background:#3a1f00;border:1px solid #ff9500;border-radius:4px;color:#ffb84d;">
                                    ⚠ ${t('comp.verify.attestto.demoWarning')}
                                  </div>`
                                : ''}
                            </div>
                          `
                        : ''}

                      ${sig.did
                        ? html`<div
                            class="signer-did"
                            part="did-link"
                            title="${t('comp.verify.decentralizedId')}"
                          >
                            ${sig.did}
                          </div>`
                        : ''}
                      ${sig.lei
                        ? html`
                            <div class="corporate-row" part="vlei-badge">
                              <span class="gleif-icon">GLEIF</span>
                              <span
                                >${sig.organization ?? t('comp.verify.organization')} &middot; LEI:
                                ${sig.lei}</span
                              >
                            </div>
                          `
                        : sig.organization
                          ? html`
                              <div class="corporate-row" part="corporate-info">
                                <span>${sig.organization}</span>
                              </div>
                            `
                          : ''}

                      <div class="level-hint" part="trust-level">${this.levelHint(sig.level)}</div>

                      ${sig.certChain?.pki
                        ? html`
                            <div class="pki-badge" part="pki-badge">
                              <span class="pki-flag">${this.countryFlag(sig.certChain.pki.country)}</span>
                              <span class="pki-name">${sig.certChain.pki.name}</span>
                              ${sig.certChain.pki.certificateType
                                ? html`<span class="pki-type">${sig.certChain.pki.certificateType}</span>`
                                : ''}
                            </div>
                          `
                        : ''}
                      ${sig.certChain?.nationalId
                        ? this.renderIdentityChallenge(sig.certChain, r.signatures.indexOf(sig))
                        : ''}
                      ${(sig.certChain?.keyUsage?.length || sig.certChain?.extKeyUsage?.length)
                        ? html`
                            <div class="trust-permissions">
                              <div class="section-title-row has-tooltip">
                                <div class="cert-chain-title">${t('comp.verify.trustPermissions')}</div>
                                <span class="info-icon">?</span>
                                <span class="tooltip-text">${t('comp.verify.trustPermissions.tooltip')}</span>
                              </div>
                              <div class="permission-grid">
                                ${(sig.certChain.keyUsage ?? []).map(
                                  (ku) => html`<span class="permission-badge permission-key has-tooltip">${ku}${this.kuTooltip(ku) ? html`<span class="tooltip-text">${this.kuTooltip(ku)}</span>` : ''}</span>`,
                                )}
                                ${(sig.certChain.extKeyUsage ?? []).map(
                                  (eku) => html`<span class="permission-badge permission-ext has-tooltip">${eku}${this.ekuTooltip(eku) ? html`<span class="tooltip-text">${this.ekuTooltip(eku)}</span>` : ''}</span>`,
                                )}
                              </div>
                            </div>
                          `
                        : ''}
                      ${sig.certChain && sig.certChain.chain.length > 0
                        ? html`
                            <div class="cert-chain" part="cert-chain">
                              <div class="section-title-row has-tooltip">
                                <div class="cert-chain-title">${t('comp.verify.certChain')}</div>
                                <span class="info-icon">?</span>
                                <span class="tooltip-text">${t('comp.verify.certChain.tooltip')}</span>
                              </div>
                              ${sig.certChain.chain.slice().reverse().map(
                                (cert, i) => html`
                                  <div class="cert-node" style="--depth: ${i}">
                                    <span class="cert-icon">${cert.role === 'root'
                                      ? '\u{1F3DB}'
                                      : cert.role === 'intermediate'
                                        ? '\u{1F517}'
                                        : '\u{270D}'}</span>
                                    <div class="cert-details">
                                      <div class="cert-cn">${cert.commonName}</div>
                                      ${cert.organization
                                        ? html`<div class="cert-org">${cert.organization}</div>`
                                        : ''}
                                      <div class="cert-meta">
                                        ${cert.validFrom && cert.validTo
                                          ? html`<span class="${cert.validTo && new Date(cert.validTo) < new Date() ? 'cert-expired' : ''}">${cert.validFrom.split('T')[0]} — ${cert.validTo.split('T')[0]}${cert.validTo && new Date(cert.validTo) < new Date() ? ' (EXPIRADO)' : ''}</span>`
                                          : ''}
                                        ${cert.country
                                          ? html`<span>${cert.country}</span>`
                                          : ''}
                                      </div>
                                    </div>
                                  </div>
                                `,
                              )}
                            </div>
                          `
                        : ''}

                      ${sig.revocationStatus && sig.revocationStatus !== 'no-data'
                        ? html`
                            <div class="revocation-status revocation-${sig.revocationStatus}" part="revocation-status">
                              <span class="revocation-icon">${sig.revocationStatus === 'good' ? '\u2705' : sig.revocationStatus === 'revoked' ? '\u274C' : '\u26A0'}</span>
                              <span>${sig.revocationMessage ?? sig.revocationStatus}</span>
                            </div>
                          `
                        : ''}

                      ${sig.certChain?.signer?.validTo && new Date(sig.certChain.signer.validTo) < new Date()
                        ? html`
                            <div class="expiry-warning" part="expiry-warning">
                              <span class="expiry-icon">\u23F0</span>
                              <span>Certificado del firmante expirado el ${sig.certChain.signer.validTo.split('T')[0]}. La firma fue valida al momento de firmar.</span>
                            </div>
                          `
                        : ''}

                      ${sig.pkcs7Hex
                        ? html`
                            <div class="pkcs7-surface" part="pkcs7-hex">
                              <button class="pkcs7-copy-btn" @click=${() => this.copyPkcs7(sig.pkcs7Hex!)}>
                                ${t('comp.verify.copyPkcs7') ?? 'Copiar PKCS#7'}
                              </button>
                              <span class="pkcs7-size">${Math.round(sig.pkcs7Hex.length / 2).toLocaleString()} bytes</span>
                            </div>
                          `
                        : ''}

                      <div class="meta-grid">
                        ${sig.reason
                          ? html`<span class="meta-label">${t('comp.verify.reason')}</span><span>${sig.reason}</span>`
                          : ''}
                        ${sig.location
                          ? html`<span class="meta-label">${t('comp.verify.location')}</span
                              ><span>${sig.location}</span>`
                          : ''}
                        ${sig.contactInfo
                          ? html`<span class="meta-label">${t('comp.verify.contact')}</span
                              ><span>${sig.contactInfo}</span>`
                          : ''}
                        ${sig.signDate
                          ? html`<span class="meta-label">${t('comp.verify.signed')}</span><span>${sig.signDate}</span>`
                          : ''}
                      </div>
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
              : ''}
          </div>
          ${this.pluginResults && this.pluginResults.size > 0
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
                        ${result.error
                          ? html`<div
                              style="color: var(--attestto-warning, #d97706); font-size: 0.85rem; margin-top: 0.5rem"
                            >
                              ${result.error}
                            </div>`
                          : ''}
                      </div>
                    `,
                  )}
                </div>
              `
            : ''}
        </div>

        ${this.expectedHash ? this.renderHashMatch() : ''}

        <div class="share-actions">
          <button class="share-btn" @click=${this.shareVerification} title="${t('comp.verify.shareLink')}">
            ${this.showShareCopied ? t('comp.verify.shareLinkCopied') : t('comp.verify.shareLink')}
          </button>
          <button class="reset-btn" @click=${this.reset}>
            ${t('comp.verify.verifyAnother')}
          </button>
        </div>

        ${this.result && !this.expectedHash ? html`
          <div class="share-hint">
            ${t('comp.verify.shareHint')}
          </div>
        ` : ''}
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
            ${match
              ? t('comp.verify.matchDetail')
              : t('comp.verify.noMatchDetail')}
          </div>
          ${match ? html`
            <a href="/sign/" class="hash-match-cta">${t('comp.verify.signYourOwn')} →</a>
          ` : ''}
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
    this.verifyStep = t('comp.verify.readingFile')
    this.result = null
    this.pluginResults = null

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

  private async shareVerification() {
    if (!this.result?.hash) return
    const url = `${window.location.origin}${window.location.pathname}#sha256=${this.result.hash}`
    const shareData = {
      title: t('comp.verify.shareTitle'),
      text: t('comp.verify.shareText'),
      url,
    }

    // Try native share (mobile), fall back to clipboard
    if (typeof navigator.share === 'function') {
      try {
        await navigator.share(shareData)
        return
      } catch {
        // User cancelled or share failed — fall through to clipboard
      }
    }

    try {
      await navigator.clipboard.writeText(url)
      this.showShareCopied = true
      setTimeout(() => { this.showShareCopied = false }, 2000)
    } catch {
      // Clipboard not available
    }
  }

  private reset() {
    this.result = null
    this.pluginResults = null
    this.revealedIds = new Set()
    this.challengeTarget = null
    this.challengeInput = ''
    this.challengeError = ''
    this.challengeMethod = null
    // Clear expected hash and URL fragment on reset
    this.expectedHash = ''
    if (window.location.hash) history.replaceState(null, '', window.location.pathname)
  }

  // ── Identity Challenge (tiered reveal) ─────────────────────────────

  private renderIdentityChallenge(certChain: { nationalId: string | null; signerEmail: string | null }, sigIndex: number) {
    const nationalId = certChain.nationalId!
    const hasEmail = !!certChain.signerEmail

    // Already revealed
    if (this.revealedIds.has(sigIndex)) {
      return html`
        <div class="meta-grid" style="margin-top: 0.5rem;">
          <span class="meta-label">${t('comp.verify.nationalId')}</span>
          <span class="id-revealed">${nationalId}</span>
        </div>
        <div class="id-cta">
          ${t('comp.verify.protectIdentity')} — <a href="https://attestto.com/id" target="_blank">${t('comp.verify.getAttesttoId')}</a>
        </div>
      `
    }

    const masked = this.maskNationalId(nationalId)

    // Challenge panel is open
    if (this.challengeTarget === sigIndex) {
      // Method selection
      if (!this.challengeMethod) {
        return html`
          <div class="id-challenge">
            <p>${t('comp.verify.proveRelationship')}</p>
            <div class="id-challenge-options">
              ${hasEmail
                ? html`<button class="id-option-btn" @click=${() => { this.challengeMethod = 'email' }}>
                    <span class="id-option-icon">✉</span>
                    <span>${t('comp.verify.iAmSigner')}</span>
                    <span class="id-option-hint">${t('comp.verify.verifyEmail')}</span>
                  </button>`
                : ''}
              <button class="id-option-btn" @click=${() => { this.challengeMethod = 'knowledge' }}>
                <span class="id-option-icon">🔑</span>
                <span>${t('comp.verify.iKnowSigner')}</span>
                <span class="id-option-hint">${t('comp.verify.enterNationalId')}</span>
              </button>
            </div>
            <button class="id-challenge-cancel" @click=${() => this.dismissChallenge()}>${t('comp.verify.cancel')}</button>
          </div>
        `
      }

      // Tier 1: Email challenge
      if (this.challengeMethod === 'email') {
        return html`
          <div class="id-challenge">
            <p>${t('comp.verify.enterEmailPrompt')}</p>
            <div class="id-challenge-input-row">
              <input
                type="email"
                class="id-challenge-input"
                placeholder="your@email.com"
                .value=${this.challengeInput}
                @input=${(e: Event) => { this.challengeInput = (e.target as HTMLInputElement).value; this.challengeError = '' }}
                @keydown=${(e: KeyboardEvent) => { if (e.key === 'Enter') this.verifyEmail(sigIndex, certChain.signerEmail!) }}
              />
              <button class="id-challenge-confirm" @click=${() => this.verifyEmail(sigIndex, certChain.signerEmail!)}>${t('comp.verify.verify')}</button>
            </div>
            ${this.challengeError ? html`<p class="id-challenge-error">${this.challengeError}</p>` : ''}
            <button class="id-challenge-cancel" @click=${() => this.dismissChallenge()}>${t('comp.verify.back')}</button>
          </div>
        `
      }

      // Tier 2: Knowledge challenge
      if (this.challengeMethod === 'knowledge') {
        const prefix = nationalId.includes('-') ? nationalId.split('-')[0] : ''
        return html`
          <div class="id-challenge">
            <p>${t('comp.verify.enterIdPrompt')}</p>
            <div class="id-challenge-input-row">
              <input
                type="text"
                class="id-challenge-input"
                placeholder="${prefix ? `${prefix}-...` : t('comp.verify.fullNationalId')}"
                .value=${this.challengeInput}
                @input=${(e: Event) => { this.challengeInput = (e.target as HTMLInputElement).value; this.challengeError = '' }}
                @keydown=${(e: KeyboardEvent) => { if (e.key === 'Enter') this.verifyKnowledge(sigIndex, nationalId) }}
              />
              <button class="id-challenge-confirm" @click=${() => this.verifyKnowledge(sigIndex, nationalId)}>${t('comp.verify.confirm')}</button>
            </div>
            ${this.challengeError ? html`<p class="id-challenge-error">${this.challengeError}</p>` : ''}
            <button class="id-challenge-cancel" @click=${() => this.dismissChallenge()}>${t('comp.verify.back')}</button>
          </div>
        `
      }
    }

    // Default: masked with reveal button
    return html`
      <div class="id-masked">
        <span class="meta-label">${t('comp.verify.nationalId')}</span>
        <span class="id-masked-value">${masked}</span>
        <button class="id-reveal-btn" @click=${() => { this.challengeTarget = sigIndex; this.challengeMethod = null; this.challengeInput = ''; this.challengeError = '' }}>
          ${t('comp.verify.reveal')}
        </button>
      </div>
    `
  }

  private dismissChallenge() {
    this.challengeTarget = null
    this.challengeMethod = null
    this.challengeInput = ''
    this.challengeError = ''
  }

  /** Tier 1: Verify email matches signer cert */
  private verifyEmail(sigIndex: number, certEmail: string) {
    const input = this.challengeInput.trim().toLowerCase()
    if (!input) { this.challengeError = t('comp.verify.enterEmail'); return }
    if (input !== certEmail.toLowerCase()) {
      this.challengeError = t('comp.verify.emailNoMatch')
      this.emitChallengeEvent(sigIndex, 'email', 'failed')
      return
    }
    this.revealIdentity(sigIndex, 'email')
  }

  /** Tier 2: Verify national ID matches cert */
  private verifyKnowledge(sigIndex: number, nationalId: string) {
    const input = this.challengeInput.trim()
    if (!input) { this.challengeError = t('comp.verify.enterId'); return }
    if (input !== nationalId) {
      this.challengeError = t('comp.verify.idNoMatch')
      this.emitChallengeEvent(sigIndex, 'knowledge', 'failed')
      return
    }
    this.revealIdentity(sigIndex, 'knowledge')
  }

  /** Common reveal logic for all tiers */
  private revealIdentity(sigIndex: number, method: 'email' | 'knowledge') {
    const updated = new Set(this.revealedIds)
    updated.add(sigIndex)
    this.revealedIds = updated
    this.dismissChallenge()
    this.emitChallengeEvent(sigIndex, method, 'revealed')
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

  private badgeLabel(level: string): string {
    return t(`comp.verify.badge.${level}`) || t('comp.verify.badge.unknown')
  }

  private levelHint(level: string): string {
    return t(`comp.verify.hint.${level}`) || ''
  }

  /** Convert ISO 3166-1 alpha-2 country code to flag emoji */
  /** Map Key Usage label → i18n tooltip key */
  private kuTooltip(label: string): string {
    const map: Record<string, string> = {
      'Digital Signature': 'comp.verify.ku.digitalSignature',
      'Non-Repudiation': 'comp.verify.ku.nonRepudiation',
      'Key Encipherment': 'comp.verify.ku.keyEncipherment',
      'Data Encipherment': 'comp.verify.ku.dataEncipherment',
      'Key Agreement': 'comp.verify.ku.keyAgreement',
      'Certificate Signing': 'comp.verify.ku.certificateSigning',
      'CRL Signing': 'comp.verify.ku.crlSigning',
      'Encipher Only': 'comp.verify.ku.encipherOnly',
      'Decipher Only': 'comp.verify.ku.decipherOnly',
    }
    return map[label] ? t(map[label]) : ''
  }

  /** Map Extended Key Usage label → i18n tooltip key */
  private ekuTooltip(label: string): string {
    const map: Record<string, string> = {
      'Server Authentication': 'comp.verify.eku.serverAuth',
      'Client Authentication': 'comp.verify.eku.clientAuth',
      'Code Signing': 'comp.verify.eku.codeSigning',
      'Email Protection': 'comp.verify.eku.emailProtection',
      'Time Stamping': 'comp.verify.eku.timeStamping',
      'OCSP Signing': 'comp.verify.eku.ocspSigning',
      'Document Signing': 'comp.verify.eku.documentSigning',
      'Smart Card Login': 'comp.verify.eku.smartCardLogin',
    }
    return map[label] ? t(map[label]) : ''
  }

  /** Tooltip for signature format (subFilter) */
  private sigFormatTooltip(subFilter: string): string {
    const key = `comp.verify.sigFormat.tooltip.${subFilter}`
    const val = t(key)
    return val !== key ? val : ''
  }

  private countryFlag(code: string): string {
    if (!code || code.length !== 2) return '\u{1F310}' // globe
    const upper = code.toUpperCase()
    return String.fromCodePoint(
      0x1f1e6 + upper.charCodeAt(0) - 65,
      0x1f1e6 + upper.charCodeAt(1) - 65,
    )
  }

  private async copyPkcs7(hex: string): Promise<void> {
    try {
      await navigator.clipboard.writeText(hex)
    } catch {
      // Fallback for non-secure contexts
      const ta = document.createElement('textarea')
      ta.value = hex
      ta.style.position = 'fixed'
      ta.style.opacity = '0'
      document.body.appendChild(ta)
      ta.select()
      document.execCommand('copy')
      document.body.removeChild(ta)
    }
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

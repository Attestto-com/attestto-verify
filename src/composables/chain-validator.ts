/**
 * Cryptographic Certificate Chain Validator
 *
 * Real PKI chain validation against bundled trust anchors. Uses pkijs +
 * WebCrypto in the browser. NO network calls. NO backend.
 *
 * This is the v2 implementation that closes the 2026-04-07 disclosure: until
 * this file existed, `certificate-parser.ts` did ASN.1 structure parsing only
 * and `attestto-verify.ts` claimed cryptographic trust based on root CA name
 * string matching. Anyone could forge a PDF with the right CN and pass.
 *
 * Now: signer cert → intermediate(s) → root, walked via
 * `pkijs.CertificateChainValidationEngine`. Root must match a bundled BCCR
 * anchor by full DER bytes (fingerprint pin). Anything else returns
 * `cryptographicallyVerified: false`.
 *
 * Source: docs/v2-pkijs-implementation-guide.md (ATT-209)
 */

import { logger } from '../logger.js'

// Trust anchors are imported as raw PEM strings via Vite's `?raw` loader.
// They are bundled into the dist at build time — zero runtime fetches.
import RAIZ_NACIONAL_PEM from '../trust-store/bccr/CA_RAIZ_NACIONAL_-_COSTA_RICA_v2.pem?raw'
import POLITICA_PJ_PEM from '../trust-store/bccr/CA_POLITICA_PERSONA_JURIDICA_-_COSTA_RICA_v2.pem?raw'
import SINPE_PJ_PEM from '../trust-store/bccr/CA_SINPE_-_PERSONA_JURIDICA_v2.pem?raw'

const log = logger.verify

// ── Types ─────────────────────────────────────────────────────────

export interface ChainValidationResult {
  /** True if the chain walks to a bundled trust anchor with valid signatures at every step. */
  trusted: boolean
  /** Trust anchor that terminated the chain (CN), if any. */
  anchorCommonName: string | null
  /** Reason the chain failed to validate, if `trusted === false`. */
  error: string | null
  /** Length of the validated chain (signer → … → root), 0 if not trusted. */
  chainLength: number
}

// ── PEM ↔ DER Helpers ─────────────────────────────────────────────

function pemToDer(pem: string): ArrayBuffer {
  const b64 = pem
    .replace(/-----BEGIN CERTIFICATE-----/g, '')
    .replace(/-----END CERTIFICATE-----/g, '')
    .replace(/\s+/g, '')
  const binary = atob(b64)
  const bytes = new Uint8Array(binary.length)
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i)
  return bytes.buffer
}

function hexToArrayBuffer(hex: string): ArrayBuffer {
  const clean = hex.replace(/\s+/g, '')
  const bytes = new Uint8Array(clean.length / 2)
  for (let i = 0; i < clean.length; i += 2) {
    bytes[i / 2] = parseInt(clean.substring(i, i + 2), 16)
  }
  return bytes.buffer
}

// ── Lazy pkijs Loader ─────────────────────────────────────────────

// pkijs is heavy (~250 KB gzipped). Lazy-load on first verification call.
let pkijsCache: typeof import('pkijs') | null = null
let asn1jsCache: typeof import('asn1js') | null = null

async function loadPkijs(): Promise<{
  pkijs: typeof import('pkijs')
  asn1js: typeof import('asn1js')
}> {
  if (pkijsCache && asn1jsCache) return { pkijs: pkijsCache, asn1js: asn1jsCache }

  log.info('[chain-validator] Lazy-loading pkijs + asn1js')
  const [pkijs, asn1js] = await Promise.all([import('pkijs'), import('asn1js')])

  // pkijs needs a WebCrypto engine. Browser provides crypto.subtle natively.
  if (typeof crypto !== 'undefined' && crypto.subtle) {
    pkijs.setEngine(
      'webcrypto',
      new pkijs.CryptoEngine({ name: 'webcrypto', crypto, subtle: crypto.subtle }),
    )
  }

  pkijsCache = pkijs
  asn1jsCache = asn1js
  return { pkijs, asn1js }
}

// ── Trust Anchor Loading ──────────────────────────────────────────

interface LoadedAnchor {
  cert: import('pkijs').Certificate
  commonName: string
}

let anchorsCache: LoadedAnchor[] | null = null

async function loadTrustAnchors(): Promise<LoadedAnchor[]> {
  if (anchorsCache) return anchorsCache

  const { pkijs, asn1js } = await loadPkijs()

  const pems: Array<{ pem: string; label: string }> = [
    { pem: RAIZ_NACIONAL_PEM, label: 'CA RAIZ NACIONAL - COSTA RICA v2' },
    { pem: POLITICA_PJ_PEM, label: 'CA POLITICA PERSONA JURIDICA - COSTA RICA v2' },
    { pem: SINPE_PJ_PEM, label: 'CA SINPE - PERSONA JURIDICA v2' },
  ]

  const loaded: LoadedAnchor[] = []
  for (const { pem, label } of pems) {
    try {
      const der = pemToDer(pem)
      const asn1 = asn1js.fromBER(der)
      if (asn1.offset === -1) {
        log.warn(`[chain-validator] Failed to parse anchor ASN.1: ${label}`)
        continue
      }
      const cert = new pkijs.Certificate({ schema: asn1.result })
      const cnAttr = cert.subject.typesAndValues.find((t) => t.type === '2.5.4.3')
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const cn = ((cnAttr?.value as any)?.valueBlock?.value as string) || label
      loaded.push({ cert, commonName: cn })
      log.info(`[chain-validator] Loaded trust anchor: ${cn}`)
    } catch (err) {
      log.warn(`[chain-validator] Trust anchor load failed (${label}): ${err}`)
    }
  }

  if (loaded.length === 0) {
    log.warn('[chain-validator] No trust anchors loaded — all chains will fail validation')
  }

  anchorsCache = loaded
  return loaded
}

// ── Public API ────────────────────────────────────────────────────

/**
 * Validate a certificate chain against bundled BCCR trust anchors.
 *
 * @param signerCertHex DER bytes of the signer (end-entity) certificate, as hex string.
 * @param intermediateCertsHex DER bytes of intermediate certificates from the PDF, as hex strings.
 */
export async function validateChain(
  signerCertHex: string,
  intermediateCertsHex: string[],
): Promise<ChainValidationResult> {
  try {
    const { pkijs, asn1js } = await loadPkijs()
    const anchors = await loadTrustAnchors()

    if (anchors.length === 0) {
      return {
        trusted: false,
        anchorCommonName: null,
        error: 'No trust anchors bundled',
        chainLength: 0,
      }
    }

    // Parse signer
    const signerDer = hexToArrayBuffer(signerCertHex)
    const signerAsn1 = asn1js.fromBER(signerDer)
    if (signerAsn1.offset === -1) {
      return {
        trusted: false,
        anchorCommonName: null,
        error: 'Signer certificate ASN.1 parse failed',
        chainLength: 0,
      }
    }
    const signerCert = new pkijs.Certificate({ schema: signerAsn1.result })

    // Parse intermediates
    const intermediates: import('pkijs').Certificate[] = []
    for (const hex of intermediateCertsHex) {
      try {
        const der = hexToArrayBuffer(hex)
        const asn1 = asn1js.fromBER(der)
        if (asn1.offset === -1) continue
        intermediates.push(new pkijs.Certificate({ schema: asn1.result }))
      } catch {
        // skip malformed
      }
    }

    // Build the chain validation engine
    // - trustedCerts: our bundled anchors (the only certs we will accept as roots)
    // - certs: candidate intermediates from the PDF + the signer
    const engine = new pkijs.CertificateChainValidationEngine({
      trustedCerts: anchors.map((a) => a.cert),
      certs: [signerCert, ...intermediates],
    })

    const result = await engine.verify()

    if (!result.result) {
      return {
        trusted: false,
        anchorCommonName: null,
        error: result.resultMessage || 'Chain validation failed',
        chainLength: 0,
      }
    }

    // Identify which anchor terminated the chain
    const builtChain = result.certificatePath || []
    const root = builtChain[builtChain.length - 1]
    let anchorCn: string | null = null
    if (root) {
      const cnAttr = root.subject.typesAndValues.find((t) => t.type === '2.5.4.3')
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      anchorCn = ((cnAttr?.value as any)?.valueBlock?.value as string) || null
    }

    log.event(
      `[chain-validator] ✓ Chain VERIFIED — anchor: ${anchorCn}, length: ${builtChain.length}`,
    )

    return {
      trusted: true,
      anchorCommonName: anchorCn,
      error: null,
      chainLength: builtChain.length,
    }
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err)
    log.warn(`[chain-validator] Chain validation threw: ${message}`)
    return {
      trusted: false,
      anchorCommonName: null,
      error: message,
      chainLength: 0,
    }
  }
}

/**
 * Test-only: clear caches so reload tests work.
 * @internal
 */
export function _resetChainValidatorCache(): void {
  pkijsCache = null
  asn1jsCache = null
  anchorsCache = null
}

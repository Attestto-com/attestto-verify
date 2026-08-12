/**
 * Cryptographic Certificate Chain Validator
 *
 * Real PKI chain validation using pkijs + WebCrypto in the browser. Trust
 * anchors are resolved ON DEMAND via did:pki at resolver.attestto.com — this
 * file bundles NO national PKI certificates. The resolver returns key
 * FINGERPRINTS; we match the PDF's own embedded intermediate/CA certs against
 * those fingerprints and use the matched cert as the pkijs trust anchor.
 *
 * This is the v2 implementation that closes the 2026-04-07 disclosure: until
 * this file existed, `certificate-parser.ts` did ASN.1 structure parsing only
 * and `attestto-verify.ts` claimed cryptographic trust based on root CA name
 * string matching. Anyone could forge a PDF with the right CN and pass.
 *
 * Now: signer cert → intermediate(s) → resolver-verified anchor, walked via
 * `pkijs.CertificateChainValidationEngine`. The anchor must be an embedded CA
 * cert whose key fingerprint matches what the resolver publishes for the
 * issuing did:pki. If the resolver does not resolve or no embedded cert
 * matches, the result is `trusted: false` — the structure is parsed but the
 * chain is not linked to a resolver-verified anchor.
 *
 * The ONLY trust-related network call the verify FE makes is this resolver
 * lookup; the opt-in revocation-list fetch lives in resolver-revocation.ts.
 *
 * Source: docs/v2-pkijs-implementation-guide.md (ATT-209 / ATT-438)
 */

import { logger } from '../logger.js'
import { resolveAndMatchChain, type PkiResolverOptions } from './pki-resolver.js'

const log = logger.verify

// ── Types ─────────────────────────────────────────────────────────

/**
 * A certificate on the validated path, as produced by pkijs's
 * `CertificateChainValidationEngine`. This is `CertificateInfo`-compatible
 * data for the certs the engine actually used to reach the trust anchor,
 * ordered signer → … → root. It lets the UI display the FULL validated chain
 * even when the PDF embedded only the signer leaf: the missing intermediates
 * and root are supplied here from the bundled trust store.
 */
export interface ResolvedChainCert {
  /** Subject Common Name */
  commonName: string
  /** Issuer Common Name */
  issuerCommonName: string
  /** Serial number (hex, uppercase) — used for dedupe against embedded certs */
  serialNumber: string
  /** Validity — not before (ISO) */
  validFrom: string | null
  /** Validity — not after (ISO) */
  validTo: string | null
  /** Subject Country (C) */
  country: string | null
  /** Position in chain */
  role: 'end-entity' | 'intermediate' | 'root'
  /** Raw DER bytes (hex, lowercase) — canonical identity for dedupe */
  rawDerHex: string
}

export interface ChainValidationResult {
  /**
   * True if the chain walks to a resolver-verified trust anchor with valid
   * signatures at every step.
   */
  trusted: boolean
  /** Trust anchor that terminated the chain (CN), if any. */
  anchorCommonName: string | null
  /** Reason the chain failed to validate, if `trusted === false`. */
  error: string | null
  /** Length of the validated chain (signer → … → root), 0 if not trusted. */
  chainLength: number
  /** How trust was established. Always 'resolver' (resolver.attestto.com) when trusted. */
  trustSource?: 'resolver'
  /** The did:pki that was resolved, if trust came from resolver */
  pkiDid?: string
  /** End-entity hints from the DID Document — how to extract signer identity per cert type */
  endEntityHints?: Record<string, import('./pki-resolver.js').EndEntityHint> | null
  /**
   * The ordered certificate path pkijs used to reach the trust anchor
   * (signer → … → root). DISPLAY ONLY. The caller merges any of these certs
   * that were NOT embedded in the PDF into the displayed chain, tagged as
   * "resolved from trust store". Empty/undefined when the chain did not
   * validate or the built path was unavailable.
   */
  resolvedChain?: ResolvedChainCert[]
}

// ── PEM ↔ DER Helpers ─────────────────────────────────────────────

function hexToArrayBuffer(hex: string): ArrayBuffer {
  const clean = hex.replace(/\s+/g, '')
  const bytes = new Uint8Array(clean.length / 2)
  for (let i = 0; i < clean.length; i += 2) {
    bytes[i / 2] = parseInt(clean.substring(i, i + 2), 16)
  }
  return bytes.buffer
}

// ── Validated-Path Extraction ─────────────────────────────────────

function rdnValue(
  cert: import('pkijs').Certificate,
  which: 'subject' | 'issuer',
  oid: string,
): string | null {
  try {
    const tv = cert[which]?.typesAndValues
    if (!tv) return null
    const attr = tv.find((t) => t.type === oid)
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    return ((attr?.value as any)?.valueBlock?.value as string) || null
  } catch {
    return null
  }
}

/**
 * Convert a pkijs `Certificate` from the validated path into
 * `CertificateInfo`-compatible display data. `role` is assigned by position:
 * the signer (index 0, leaf) is 'end-entity', the anchor (last) that is
 * self-issued is 'root', everything between is 'intermediate'.
 */
function certToResolved(
  cert: import('pkijs').Certificate,
  role: 'end-entity' | 'intermediate' | 'root',
): ResolvedChainCert {
  const commonName = rdnValue(cert, 'subject', '2.5.4.3') || ''
  const issuerCommonName = rdnValue(cert, 'issuer', '2.5.4.3') || ''
  const country = rdnValue(cert, 'subject', '2.5.4.6')
  const toIso = (t: { value?: Date } | undefined): string | null => {
    try {
      return t?.value instanceof Date ? t.value.toISOString() : null
    } catch {
      return null
    }
  }
  const validFrom = toIso(cert.notBefore)
  const validTo = toIso(cert.notAfter)

  // Serial number as uppercase hex (matches certificate-parser's rendering).
  let serialNumber: string
  try {
    const bytes = new Uint8Array(cert.serialNumber.valueBlock.valueHexView)
    serialNumber = Array.from(bytes)
      .map((b) => b.toString(16).padStart(2, '0'))
      .join('')
      .toUpperCase()
  } catch {
    serialNumber = ''
  }

  // Raw DER (lowercase hex) — canonical dedupe key.
  let rawDerHex: string
  try {
    const der = cert.toSchema().toBER(false)
    const bytes = new Uint8Array(der)
    rawDerHex = Array.from(bytes)
      .map((b) => b.toString(16).padStart(2, '0'))
      .join('')
  } catch {
    rawDerHex = ''
  }

  return {
    commonName,
    issuerCommonName,
    serialNumber,
    validFrom,
    validTo,
    country,
    role,
    rawDerHex,
  }
}

/**
 * Map the ordered validated path (signer → … → root) to display certs.
 * The engine returns `certificatePath` root-first in some pkijs versions and
 * leaf-first in others; we normalize to leaf-first by finding the self-issued
 * cert (root) and orienting from the signer.
 */
function resolvedChainFromPath(
  builtChain: import('pkijs').Certificate[],
  candidateCerts: import('pkijs').Certificate[] = [],
): ResolvedChainCert[] {
  // DISPLAY ONLY. This must NEVER throw into the trust decision, so the whole
  // body is guarded: any failure yields an empty resolved chain (the display
  // simply falls back to the embedded certs) and leaves `trusted` untouched.
  try {
    if (!Array.isArray(builtChain) || builtChain.length === 0) return []

    // Normalize orientation to signer → … → root. pkijs's certificatePath is
    // leaf-first (index 0 = signer). Detect root as the self-issued cert.
    const isSelfIssued = (c: import('pkijs').Certificate) =>
      rdnValue(c, 'subject', '2.5.4.3') === rdnValue(c, 'issuer', '2.5.4.3')

    let ordered = builtChain
    if (
      isSelfIssued(builtChain[0]) &&
      builtChain.length > 1 &&
      !isSelfIssued(builtChain[builtChain.length - 1])
    ) {
      // Root-first — reverse to leaf-first.
      ordered = [...builtChain].reverse()
    } else {
      ordered = [...builtChain]
    }

    // Walk up to the self-issued root through the candidate certs (the
    // resolver-matched anchor + PDF-embedded CA certs). pkijs stops
    // `certificatePath` at the first trusted cert (often the issuing
    // intermediate). For a leaf-only PDF that leaves the chain short
    // (… → issuing CA), so continue upward for DISPLAY only: append each parent
    // (issuer subject == child issuer, full DN match) until the self-issued
    // root. Full DN matching is robust to same-CN CA generations (e.g. SINPE v2
    // 2023 vs 2026).
    const derHex = (c: import('pkijs').Certificate) => {
      try {
        return Array.from(new Uint8Array(c.toSchema().toBER(false)))
          .map((b) => b.toString(16).padStart(2, '0'))
          .join('')
      } catch {
        return ''
      }
    }
    const seen = new Set(ordered.map(derHex))
    let guard = 0
    while (guard++ < 12 && !isSelfIssued(ordered[ordered.length - 1])) {
      const child = ordered[ordered.length - 1]
      const parent = candidateCerts.find(
        (cand) => cand.subject.isEqual(child.issuer) && !seen.has(derHex(cand)),
      )
      if (!parent) break
      ordered.push(parent)
      seen.add(derHex(parent))
    }

    const last = ordered.length - 1
    return ordered.map((cert, i) => {
      const role: 'end-entity' | 'intermediate' | 'root' =
        i === last && isSelfIssued(cert) ? 'root' : i === 0 ? 'end-entity' : 'intermediate'
      return certToResolved(cert, role)
    })
  } catch {
    return []
  }
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

// ── Document Integrity (Phase A) ──────────────────────────────────

/**
 * Result of verifying that a PDF's content matches what was actually signed.
 *
 * `integrityValid: true`  → the bytes covered by the signature's ByteRange
 *                            hash to exactly the value the signer signed.
 * `integrityValid: false` → the document was modified after signing
 *                            (a single byte change is enough). The certificate
 *                            chain may still be valid, but the document is
 *                            TAMPERED and MUST NOT be trusted.
 * `integrityValid: null`  → the integrity check could NOT be run (e.g. pkijs
 *                            failed to load, ASN.1 parser threw, network
 *                            error). This is NOT a tamper signal — the
 *                            document state is unknown and the UI must
 *                            render an "unknown" state, never "tampered".
 *                            (ATT-357)
 */
export interface IntegrityResult {
  integrityValid: boolean | null
  error: string | null
}

/**
 * Verify that a PDF's content matches the signed hash. This is the
 * mathematical "did anyone change a byte after signing?" check.
 *
 * It is COMPLETELY independent from `validateChain()`:
 *   - `validateChain()` answers "do we trust the signer's identity?"
 *   - `verifyDocumentIntegrity()` answers "is the document the original?"
 *
 * Both must pass for a signature to be considered valid. Until 2026-04-07
 * verify.attestto.com only ran the first one, which meant a tampered PDF
 * with a valid certificate chain still showed a green "VERIFIED" badge.
 * This function closes that gap.
 *
 * @param pkcs7Hex          Hex-encoded /Contents PKCS#7 blob from the PDF
 * @param signedDataBytes   ByteRange-reconstructed bytes that were signed
 *                          (concatenation of bytes[offset1..offset1+length1]
 *                           and bytes[offset2..offset2+length2])
 */
export async function verifyDocumentIntegrity(
  pkcs7Hex: string,
  signedDataBytes: ArrayBuffer,
): Promise<IntegrityResult> {
  try {
    const { pkijs, asn1js } = await loadPkijs()

    // Parse the PKCS#7 blob into a SignedData structure.
    const pkcs7Der = hexToArrayBuffer(pkcs7Hex)
    const asn1 = asn1js.fromBER(pkcs7Der)
    if (asn1.offset === -1) {
      // ASN.1 structure could not be parsed — this is a runtime/parser
      // failure, NOT a tamper signal. We have no proof either way.
      return {
        integrityValid: null,
        error: 'PKCS#7 ASN.1 parse failed',
      }
    }

    // CMS ContentInfo → SignedData
    const contentInfo = new pkijs.ContentInfo({ schema: asn1.result })
    const signedData = new pkijs.SignedData({ schema: contentInfo.content })

    // Run pkijs's verify() with the reconstructed data. checkChain:false
    // because chain trust is handled separately by validateChain().
    // signer:0 because PDFs always sign with the first signerInfo.
    const result = await signedData.verify({
      signer: 0,
      data: signedDataBytes,
      checkChain: false,
      extendedMode: true,
    })

    // pkijs result shape varies by mode. In extendedMode it returns an object
    // with `signatureVerified`. Treat any "true" signal as success and
    // anything else as failure.
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const r = result as any
    const ok =
      r === true ||
      r?.signatureVerified === true ||
      (typeof r === 'object' && r?.code === undefined && r?.signatureVerified !== false)

    if (!ok) {
      log.warn(`[chain-validator] ✗ Document integrity FAILED — content was modified after signing`)
      return {
        integrityValid: false,
        error: 'Signature does not match document content (tampered)',
      }
    }

    log.event('[chain-validator] ✓ Document integrity VERIFIED — content matches signature')
    return { integrityValid: true, error: null }
  } catch (err) {
    // ATT-357: a thrown exception means the integrity check could not run
    // (pkijs dynamic import failure, network blip, asn1js bug, …). We have
    // NO information about whether the document was tampered. Returning
    // `false` here would falsely accuse a real signer of forgery.
    // Use `null` so the caller can render an "unknown" state.
    const message = err instanceof Error ? err.message : String(err)
    log.warn(`[chain-validator] Integrity verification threw: ${message}`)
    return {
      integrityValid: null,
      error: message,
    }
  }
}

/**
 * Reconstruct the bytes covered by a PDF signature's ByteRange.
 *
 * A PDF signature is "hollow": the /Contents hex blob occupies a hole in
 * the file, and the ByteRange tells us which two slices of the PDF were
 * actually hashed. We must concatenate them to recover the exact bytes
 * the signer ran SHA-256 over.
 *
 * @example
 *   ByteRange: [0, 1234, 5678, 999]
 *     part1 = pdfBytes[0 .. 1234]      (everything before /Contents)
 *     part2 = pdfBytes[5678 .. 6677]   (everything after /Contents)
 *     signed = part1 + part2
 */
export function reconstructSignedBytes(
  pdfBytes: Uint8Array,
  byteRange: [number, number, number, number],
): Uint8Array {
  const [offset1, length1, offset2, length2] = byteRange
  const part1 = pdfBytes.subarray(offset1, offset1 + length1)
  const part2 = pdfBytes.subarray(offset2, offset2 + length2)
  const out = new Uint8Array(length1 + length2)
  out.set(part1, 0)
  out.set(part2, length1)
  return out
}

// ── Resolver-Backed Validation (ATT-438) ──────────────────────────────

/**
 * Validate a certificate chain using resolver.attestto.com for dynamic trust
 * anchor resolution. This is RESOLVER-ONLY — no national PKI certs are bundled
 * into this FE, so there is no offline fallback.
 *
 * Flow:
 * 1. Requires a pkiDid; resolve it via resolver.attestto.com.
 * 2. Match resolved key fingerprints against the PDF-embedded CA certs.
 * 3. If a fingerprint matches, use that embedded CA cert as the pkijs trust
 *    anchor and validate the full chain cryptographically.
 * 4. If the issuing DID does not match, retry with its parent DID (policy CA).
 * 5. If nothing resolves/matches, return `trusted: false` with an honest
 *    error — the structure was parsed but the chain is not linked to a
 *    resolver-verified anchor.
 *
 * @param signerCertHex         DER hex of the signer cert
 * @param intermediateCertsHex  DER hex of intermediate CA certs from the PDF
 * @param pkiDid                The did:pki identifier for the issuing CA (optional)
 * @param resolverOptions       Resolver configuration
 */
export async function validateChainWithResolver(
  signerCertHex: string,
  intermediateCertsHex: string[],
  pkiDid?: string | null,
  resolverOptions?: PkiResolverOptions,
): Promise<ChainValidationResult> {
  // Try resolver-backed validation first if we have a did:pki
  if (pkiDid) {
    try {
      log.info(`[chain-validator] Attempting resolver-backed validation: ${pkiDid}`)

      // The CA certs to match are the intermediates + we also try building
      // from the full candidate pool (intermediates may include the issuing CA)
      const allCaCerts = [...intermediateCertsHex]

      const { matched, matchedCertIndex, matchedKey, resolution } = await resolveAndMatchChain(
        pkiDid,
        allCaCerts,
        resolverOptions,
      )

      if (matched && matchedKey && matchedCertIndex >= 0) {
        // We have a fingerprint-verified CA cert. Use it as a trust anchor
        // in pkijs to validate the full chain cryptographically.
        const trustedCertHex = allCaCerts[matchedCertIndex]

        const result = await validateChainWithDynamicAnchor(
          signerCertHex,
          intermediateCertsHex,
          trustedCertHex,
        )

        if (result.trusted) {
          log.event(
            `[chain-validator] ✓ Chain VERIFIED via resolver — ` +
              `${pkiDid} → ${matchedKey.keyId} (${matchedKey.status})`,
          )
          return {
            ...result,
            trustSource: 'resolver',
            pkiDid,
            endEntityHints: resolution?.endEntityHints ?? null,
          }
        }

        // Fingerprint matched but chain validation failed — cert might be
        // the wrong level in the hierarchy. Log and try the parent DID below.
        log.warn(
          `[chain-validator] Fingerprint matched but chain validation failed: ${result.error}.`,
        )
      } else if (resolution) {
        log.info(
          `[chain-validator] Resolver returned ${resolution.keys.length} key(s) ` +
            `but no fingerprint matched. Trying parent DID if available.`,
        )
      }

      // Also try resolving the parent DID (e.g., policy CA) if the issuing CA
      // DID didn't match. The PDF might embed the policy CA cert instead.
      if (!matched && resolution?.metadata?.parentDid) {
        log.info(`[chain-validator] Trying parent DID: ${resolution.metadata.parentDid}`)
        const parentResult = await resolveAndMatchChain(
          resolution.metadata.parentDid,
          allCaCerts,
          resolverOptions,
        )

        if (parentResult.matched && parentResult.matchedCertIndex >= 0) {
          const trustedCertHex = allCaCerts[parentResult.matchedCertIndex]
          const result = await validateChainWithDynamicAnchor(
            signerCertHex,
            intermediateCertsHex,
            trustedCertHex,
          )

          if (result.trusted) {
            log.event(
              `[chain-validator] ✓ Chain VERIFIED via resolver (parent DID) — ` +
                `${resolution.metadata.parentDid}`,
            )
            return {
              ...result,
              trustSource: 'resolver',
              pkiDid: resolution.metadata.parentDid,
              endEntityHints: resolution?.endEntityHints ?? null,
            }
          }
        }
      }
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err)
      log.warn(`[chain-validator] Resolver-backed validation error: ${message}.`)
    }
  }

  // Resolver-only: no bundled anchors, so nothing else to try. Return an honest
  // failure — the certificate structure was parsed but the chain could not be
  // linked to a resolver-verified trust anchor.
  return {
    trusted: false,
    anchorCommonName: null,
    error: pkiDid
      ? 'Certificate structure parsed, but the chain could not be linked to a ' +
        'resolver-verified trust anchor (no matching key fingerprint from ' +
        'resolver.attestto.com for the issuing did:pki).'
      : 'Certificate structure parsed, but no issuing did:pki was derivable, ' +
        'so the chain could not be linked to a resolver-verified trust anchor.',
    chainLength: 0,
    trustSource: undefined,
  }
}

/**
 * Validate a chain using a dynamically resolved trust anchor.
 * The anchor is a CA cert from the PDF whose fingerprint was verified
 * against the resolver.
 */
async function validateChainWithDynamicAnchor(
  signerCertHex: string,
  intermediateCertsHex: string[],
  trustedAnchorHex: string,
): Promise<ChainValidationResult> {
  try {
    const { pkijs, asn1js } = await loadPkijs()

    // Parse the trusted anchor
    const anchorDer = hexToArrayBuffer(trustedAnchorHex)
    const anchorAsn1 = asn1js.fromBER(anchorDer)
    if (anchorAsn1.offset === -1) {
      return {
        trusted: false,
        anchorCommonName: null,
        error: 'Resolver-matched anchor cert ASN.1 parse failed',
        chainLength: 0,
      }
    }
    const anchorCert = new pkijs.Certificate({ schema: anchorAsn1.result })
    const anchorCnAttr = anchorCert.subject.typesAndValues.find(
      (t: { type: string }) => t.type === '2.5.4.3',
    )
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const anchorCn = ((anchorCnAttr?.value as any)?.valueBlock?.value as string) || null

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

    // Build the chain validation engine with the resolver-matched anchor as the
    // ONLY trusted cert. The candidate pool is the signer + PDF-embedded
    // intermediates + the anchor itself, so pkijs can complete the chain from
    // the signer up to the resolver-verified anchor.
    const engine = new pkijs.CertificateChainValidationEngine({
      trustedCerts: [anchorCert],
      certs: [signerCert, ...intermediates, anchorCert],
    })

    const result = await engine.verify()

    if (!result.result) {
      return {
        trusted: false,
        anchorCommonName: anchorCn,
        error: result.resultMessage || 'Chain validation failed with dynamic anchor',
        chainLength: 0,
      }
    }

    const builtChain = result.certificatePath || []
    const root = builtChain[builtChain.length - 1]
    let rootCn: string | null = null
    if (root) {
      const cnAttr = root.subject.typesAndValues.find((t: { type: string }) => t.type === '2.5.4.3')
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      rootCn = ((cnAttr?.value as any)?.valueBlock?.value as string) || null
    }

    return {
      trusted: true,
      anchorCommonName: rootCn || anchorCn,
      error: null,
      chainLength: builtChain.length,
      resolvedChain: resolvedChainFromPath(builtChain, [anchorCert, ...intermediates]),
    }
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err)
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
}

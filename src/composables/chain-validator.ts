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
import { resolveAndMatchChain, type PkiResolverOptions } from './pki-resolver.js'

// Trust anchors from the centralized @attestto/trust package.
// PEM strings are bundled into the dist at build time — zero runtime fetches.
import {
  CA_RAIZ_NACIONAL_COSTA_RICA_V2 as RAIZ_NACIONAL_PEM,
  CA_POLITICA_PERSONA_JURIDICA_COSTA_RICA_V2 as POLITICA_PJ_PEM,
  CA_POLITICA_PERSONA_FISICA_COSTA_RICA_V2 as POLITICA_PF_PEM,
  CA_POLITICA_SELLADO_DE_TIEMPO_COSTA_RICA_V2 as POLITICA_TSA_PEM,
  CA_SINPE_PERSONA_JURIDICA_V2 as SINPE_PJ_PEM,
  CA_SINPE_PERSONA_FISICA_V2 as SINPE_PF_PEM,
  CA_SINPE_PERSONA_FISICA_V2_2023 as SINPE_PF_2023_PEM,
} from '@attestto/trust/cr'
import {
  AC_RAIZ_ICP_BRASIL_V5 as BR_RAIZ_V5_PEM,
  AC_RAIZ_ICP_BRASIL_V10 as BR_RAIZ_V10_PEM,
  AC_RAIZ_ICP_BRASIL_V11 as BR_RAIZ_V11_PEM,
  AC_RAIZ_ICP_BRASIL_V12 as BR_RAIZ_V12_PEM,
} from '@attestto/trust/br'

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
  /** How trust was established: 'bundled' (local certs) or 'resolver' (resolver.attestto.com) */
  trustSource?: 'bundled' | 'resolver'
  /** The did:pki that was resolved, if trust came from resolver */
  pkiDid?: string
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
    { pem: POLITICA_PF_PEM, label: 'CA POLITICA PERSONA FISICA - COSTA RICA v2' },
    { pem: SINPE_PJ_PEM, label: 'CA SINPE - PERSONA JURIDICA v2' },
    { pem: SINPE_PF_PEM, label: 'CA SINPE - PERSONA FISICA v2 (2019)' },
    { pem: SINPE_PF_2023_PEM, label: 'CA SINPE - PERSONA FISICA v2 (2023)' },
    { pem: POLITICA_TSA_PEM, label: 'CA POLITICA SELLADO DE TIEMPO - COSTA RICA v2' },
    // Brazil — ICP-Brasil root CAs (ATT-314)
    { pem: BR_RAIZ_V5_PEM, label: 'AC Raiz ICP-Brasil v5' },
    { pem: BR_RAIZ_V10_PEM, label: 'AC Raiz ICP-Brasil v10' },
    { pem: BR_RAIZ_V11_PEM, label: 'AC Raiz ICP-Brasil v11' },
    { pem: BR_RAIZ_V12_PEM, label: 'AC Raiz ICP-Brasil v12' },
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
    // - certs: candidate intermediates from the PDF + the signer + bundled anchors
    //   (anchors are also added as certs so pkijs can use them as intermediates
    //    when the PDF doesn't embed the full chain)
    const engine = new pkijs.CertificateChainValidationEngine({
      trustedCerts: anchors.map((a) => a.cert),
      certs: [signerCert, ...intermediates, ...anchors.map((a) => a.cert)],
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
      log.warn(
        `[chain-validator] ✗ Document integrity FAILED — content was modified after signing`,
      )
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
 * Validate a certificate chain using resolver.attestto.com for dynamic
 * trust anchor resolution, with fallback to bundled certs.
 *
 * Flow:
 * 1. If pkiDid provided, resolve via resolver.attestto.com
 * 2. Match resolved key fingerprints against CA certs from the PDF
 * 3. If match found, use the matched CA cert as a pkijs trust anchor
 * 4. If no match or resolver fails, fall back to bundled BCCR certs
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

      const { matched, matchedCertIndex, matchedKey, resolution } =
        await resolveAndMatchChain(pkiDid, allCaCerts, resolverOptions)

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
          }
        }

        // Fingerprint matched but chain validation failed — cert might be
        // the wrong level in the hierarchy. Log and fall through to bundled.
        log.warn(
          `[chain-validator] Fingerprint matched but chain validation failed: ${result.error}. ` +
            `Falling back to bundled anchors.`,
        )
      } else if (resolution) {
        log.info(
          `[chain-validator] Resolver returned ${resolution.keys.length} key(s) ` +
            `but no fingerprint matched. Falling back to bundled anchors.`,
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
            }
          }
        }
      }
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err)
      log.warn(`[chain-validator] Resolver-backed validation error: ${message}. Falling back.`)
    }
  }

  // Fallback: bundled trust anchors (existing behavior)
  const result = await validateChain(signerCertHex, intermediateCertsHex)
  return {
    ...result,
    trustSource: result.trusted ? 'bundled' : undefined,
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

    // Also load bundled anchors so pkijs can complete chains that go
    // through the resolved anchor up to a bundled root
    const bundledAnchors = await loadTrustAnchors()

    // Build the chain validation engine with the resolved anchor + bundled anchors
    const engine = new pkijs.CertificateChainValidationEngine({
      trustedCerts: [anchorCert, ...bundledAnchors.map((a) => a.cert)],
      certs: [signerCert, ...intermediates, anchorCert, ...bundledAnchors.map((a) => a.cert)],
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
      const cnAttr = root.subject.typesAndValues.find(
        (t: { type: string }) => t.type === '2.5.4.3',
      )
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      rootCn = ((cnAttr?.value as any)?.valueBlock?.value as string) || null
    }

    return {
      trusted: true,
      anchorCommonName: rootCn || anchorCn,
      error: null,
      chainLength: builtChain.length,
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
  anchorsCache = null
}

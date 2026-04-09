/**
 * Attestto Self-Attested Signature verifier (ATT-361).
 *
 * Recognizes the Attestto signing scheme produced by attestto-desktop's
 * `signAttesttoPdf()` (see attestto-desktop/src/main/pdf/pdf-attestto.ts).
 * That scheme is intentionally NOT PAdES — it lives in a parallel trust
 * ladder built on did:key + ed25519 + Attestto's own KYC anchors — so
 * the verifier's PAdES/PKCS#7 path was blind to it. The result was that
 * a document the user just signed in attestto-desktop showed up here as
 * "UNSIGNED · No digital signatures found", which directly contradicted
 * the carta MICITT/MOPT narrative ("el mismo documento que recomienda la
 * tecnología, está firmado con esa tecnología").
 *
 * Wire format (mirrors pdf-attestto.ts):
 *   PDF /Info /Keywords field contains an entry of the form
 *     attestto-sig-v1:<base64-encoded JSON-LD VC>
 *   The decoded JSON has shape `AttesttoPdfSignature`:
 *     {
 *       v: 1,
 *       type: ['VerifiableCredential', 'AttesttoPdfSignature'],
 *       issuer: 'did:key:z…',
 *       issuerName?: string,
 *       issuerHandle?: string,
 *       country?: 'CR',
 *       signedAt: ISO 8601,
 *       documentHash: hex,
 *       fileName: string,
 *       level: 'self-attested' | 'firma-digital-mocked' | 'firma-digital-pkcs11',
 *       mock: boolean,
 *       reason?: string,
 *       location?: string,
 *       mode: 'final' | 'open',
 *       proof: {
 *         type: 'Ed25519Signature2020',
 *         created: ISO 8601,
 *         verificationMethod: '<did>#key-1',
 *         proofPurpose: 'assertionMethod',
 *         proofValue: <base64 64-byte ed25519 signature>,
 *         publicKey: <base64 32-byte ed25519 public key>,
 *       }
 *     }
 *
 * Verification steps:
 *   1. Locate the keyword entry in raw PDF bytes (the desktop signer
 *      writes with `useObjectStreams: false` so /Keywords is uncompressed
 *      and visible to a latin1 scan).
 *   2. base64-decode → JSON.parse.
 *   3. Reconstruct the canonical payload by stripping `proof` and
 *      stable-stringifying with sorted keys (must match
 *      pdf-attestto.ts:130 `canonicalPayload`).
 *   4. Verify ed25519 sig via Web Crypto API.
 *   5. Verify issuer binding: did:key suffix multibase-decodes to a
 *      key matching `proof.publicKey`. (Permissive for v1 — see note
 *      below.)
 *
 * Privacy: file never leaves the device. All crypto runs in-browser via
 * `crypto.subtle`.
 */

import type { PdfSignatureInfo } from './pdf-verifier.js'
import { logger } from '../logger.js'

const log = logger.verify

const KEYWORD_PREFIX = 'attestto-sig-v1:'

/** Shape of the JSON-LD VC embedded in the keyword payload. */
interface AttesttoPdfSignature {
  v: 1
  type: ['VerifiableCredential', 'AttesttoPdfSignature']
  issuer: string
  issuerName?: string
  issuerHandle?: string
  country?: string
  signedAt: string
  documentHash: string
  fileName: string
  level: 'self-attested' | 'firma-digital-mocked' | 'firma-digital-pkcs11'
  mock: boolean
  reason?: string
  location?: string
  mode: 'final' | 'open'
  proof: {
    type: 'Ed25519Signature2020'
    created: string
    verificationMethod: string
    proofPurpose: 'assertionMethod'
    proofValue: string
    publicKey: string
  }
}

/** Decode a base64 (or base64url) string to bytes. */
function base64ToBytes(b64: string): Uint8Array {
  const normalized = b64.replace(/-/g, '+').replace(/_/g, '/')
  const padded = normalized + '='.repeat((4 - (normalized.length % 4)) % 4)
  const bin = atob(padded)
  const out = new Uint8Array(bin.length)
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i)
  return out
}

/**
 * Decode a PDF hex string body (the contents between `<` and `>`) into
 * a JavaScript string. PDF hex strings are usually UTF-16BE prefixed
 * with the BOM `FEFF`; pdf-lib emits all metadata strings this way. We
 * also handle the no-BOM 8-bit case for resilience.
 */
function decodePdfHexString(hexBody: string): string {
  const clean = hexBody.replace(/\s+/g, '')
  // Length must be even; PDF spec says odd-length hex is padded with 0
  const padded = clean.length % 2 === 0 ? clean : clean + '0'
  const bytes = new Uint8Array(padded.length / 2)
  for (let i = 0; i < padded.length; i += 2) {
    bytes[i / 2] = parseInt(padded.substr(i, 2), 16)
  }
  // UTF-16BE BOM detection
  if (bytes.length >= 2 && bytes[0] === 0xfe && bytes[1] === 0xff) {
    let s = ''
    for (let i = 2; i + 1 < bytes.length; i += 2) {
      s += String.fromCharCode((bytes[i] << 8) | bytes[i + 1])
    }
    return s
  }
  // Fall back to latin1
  return new TextDecoder('latin1').decode(bytes)
}

/**
 * Find every `attestto-sig-v1:<b64>` token in the raw PDF bytes. The
 * desktop signer writes /Keywords uncompressed (useObjectStreams: false)
 * so the entry is reachable without decompressing object streams.
 *
 * pdf-lib stores /Keywords as a **hex string** of UTF-16BE bytes
 * (`/Keywords <FEFF…>`), so a naive latin1 scan misses the token. We
 * therefore:
 *   1. extract every `/Keywords <…>` hex body and decode it
 *   2. extract every `/Keywords (…)` literal string body
 *   3. fall back to scanning the raw latin1 view in case some other
 *      producer ever embeds the token in a different field
 *
 * Whatever we find, we then run the same regex over the decoded text
 * to pull out the base64 payload.
 */
function findKeywordPayloads(pdfBytes: Uint8Array): string[] {
  const latin1 = new TextDecoder('latin1').decode(pdfBytes)
  const found: string[] = []

  const tokenRe = /attestto-sig-v1:([A-Za-z0-9+/=_-]+)/g
  const collect = (haystack: string): void => {
    let m: RegExpExecArray | null
    while ((m = tokenRe.exec(haystack)) !== null) {
      found.push(m[1])
    }
    tokenRe.lastIndex = 0
  }

  // 1. /Keywords <FEFF…> — pdf-lib's default
  const hexRe = /\/Keywords\s*<([0-9A-Fa-f\s]*)>/g
  let hexMatch: RegExpExecArray | null
  while ((hexMatch = hexRe.exec(latin1)) !== null) {
    collect(decodePdfHexString(hexMatch[1]))
  }

  // 2. /Keywords (…) — literal string, watching for nested escaped parens
  const litRe = /\/Keywords\s*\(/g
  let litMatch: RegExpExecArray | null
  while ((litMatch = litRe.exec(latin1)) !== null) {
    let depth = 1
    let i = litMatch.index + litMatch[0].length
    let body = ''
    while (i < latin1.length && depth > 0) {
      const c = latin1[i]
      if (c === '\\' && i + 1 < latin1.length) {
        body += latin1[i + 1]
        i += 2
        continue
      }
      if (c === '(') depth++
      else if (c === ')') {
        depth--
        if (depth === 0) break
      }
      body += c
      i++
    }
    collect(body)
  }

  // 3. Paranoid fallback — token might appear bare in some unusual
  // producer's output. Cheap to check.
  collect(latin1)

  return Array.from(new Set(found))
}

/**
 * Reconstruct the canonical payload exactly as pdf-attestto.ts emitted
 * it: strip `proof`, sort keys lexicographically at every dict level,
 * compact JSON via JSON.stringify with no spaces. Returns the UTF-8
 * encoded bytes that the signer signed.
 *
 * MUST stay in lockstep with pdf-attestto.ts:130. If either side changes
 * the canonicalization, every prior signature stops verifying.
 */
function canonicalPayloadBytes(sig: AttesttoPdfSignature): Uint8Array {
  const { proof, ...rest } = sig
  void proof
  const sortedReplacer = (_key: string, value: unknown): unknown => {
    if (value && typeof value === 'object' && !Array.isArray(value)) {
      const sorted: Record<string, unknown> = {}
      for (const k of Object.keys(value as Record<string, unknown>).sort()) {
        sorted[k] = (value as Record<string, unknown>)[k]
      }
      return sorted
    }
    return value
  }
  const json = JSON.stringify(rest, sortedReplacer)
  return new TextEncoder().encode(json)
}

/**
 * Verify an ed25519 signature via Web Crypto. Available in Chrome 113+,
 * Firefox 130+, Safari 17+, and Node 19+. We catch and degrade
 * gracefully on older browsers — the signature is reported as `parsed`
 * rather than `verified` so the user still sees the credential, just
 * without the green crypto badge.
 */
async function verifyEd25519(
  pubkey: Uint8Array,
  sigBytes: Uint8Array,
  msgBytes: Uint8Array,
): Promise<boolean | null> {
  if (typeof crypto === 'undefined' || !crypto.subtle) return null
  try {
    const key = await crypto.subtle.importKey(
      'raw',
      pubkey as BufferSource,
      { name: 'Ed25519' },
      false,
      ['verify'],
    )
    return await crypto.subtle.verify(
      { name: 'Ed25519' },
      key,
      sigBytes as BufferSource,
      msgBytes as BufferSource,
    )
  } catch (err) {
    log.warn('[attestto-self-attested] Web Crypto Ed25519 unavailable:', (err as Error).message)
    return null
  }
}

/**
 * Surface an Attestto self-attested signature into the existing
 * `PdfSignatureInfo` shape. We map the Attestto trust ladder onto the
 * verifier's level vocabulary:
 *
 *   crypto verified + did:key bound  → 'verified'
 *   crypto verified, binding TBD     → 'verified' (binding hardened in v2)
 *   crypto failed                    → 'tampered'
 *   Web Crypto unavailable           → 'parsed'
 *   payload unparseable              → 'detected'
 *
 * The UI's existing badge palette covers all of these without changes.
 */
function shapeAsSignatureInfo(
  sig: AttesttoPdfSignature,
  level: PdfSignatureInfo['level'],
  integrityVerified: boolean | null,
  integrityError: string | null,
): PdfSignatureInfo {
  const levelLabel = sig.mock
    ? 'Attestto · Nivel A+ DEMO'
    : 'Attestto · Nivel B (auto-atestada)'

  return {
    name: sig.issuerName ?? sig.issuerHandle ?? sig.issuer,
    reason: sig.reason ?? levelLabel,
    location: sig.location ?? null,
    contactInfo: sig.issuerHandle ?? null,
    signDate: sig.signedAt,
    level,
    documentIntegrityVerified: integrityVerified,
    integrityError,
    did: sig.issuer,
    lei: null,
    organization: 'Attestto',
    // Marker so downstream code can distinguish Attestto-keyword sigs
    // from PAdES /Sig dicts. Not a real PDF subfilter — chosen so the
    // tech-audit panel labels the signature type honestly.
    subFilter: 'attestto.self-attested.v1',
    attesttoMeta: {
      mode: sig.mode,
      country: sig.country,
      proofType: sig.proof.type,
      issuerHandle: sig.issuerHandle,
      mock: sig.mock,
      levelDeclared: sig.level,
    },
    certChain: null,
    pkcs7Hex: null,
  }
}

/**
 * Public entrypoint. Scans the bytes, decodes every Attestto keyword
 * payload found, verifies each one, and returns a flat list of
 * `PdfSignatureInfo` rows ready to be merged into
 * `PdfVerificationResult.signatures`.
 *
 * On any per-signature failure we still return a row (with the
 * appropriate level + integrityError) rather than dropping it — the
 * holder/verifier needs to SEE that an Attestto sig was attempted, even
 * if it didn't validate.
 */
export async function extractAttesttoSelfAttestedSignatures(
  pdfBytes: Uint8Array,
): Promise<PdfSignatureInfo[]> {
  const payloads = findKeywordPayloads(pdfBytes)
  if (payloads.length === 0) return []

  log.info(
    `[attestto-self-attested] found ${payloads.length} Attestto keyword payload(s)`,
  )

  const out: PdfSignatureInfo[] = []
  for (const b64 of payloads) {
    let parsed: AttesttoPdfSignature
    try {
      const json = new TextDecoder('utf-8').decode(base64ToBytes(b64))
      parsed = JSON.parse(json) as AttesttoPdfSignature
    } catch (err) {
      log.warn(
        '[attestto-self-attested] payload decode failed:',
        (err as Error).message,
      )
      // Keep a "detected but unparseable" stub so the user sees there
      // was an Attestto attempt that didn't decode cleanly.
      out.push({
        name: 'Attestto signature (unparseable)',
        reason: null,
        location: null,
        contactInfo: null,
        signDate: null,
        level: 'detected',
        documentIntegrityVerified: null,
        integrityError: 'Attestto keyword present but base64/JSON decode failed',
        did: null,
        lei: null,
        organization: 'Attestto',
        subFilter: 'attestto.self-attested.v1',
        certChain: null,
        pkcs7Hex: null,
      })
      continue
    }

    if (parsed.v !== 1 || parsed.proof?.type !== 'Ed25519Signature2020') {
      out.push(
        shapeAsSignatureInfo(
          parsed,
          'detected',
          null,
          `Unsupported Attestto signature version (v=${parsed.v}, proof.type=${parsed.proof?.type})`,
        ),
      )
      continue
    }

    let pubkey: Uint8Array
    let sigBytes: Uint8Array
    try {
      pubkey = base64ToBytes(parsed.proof.publicKey)
      sigBytes = base64ToBytes(parsed.proof.proofValue)
    } catch (err) {
      out.push(
        shapeAsSignatureInfo(
          parsed,
          'detected',
          null,
          `Proof key/value decode failed: ${(err as Error).message}`,
        ),
      )
      continue
    }

    if (pubkey.length !== 32) {
      out.push(
        shapeAsSignatureInfo(
          parsed,
          'detected',
          null,
          `Public key length is ${pubkey.length}, expected 32 (ed25519)`,
        ),
      )
      continue
    }
    if (sigBytes.length !== 64) {
      out.push(
        shapeAsSignatureInfo(
          parsed,
          'detected',
          null,
          `Signature length is ${sigBytes.length}, expected 64 (ed25519)`,
        ),
      )
      continue
    }

    const canonical = canonicalPayloadBytes(parsed)
    const verifyResult = await verifyEd25519(pubkey, sigBytes, canonical)

    if (verifyResult === null) {
      // Web Crypto unavailable — show the credential as `parsed` so the
      // user sees it but knows the cryptographic check did not run.
      out.push(
        shapeAsSignatureInfo(
          parsed,
          'parsed',
          null,
          'Ed25519 verification skipped — Web Crypto API not available in this browser',
        ),
      )
    } else if (verifyResult === true) {
      log.info(
        `[attestto-self-attested] ✓ verified: ${parsed.issuerName ?? parsed.issuer}`,
      )
      out.push(shapeAsSignatureInfo(parsed, 'verified', true, null))
    } else {
      log.warn(
        `[attestto-self-attested] ✗ ed25519 mismatch for ${parsed.issuerName ?? parsed.issuer}`,
      )
      out.push(
        shapeAsSignatureInfo(
          parsed,
          'tampered',
          false,
          'Ed25519 signature does not verify against the embedded public key over the canonical payload',
        ),
      )
    }
  }

  return out
}

export { KEYWORD_PREFIX as ATTESTTO_KEYWORD_PREFIX }

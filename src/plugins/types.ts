/**
 * Attestto Verification Result Schema — The Universal Contract
 *
 * This is the standardized response shape that ALL plugins must return.
 * It bridges PDF/PAdES (Web 2.0) and DID/VC (Web 3.0) verification
 * through a single interface.
 *
 * Any site embedding <attestto-verify> gets results in this format,
 * regardless of whether the trust comes from a CA or a DID.
 */

// ── Core Result (returned by every verification) ─────────────────────

export interface AttesttoVerificationResult {
  /** Overall verification passed */
  verified: boolean

  /** Verification timestamp (ISO 8601) */
  timestamp: string

  /** Source file info */
  document: DocumentInfo

  /** Integrity check — was the document modified after signing? */
  integrity: IntegrityResult

  /** Signatures found in the document */
  signatures: SignatureResult[]

  /** Plugin results — additional trust signals */
  extensions: ExtensionResult[]
}

// ── Document Info ────────────────────────────────────────────────────

export interface DocumentInfo {
  fileName: string
  fileSize: number
  /** SHA-256 hash of the complete file */
  hash: string
  hashAlgorithm: 'SHA-256'
  /** File format detected */
  format: 'pdf' | 'json-ld' | 'jwt' | 'xml' | 'unknown'
}

// ── Integrity ────────────────────────────────────────────────────────

export interface IntegrityResult {
  /** Document hash was computed successfully */
  hashValid: boolean
  /**
   * ByteRange integrity (PDF only) — the signed content was not modified.
   * null if not a signed PDF or if v2 (ATT-209) is not loaded.
   */
  byteRangeValid: boolean | null
  /** Human-readable summary */
  message: string
}

// ── Signature (one per signer) ───────────────────────────────────────

export interface SignatureResult {
  /** Detection level achieved */
  level: VerificationLevel

  /** Signature type / origin */
  type: SignatureType

  /** Signer identity (extracted from cert or DID) */
  signer: SignerIdentity

  /** Certificate chain info (PAdES) or DID resolution info (VC) */
  trust: TrustInfo

  /** Raw metadata from the signature container */
  metadata: Record<string, unknown>
}

/**
 * Verification levels — progressive trust ladder.
 *
 *   detected  → Found signature structure (v1 byte scan)
 *   parsed    → Signature bytes decode correctly (pkijs/vc-js)
 *   signed    → Cryptographic math verifies (key matches signature)
 *   trusted   → Chain reaches a known root (CA or DID trust registry)
 *   qualified → Meets regulatory standard (eIDAS qualified, gov-issued)
 */
export type VerificationLevel =
  | 'detected'
  | 'parsed'
  | 'signed'
  | 'trusted'
  | 'qualified'

/**
 * Signature types — what ecosystem produced this signature.
 */
export type SignatureType =
  | 'pades'          // PDF PKCS#7 (adbe.pkcs7.detached)
  | 'cades'          // PDF CAdES (ETSI.CAdES.detached)
  | 'pades-legacy'   // PDF PKCS#7 SHA-1 (adbe.pkcs7.sha1)
  | 'did-ecdsa'      // DID-based ECDSA signature
  | 'did-eddsa'      // DID-based EdDSA signature
  | 'vc-jwt'         // Verifiable Credential (JWT proof)
  | 'vc-ld'          // Verifiable Credential (Linked Data proof)
  | 'sd-jwt'         // Selective Disclosure JWT
  | 'xml-dsig'       // XML Digital Signature
  | 'unknown'

// ── Signer Identity ──────────────────────────────────────────────────

export interface SignerIdentity {
  /** Display name (from CN, or DID document name) */
  name: string
  /** Email (from cert SAN or DID service endpoint) */
  email?: string
  /** Organization (from cert O field or DID controller) */
  organization?: string
  /** Country (from cert C field) */
  country?: string
  /** Title/role (from cert title field) */
  title?: string
  /** DID URI (from cert SAN or VC issuer) */
  did?: string
  /** LEI code (from cert serialNumber) */
  lei?: string
}

// ── Trust Info ───────────────────────────────────────────────────────

export interface TrustInfo {
  /** Is the signer trusted by a known authority? */
  trusted: boolean

  /** Trust source identifier */
  source: TrustSource

  /** Trust level detail */
  level: TrustLevel

  /** Certificate or DID details */
  details: CertTrustDetails | DidTrustDetails
}

export type TrustSource =
  | 'attestto-root'   // Attestto Trust Root CA
  | 'aatl'            // Adobe Approved Trust List
  | 'eu-tsl'          // EU Trusted Services List (eIDAS)
  | 'did-web'         // Resolved via did:web
  | 'did-sns'         // Resolved via did:sns (Solana)
  | 'did-key'         // Self-issued (did:key)
  | 'did-jwk'         // Self-issued (did:jwk)
  | 'custom'          // Plugin-provided trust source
  | 'unknown'

export type TrustLevel =
  | 'qualified'       // eIDAS Qualified / gov-issued
  | 'recognized'      // Known CA or verified DID
  | 'self-signed'     // Self-issued cert or self-issued DID
  | 'unknown'         // Cannot determine trust

export interface CertTrustDetails {
  type: 'x509'
  /** Certificate serial number */
  serial: string
  /** Issuer common name */
  issuer: string
  /** Validity period */
  validFrom: string
  validTo: string
  /** Is the cert currently valid (not expired, not revoked)? */
  isValid: boolean
  /** SubFilter from PDF signature dictionary */
  subFilter?: string
}

export interface DidTrustDetails {
  type: 'did'
  /** The resolved DID */
  did: string
  /** DID method (web, sns, key, jwk, etc.) */
  method: string
  /** Was the DID document successfully resolved? */
  resolved: boolean
  /** Number of verification methods in the DID document */
  verificationMethods: number
  /** Controller DID (if different from subject) */
  controller?: string
}

// ── Extension Results ────────────────────────────────────────────────

export interface ExtensionResult {
  /** Plugin name */
  plugin: string
  /** Plugin label for display */
  label: string
  /** Did this plugin's check pass? */
  valid: boolean
  /** Human-readable message */
  message: string
  /** Plugin-specific details */
  details?: Record<string, unknown>
}

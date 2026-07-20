/**
 * Presentational model for <attestto-signature-card>.
 *
 * This is the single view-model both surfaces render through:
 *   - the website (attestto-verify) maps its `PdfSignatureInfo` → SignatureCardModel
 *   - the desktop (Vue/Quasar) maps its own verify result → SignatureCardModel
 *
 * Keeping the card decoupled from either app's verify types is deliberate: the
 * two data sources differ slightly, but the card must look identical. Each host
 * writes a tiny mapper; the component only ever sees this clean shape.
 */

export type SignatureStatus =
  | 'verified' // chain trusted + document intact
  | 'structure-only' // parsed but chain not trusted
  | 'self-attested' // Attestto Nivel B (KYC-anchored, not a third-party CA)
  | 'tampered' // document changed after signing
  | 'unknown' // integrity check could not run

export interface SignatureCapability {
  label: string
  /** Where it came from, for styling/grouping. */
  kind: 'keyusage' | 'eku' | 'attestto'
}

export interface OfficialVerifier {
  /** Short label, e.g. "Firma Digital CR". */
  name: string
  /** Official third-party verifier the user can re-check this signature on. */
  url: string
}

/**
 * Long-Term Validation status. For CR Firma Digital this is the BCCR-anchored
 * archival evidence: an embedded timestamp (RFC 3161) + embedded revocation
 * (OCSP/CRL in the PDF's DSS). Without it, a signature is only valid while the
 * cert is unexpired AND BCCR's responders stay reachable.
 */
export interface SignatureLtv {
  /** PAdES conformance tier. */
  tier: 'B' | 'T' | 'LT' | 'LTA' | 'none'
  hasTimestamp: boolean
  /** Authoritative signing time from the TSA token, if present. */
  timestampAt?: string | null
  timestampAuthority?: string | null
  /** Where revocation evidence came from. 'embedded' = self-contained/long-term. */
  revocationSource: 'embedded' | 'live' | 'none'
}

export interface SignatureCardTech {
  standard?: string | null
  byteRange?: number[] | null
  pkcs7Size?: number | null
  location?: string | null
  /** Hex PKCS#7/CMS blob, for a "copy" affordance in dev-facing details. */
  pkcs7Hex?: string | null
  /** Digest algorithm, e.g. "SHA-256". */
  digestAlgorithm?: string | null
  /** DID or key id of the signer, when present. */
  keyId?: string | null
  /** Cert chain, root-first (leaf last), for the technical-details tree. */
  chain?: Array<{ name: string; issuer?: string; from?: string; to?: string; country?: string }>
}

export interface SignatureCardModel {
  index: number
  signerName: string
  /** 1–2 letter avatar initials. Derived if omitted. */
  initials?: string
  /** ISO 3166-1 alpha-2 for the flag. */
  country: string | null
  status: SignatureStatus
  /** e.g. "Persona Física · CR Firma Digital" or "Attestto self-attested". */
  subtitle: string
  jurisdiction: string | null
  /** e.g. "CAdES · ETSI.CAdES" or "Ed25519 · self-attested". */
  method: string
  /** Raw subfilter for the tech row, e.g. "ETSI.CAdES.detached". */
  methodTech: string | null
  /** Signing time. Null when the PDF carries no parseable signing date. */
  signedAt: string | null
  /** Signing certificate validity window (leaf cert), for the "vigente · vence" range. */
  cert?: { validFrom?: string | null; validTo?: string | null } | null
  /** National ID, masked for display + full for the reveal action. */
  nationalId: { masked: string; full: string } | null
  /** What the signing key/cert is authorized to do. */
  capabilities: SignatureCapability[]
  officialVerifier: OfficialVerifier | null
  /** Trust-provenance links (did:pki resolver, OCSP, trust registry) for the Trust tab. */
  trustLinks?: Array<{ label: string; url: string }> | null
  /** dataURL of a visible signature/seal appearance, if the PDF carries one. */
  signatureImage: string | null
  /** Attestto handle (cr-….attestto.id) or DID, shown under the ID column. */
  handle: string | null
  /** Long-term validation status. Null when not applicable (e.g. self-attested). */
  ltv?: SignatureLtv | null
  tech: SignatureCardTech
}

// ── Capability label maps ──────────────────────────────────────────────

const KEY_USAGE_LABELS: Record<string, string> = {
  digitalSignature: 'Digital signature',
  nonRepudiation: 'Non-repudiation',
  contentCommitment: 'Non-repudiation',
  keyEncipherment: 'Key encipherment',
  dataEncipherment: 'Data encipherment',
  keyAgreement: 'Key agreement',
  keyCertSign: 'Certificate signing',
  cRLSign: 'CRL signing',
}

const EKU_LABELS: Record<string, string> = {
  emailProtection: 'Email protection',
  clientAuth: 'Client authentication',
  serverAuth: 'Server authentication',
  codeSigning: 'Code signing',
  timeStamping: 'Time stamping',
  documentSigning: 'Document signing',
}

/** Map raw X.509 KeyUsage/EKU tokens to friendly capability chips. */
export function capabilitiesFromCert(
  keyUsage: string[] = [],
  extendedKeyUsage: string[] = [],
): SignatureCapability[] {
  const seen = new Set<string>()
  const out: SignatureCapability[] = []
  for (const ku of keyUsage) {
    const label = KEY_USAGE_LABELS[ku] ?? ku
    if (!seen.has(label)) {
      seen.add(label)
      out.push({ label, kind: 'keyusage' })
    }
  }
  for (const eku of extendedKeyUsage) {
    const label = EKU_LABELS[eku] ?? eku
    if (!seen.has(label)) {
      seen.add(label)
      out.push({ label, kind: 'eku' })
    }
  }
  return out
}

/**
 * Official third-party verifier for a signature, derived from its
 * jurisdiction / method. Returns null when we have no trustworthy endpoint.
 *
 * NOTE: confirm the exact CR endpoint before shipping — `firmadigital.go.cr`
 * is the program site; the concrete "validate a signed document" URL should be
 * pinned so the "verify on the official site" link never points somewhere wrong.
 */
export function officialVerifierFor(opts: {
  country: string | null
  status: SignatureStatus
  methodTech: string | null
}): OfficialVerifier | null {
  const { country, status, methodTech } = opts
  if (status === 'self-attested') {
    return { name: 'Attestto resolver', url: 'https://resolver.attestto.com' }
  }
  if (country === 'CR') {
    // NOTE(confirm-before-ship): pin the exact CR signed-document validator
    // URL; `firmadigital.go.cr` is the program site, not the validate endpoint.
    return { name: 'Firma Digital CR', url: 'https://firmadigital.go.cr' }
  }
  if (country === 'ES') {
    return { name: 'VALIDe (Gobierno de España)', url: 'https://valide.redsara.es' }
  }
  // eIDAS / EU default: the European Commission DSS validation demo.
  if (methodTech?.includes('CAdES') || methodTech?.includes('pkcs7')) {
    return {
      name: 'EU DSS validator',
      url: 'https://ec.europa.eu/digital-building-blocks/DSS/webapp-demo/validation',
    }
  }
  return null
}

export function initialsFor(name: string): string {
  const parts = name.trim().split(/\s+/).filter(Boolean)
  if (parts.length === 0) return '?'
  if (parts.length === 1) return parts[0].slice(0, 2).toUpperCase()
  return (parts[0][0] + parts[parts.length - 1][0]).toUpperCase()
}

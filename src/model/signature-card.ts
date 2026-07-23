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
 * Long-Term Validation status. Two independent worlds map onto this shape:
 *
 *   - X.509 / PAdES (CR Firma Digital, eIDAS…): archival evidence is an embedded
 *     timestamp (RFC 3161) + embedded revocation (OCSP/CRL in the PDF's DSS).
 *     Without it, the signature is valid only while the cert is unexpired AND the
 *     issuer's responders stay reachable. Described by tier/hasTimestamp/
 *     timestampAuthority/revocationSource.
 *
 *   - Attestto self-attested: there is no CA or TSA, so the ONLY valid long-term
 *     time proof is an on-chain `anchor` whose block time proves the signature
 *     existed before T, independent of any responder. A merely self-asserted
 *     signing clock (the signer's own `new Date()`) is NOT a time proof and must
 *     leave `anchor` unset — otherwise the card would overclaim anchoring.
 */
export interface SignatureLtv {
  /** PAdES conformance tier. Use 'none' for the non-X.509 (anchor) path. */
  tier: 'B' | 'T' | 'LT' | 'LTA' | 'none'
  hasTimestamp: boolean
  /** Authoritative signing time from the TSA token, if present. */
  timestampAt?: string | null
  timestampAuthority?: string | null
  /** Where revocation evidence came from. 'embedded' = self-contained/long-term. */
  revocationSource: 'embedded' | 'live' | 'none'
  /**
   * On-chain time anchor. Present ONLY when a verifiable anchor exists (its block
   * time is the authoritative "existed before T"). Never populate this from a
   * self-asserted signing clock. This is the Attestto-native LTV: the ledger, not
   * a CA, is the time authority.
   */
  anchor?: {
    /** Anchoring network, e.g. "Solana". */
    network: string
    /** Transaction / anchor reference, when available. */
    ref?: string | null
    /** Authoritative anchor (block) time, ISO 8601. */
    anchoredAt?: string | null
  } | null
}

/**
 * A recognized trust-scheme mark (eIDAS qualified, EU Trusted List, CR Firma
 * Digital, Attestto Nivel B…). Rendered as a styled badge — NOT third-party
 * logos. `scheme` drives colour/icon and must reflect reality, never marketing.
 */
export interface SignatureTrustMark {
  label: string
  scheme: 'qualified' | 'trusted-list' | 'cr-firma' | 'attestto' | 'untrusted' | 'other'
}

export interface SignatureCardTech {
  standard?: string | null
  /** Full signing time to the millisecond (ISO 8601 UTC), for the advanced tab. */
  signedAtISO?: string | null
  /** Signer's stated commitment / reason for signing (PAdES /Reason). */
  reason?: string | null
  /** PDF producer / creating application. */
  producer?: string | null
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
  chain?: Array<{
    name: string
    issuer?: string
    from?: string
    to?: string
    country?: string
    /**
     * Provenance: 'embedded' = cert was in the signed PDF; 'trust-store' =
     * cert was supplied by the bundled trust store to complete the validated
     * chain (the PDF did not embed it). Used to render an honest label.
     */
    source?: 'embedded' | 'trust-store'
  }>
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
  /**
   * Long-term validation status. For self-attested signatures this carries the
   * on-chain `anchor` when one exists (the only valid time proof without a CA);
   * null when the signature is only bound to content + KYC with a self-asserted
   * signing clock.
   */
  ltv?: SignatureLtv | null
  /**
   * OPT-IN online revocation. The default no-network behavior is unchanged: this
   * is populated ONLY after the user explicitly runs the online check.
   *   - `available`: an OCSP responder URL exists, so the button may be offered.
   *   - `result`: the outcome once the user has run the check (else null).
   * The host (attestto-verify.ts) owns the raw certs and runs the actual fetch
   * in response to the card's `request-online-revocation` event.
   */
  onlineRevocation?: {
    available: boolean
    result?: {
      status: 'good' | 'revoked' | 'unknown' | 'unreachable'
      message: string
      checkedAt: string
    } | null
    /** True while the host is performing the network check. */
    checking?: boolean
  } | null
  /** Recognized trust-scheme marks (eIDAS qualified, CR Firma Digital, …). */
  trustMarks?: SignatureTrustMark[] | null
  tech: SignatureCardTech
}

// ── Capability label maps ──────────────────────────────────────────────

// ── Canonical capability vocabulary ────────────────────────────────────
// One user-facing term set that BOTH X.509 (KeyUsage/EKU) and Attestto (DID
// verification relationships) map onto, so "Digital signature" and "Document
// signing" never appear side-by-side meaning the same thing.
//   Document signing · Non-repudiation · Authentication · Identity assertion
//   · Email protection · Encryption · Certificate signing · Timestamping
const KEY_USAGE_LABELS: Record<string, string> = {
  digitalSignature: 'Document signing',
  nonRepudiation: 'Non-repudiation',
  contentCommitment: 'Non-repudiation',
  keyEncipherment: 'Encryption',
  dataEncipherment: 'Encryption',
  keyAgreement: 'Encryption',
  encipherOnly: 'Encryption',
  decipherOnly: 'Encryption',
  keyCertSign: 'Certificate signing',
  cRLSign: 'Certificate signing',
}

const EKU_LABELS: Record<string, string> = {
  emailProtection: 'Email protection',
  clientAuth: 'Authentication',
  smartCardLogin: 'Authentication',
  serverAuth: 'Server authentication',
  codeSigning: 'Code signing',
  timeStamping: 'Timestamping',
  ocspSigning: 'OCSP signing',
  documentSigning: 'Document signing',
}

/**
 * Friendly labels for known Extended-Key-Usage OIDs. Some certs (e.g. Adobe /
 * eIDAS) declare EKUs by raw OID that the parser leaves un-mapped. A raw OID
 * dotted-string is NOT a user-facing capability — map the known ones here and
 * drop the rest from the main card (see `capabilitiesFromCert`).
 */
const EKU_OID_LABELS: Record<string, string> = {
  '1.2.840.113583.1.1.5': 'Adobe PDF Signing', // Adobe Authentic Documents Trust
  '1.3.6.1.5.5.7.3.1': 'Server authentication',
  '1.3.6.1.5.5.7.3.2': 'Authentication',
  '1.3.6.1.5.5.7.3.3': 'Code signing',
  '1.3.6.1.5.5.7.3.4': 'Email protection',
  '1.3.6.1.5.5.7.3.8': 'Timestamping',
  '1.3.6.1.5.5.7.3.9': 'OCSP signing',
}

/** True when a token is a raw OID dotted-string (e.g. "1.2.840.113583.1.1.5"). */
function isRawOid(token: string): boolean {
  return /^\d+(\.\d+)+$/.test(token)
}

/**
 * Human names for ISO 3166-1 alpha-2 jurisdiction codes. The card shows a flag
 * from the country code even when no PKI trust root is bundled; without this
 * map the JURISDICTION label falls back to an empty em-dash. Bilingual so the
 * name matches the active locale.
 */
const COUNTRY_NAMES: Record<string, { en: string; es: string }> = {
  CR: { en: 'Costa Rica', es: 'Costa Rica' },
  ES: { en: 'Spain', es: 'España' },
  US: { en: 'United States', es: 'Estados Unidos' },
  MX: { en: 'Mexico', es: 'México' },
  DE: { en: 'Germany', es: 'Alemania' },
  FR: { en: 'France', es: 'Francia' },
  IT: { en: 'Italy', es: 'Italia' },
  PT: { en: 'Portugal', es: 'Portugal' },
  GB: { en: 'United Kingdom', es: 'Reino Unido' },
  NL: { en: 'Netherlands', es: 'Países Bajos' },
  BE: { en: 'Belgium', es: 'Bélgica' },
  BR: { en: 'Brazil', es: 'Brasil' },
  AR: { en: 'Argentina', es: 'Argentina' },
  CO: { en: 'Colombia', es: 'Colombia' },
  CL: { en: 'Chile', es: 'Chile' },
  PA: { en: 'Panama', es: 'Panamá' },
}

/** Map an ISO 3166-1 alpha-2 code to a localized country name, or null. */
export function countryName(code: string | null, lang: 'en' | 'es'): string | null {
  if (!code) return null
  const entry = COUNTRY_NAMES[code.toUpperCase()]
  return entry ? entry[lang] : null
}

/**
 * Map a signature method (PDF /SubFilter or Attestto scheme) to the standard
 * FAMILY it belongs to. The `method` field already shows the raw subFilter
 * (e.g. `ETSI.CAdES.detached`); `standard` should name the spec it implements
 * (e.g. PAdES), not echo the same string. Returns null when the input is empty.
 */
export function signatureStandard(subFilter: string | null | undefined): string | null {
  if (!subFilter) return null
  const sf = subFilter.toLowerCase()
  if (sf === 'etsi.cades.detached') return 'PAdES (ETSI EN 319 142)'
  if (sf === 'etsi.rfc3161') return 'PAdES document timestamp (RFC 3161)'
  if (sf.startsWith('adbe.pkcs7')) return 'PKCS#7 / adbe (ISO 32000)'
  if (sf.startsWith('adbe.x509')) return 'X.509 / adbe (ISO 32000, legacy)'
  if (sf.startsWith('attestto.self-attested')) return 'Attestto self-attested'
  if (sf.startsWith('attestto.')) return 'Attestto'
  return subFilter
}

/** Map Attestto DID verification relationships onto the same canonical terms. */
export function capabilitiesFromDid(relationships: string[] = []): SignatureCapability[] {
  const out: SignatureCapability[] = []
  const add = (label: string) => {
    if (!out.some((c) => c.label === label)) out.push({ label, kind: 'attestto' })
  }
  for (const r of relationships) {
    if (r === 'assertionMethod') {
      add('Document signing')
      add('Identity assertion')
    } else if (r === 'authentication') add('Authentication')
    else if (r === 'keyAgreement') add('Encryption')
  }
  return out
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
    // Resolve friendly EKU name → known-OID name; a raw un-mapped OID is not a
    // human capability, so drop it from the main card entirely.
    let label = EKU_LABELS[eku]
    if (!label && isRawOid(eku)) label = EKU_OID_LABELS[eku]
    if (!label) {
      if (isRawOid(eku)) continue // unknown raw OID — omit, not a real capability
      label = eku
    }
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

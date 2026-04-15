/**
 * PKI DID Derivation — Maps certificate chain data to did:pki identifiers.
 *
 * Given a parsed certificate chain and identified PKI hierarchy, derives the
 * canonical did:pki identifier for each CA in the chain. This enables dynamic
 * trust anchor resolution via resolver.attestto.com instead of requiring
 * bundled certificates for every country.
 *
 * The mapping is deterministic: a CA common name + country code always produces
 * the same did:pki path. The resolver is the source of truth for whether that
 * DID actually resolves to a live CA.
 *
 * ATT-438
 */

import type { CertificateInfo, PkiIdentity } from './certificate-parser.js'

// ── CR CA Name → did:pki Path Mapping ────────────────────────────────

interface CaDidMapping {
  /** Uppercase substring to match in the CA common name */
  pattern: string
  /** did:pki path segments after the country code */
  path: string
}

/**
 * Country-specific CA name → did:pki path mappings.
 * Each entry maps CA common name patterns to the did:pki path segments.
 *
 * Order matters: more specific patterns first (SINPE before POLITICA).
 */
const CA_DID_MAPPINGS: Record<string, CaDidMapping[]> = {
  CR: [
    { pattern: 'SINPE', path: 'sinpe' },
    { pattern: 'POLITICA', path: 'politica' },
    { pattern: 'RAIZ NACIONAL', path: 'raiz-nacional' },
  ],
  // Future countries follow the same pattern:
  // BR: [
  //   { pattern: 'SERPRO', path: 'serpro' },
  //   { pattern: 'CERTISIGN', path: 'certisign' },
  //   ...
  // ],
}

/**
 * Certificate type label → did:pki path segment.
 * Maps the human-readable cert type (from pki-registry.ts certTypeRules)
 * to the path segment used in did:pki identifiers.
 */
const CERT_TYPE_SEGMENTS: Record<string, string> = {
  'Persona Física': 'persona-fisica',
  'Persona Jurídica': 'persona-juridica',
  'Persona Natural': 'persona-natural',
  'Sello Electrónico': 'sello-electronico',
  'Sellado de Tiempo': 'sellado-de-tiempo',
  // BR
  'e-CPF A1 (Pessoa Física)': 'pessoa-fisica',
  'e-CPF A3 (Pessoa Física)': 'pessoa-fisica',
  // Generic fallback patterns
  'e.firma': 'persona-fisica',
  'CSD (Sello Digital)': 'sello-digital',
}

// ── Public API ────────────────────────────────────────────────────────

export interface PkiDidDerivation {
  /** The derived did:pki identifier for the issuing CA */
  issuingCaDid: string | null
  /** The full chain of did:pki identifiers (issuing → policy → root) */
  chainDids: string[]
  /** How the DID was derived */
  derivedVia: 'ca-name-mapping' | 'heuristic' | null
}

/**
 * Derive did:pki identifiers from a parsed certificate chain.
 *
 * @param chain  The certificate chain (signer → intermediate(s) → root)
 * @param pki    The identified PKI hierarchy (from identifyPki)
 * @returns      The derived did:pki for the issuing CA, plus the full chain
 */
export function derivePkiDids(
  chain: CertificateInfo[],
  pki: PkiIdentity | null,
): PkiDidDerivation {
  if (!pki || chain.length === 0) {
    return { issuingCaDid: null, chainDids: [], derivedVia: null }
  }

  const country = pki.country.toLowerCase()
  const chainDids: string[] = []

  // Walk the chain from signer's issuer upward
  for (const cert of chain) {
    if (cert.role === 'end-entity') continue // Skip the signer itself

    const result = deriveSingleCaDid(cert, country, pki)
    if (result) chainDids.push(result.did)
  }

  // The issuing CA is the first CA above the signer
  const signer = chain.find((c) => c.role === 'end-entity')
  let issuingCaDid: string | null = null
  let derivedVia: PkiDidDerivation['derivedVia'] = null

  if (signer) {
    const issuingCa = chain.find(
      (c) => c.commonName === signer.issuerCommonName && c !== signer,
    )
    if (issuingCa) {
      const result = deriveSingleCaDid(issuingCa, country, pki)
      if (result) {
        issuingCaDid = result.did
        derivedVia = result.via
      }
    }
  }

  // If structured mapping failed, try heuristic derivation
  if (!issuingCaDid && pki.issuingAuthority) {
    const heuristicDid = deriveHeuristic(pki.issuingAuthority, country, pki.certificateType)
    if (heuristicDid) {
      issuingCaDid = heuristicDid
      derivedVia = 'heuristic'
    }
  }

  return { issuingCaDid, chainDids, derivedVia }
}

interface SingleCaResult {
  did: string
  via: 'ca-name-mapping' | 'heuristic'
}

/**
 * Derive did:pki for a single CA certificate.
 */
function deriveSingleCaDid(
  cert: CertificateInfo,
  country: string,
  pki: PkiIdentity,
): SingleCaResult | null {
  const cn = cert.commonName.toUpperCase()
  const countryUpper = country.toUpperCase()
  const mappings = CA_DID_MAPPINGS[countryUpper]

  if (!mappings) {
    // No country-specific mapping — try heuristic
    const did = deriveHeuristic(cert.commonName, country, pki.certificateType)
    return did ? { did, via: 'heuristic' } : null
  }

  // Find the matching CA authority pattern
  for (const mapping of mappings) {
    if (!cn.includes(mapping.pattern)) continue

    // For root CAs, no cert type segment needed
    if (cert.role === 'root' || mapping.path === 'raiz-nacional') {
      return { did: `did:pki:${country}:${mapping.path}`, via: 'ca-name-mapping' }
    }

    // For intermediate/issuing CAs, determine the cert type segment
    const typeSegment = deriveCertTypeSegment(cn, pki.certificateType)
    if (typeSegment) {
      return { did: `did:pki:${country}:${mapping.path}:${typeSegment}`, via: 'ca-name-mapping' }
    }

    // Authority matched but no type segment — return authority-only DID
    return { did: `did:pki:${country}:${mapping.path}`, via: 'ca-name-mapping' }
  }

  return null
}

/**
 * Determine the certificate type path segment from the CA common name
 * or the PKI identity's certificateType.
 */
function deriveCertTypeSegment(
  caCn: string,
  certificateType: string | null,
): string | null {
  // Try direct CN pattern matching first
  const cnUpper = caCn.toUpperCase()
  if (cnUpper.includes('PERSONA FISICA') || cnUpper.includes('PERSONA FÍSICA')) {
    return 'persona-fisica'
  }
  if (cnUpper.includes('PERSONA JURIDICA') || cnUpper.includes('PERSONA JURÍDICA')) {
    return 'persona-juridica'
  }
  if (cnUpper.includes('PERSONA NATURAL')) {
    return 'persona-natural'
  }
  if (cnUpper.includes('SELLO ELECTRONICO') || cnUpper.includes('SELLO ELECTRÓNICO')) {
    return 'sello-electronico'
  }
  if (cnUpper.includes('SELLADO DE TIEMPO')) {
    return 'sellado-de-tiempo'
  }
  if (cnUpper.includes('PESSOA FISICA') || cnUpper.includes('PESSOA FÍSICA')) {
    return 'pessoa-fisica'
  }
  if (cnUpper.includes('PESSOA JURIDICA') || cnUpper.includes('PESSOA JURÍDICA')) {
    return 'pessoa-juridica'
  }

  // Fallback to certificateType from PKI identification
  if (certificateType) {
    return CERT_TYPE_SEGMENTS[certificateType] || null
  }

  return null
}

/**
 * Heuristic derivation when no structured mapping exists.
 * Normalizes the CA name into a did:pki path.
 */
function deriveHeuristic(
  caName: string,
  country: string,
  certificateType: string | null,
): string | null {
  // Normalize: lowercase, strip "CA ", "- COSTA RICA", version suffixes, etc.
  let normalized = caName
    .toUpperCase()
    .replace(/^CA\s+/i, '')
    .replace(/\s*-\s*COSTA RICA.*$/i, '')
    .replace(/\s*V\d+\s*$/i, '')
    .replace(/\s*\(\d{4}\)\s*$/i, '')
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-|-$/g, '')

  if (!normalized) return null

  // Append cert type if it's not already in the name
  const typeSegment = certificateType ? CERT_TYPE_SEGMENTS[certificateType] : null
  if (typeSegment && !normalized.includes(typeSegment)) {
    normalized = `${normalized}:${typeSegment}`
  }

  return `did:pki:${country}:${normalized}`
}

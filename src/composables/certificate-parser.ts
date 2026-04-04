/**
 * X.509 Certificate Parser — PKCS#7 SignedData extraction
 *
 * Extracts certificate chain from PAdES digital signatures.
 * Recognizes known PKI hierarchies across LATAM (CR, MX, CO, BR, CL, PE, AR, EC, UY).
 * No external dependencies — uses the minimal ASN.1 parser.
 *
 * This is v1.5: structure parsing without cryptographic verification.
 * v2 (ATT-209) adds pkijs for signature math, CRL/OCSP validation.
 */

import { PKI_REGISTRY, type PkiRegistryEntry } from './pki-registry.js'
import {
  parseAsn1,
  decodeOid,
  decodeString,
  decodeTime,
  decodeInteger,
  findChild,
  findContext,
  ASN1_TAG,
  type Asn1Node,
} from './asn1-parser.js'
import { logger } from '../logger.js'

const log = logger.verify

// ── Types ─────────────────────────────────────────────────────────

export interface CertificateInfo {
  /** Subject Common Name */
  commonName: string
  /** Subject Organization */
  organization: string | null
  /** Subject Organizational Unit */
  organizationalUnit: string | null
  /** Subject Country */
  country: string | null
  /** Serial number (hex) — for CR Firma Digital, contains the cédula */
  serialNumber: string
  /** Subject serialNumber field (OID 2.5.4.5) — cédula / ID number */
  subjectSerialNumber: string | null
  /** Issuer Common Name */
  issuerCommonName: string
  /** Issuer Organization */
  issuerOrganization: string | null
  /** Validity — not before */
  validFrom: string | null
  /** Validity — not after */
  validTo: string | null
  /** Whether this is a CA certificate (from Basic Constraints) */
  isCa: boolean
  /** Certificate policy OIDs */
  policyOids: string[]
  /** Subject email (from RDN OID 1.2.840.113549.1.9.1) */
  email: string | null
  /** Subject Alternative Names (if present) */
  subjectAltNames: string[]
  /** Key Usage flags (from extension 2.5.29.15) */
  keyUsage: string[]
  /** Extended Key Usage OID labels (from extension 2.5.29.37) */
  extKeyUsage: string[]
  /** Position in chain: 'end-entity' | 'intermediate' | 'root' */
  role: 'end-entity' | 'intermediate' | 'root'
  /** CR-specific: profesión from BCCR extension */
  profesion: string | null
  /** CR-specific: número de colegiado from BCCR extension */
  numeroColegiado: string | null
}

export interface CertificateChainResult {
  /** All certificates found in the SignedData */
  certificates: CertificateInfo[]
  /** The end-entity (signer) certificate */
  signer: CertificateInfo | null
  /** Chain from signer to root: [signer, intermediate..., root] */
  chain: CertificateInfo[]
  /** Recognized PKI name */
  pki: PkiIdentity | null
  /** National ID extracted from signer cert (cédula for CR) */
  nationalId: string | null
  /** Signer name cleaned up (no backslash escapes) */
  signerDisplayName: string | null
  /** Key Usage flags from signer cert (e.g. Digital Signature, Non-Repudiation) */
  keyUsage: string[]
  /** Extended Key Usage labels from signer cert (e.g. Email Protection, Document Signing) */
  extKeyUsage: string[]
  /** Signer email from cert (Subject email or SAN) */
  signerEmail: string | null
}

export interface PkiIdentity {
  /** Short name: "CR Firma Digital" */
  name: string
  /** Full PKI name */
  fullName: string
  /** Country */
  country: string
  /** Root authority */
  rootAuthority: string
  /** Issuing authority (the CA that issued the signer cert) */
  issuingAuthority: string | null
  /** Certificate type: "Persona Física", "Persona Jurídica", "Sello Electrónico" */
  certificateType: string | null
  /** Detection method used: 'oid' | 'ca-name' | 'signer-heuristic' | 'national-id' */
  detectedVia: 'oid' | 'ca-name' | 'signer-heuristic' | 'national-id'
}

// ── Known OIDs ────────────────────────────────────────────────────

const RDN_OIDS: Record<string, string> = {
  '2.5.4.3': 'CN',
  '2.5.4.5': 'serialNumber',
  '2.5.4.6': 'C',
  '2.5.4.7': 'L',
  '2.5.4.8': 'ST',
  '2.5.4.10': 'O',
  '2.5.4.11': 'OU',
  '2.5.4.12': 'title',
  '1.2.840.113549.1.9.1': 'email',
}

const OID_SIGNED_DATA = '1.2.840.113549.1.7.2'

// ── CR-Specific Extension OIDs (BCCR/GAUDI) ─────────────────────
// These are used for extracting national ID from BCCR certificate extensions.
// PKI recognition has moved to pki-registry.ts.

/** BCCR-specific subject attribute OIDs (from SINPE/GAUDI cert extensions) */
const CR_SUBJECT_OIDS: Record<string, string> = {
  '1.3.6.1.4.1.35513.1.2.1': 'cedulaFisica',
  '1.3.6.1.4.1.35513.1.2.2': 'cedulaJuridica',
  '1.3.6.1.4.1.35513.1.5.1.1': 'profesion',
  '1.3.6.1.4.1.35513.1.5.1.2': 'numeroColegiado',
}

// PKI recognition constants have moved to pki-registry.ts.
// CR_ROOT_NAMES, CR_POLICY_*, CR_ID_PREFIXES, CR_OID_LABELS removed.

// ── Key Usage / Extended Key Usage ───────────────────────────────

/** Key Usage bit flags (2.5.29.15) — bit position → label */
const KEY_USAGE_BITS: string[] = [
  'Digital Signature',
  'Non-Repudiation',
  'Key Encipherment',
  'Data Encipherment',
  'Key Agreement',
  'Certificate Signing',
  'CRL Signing',
  'Encipher Only',
  'Decipher Only',
]

/** Extended Key Usage OIDs (2.5.29.37) → human label */
const EKU_OIDS: Record<string, string> = {
  '1.3.6.1.5.5.7.3.1': 'Server Authentication',
  '1.3.6.1.5.5.7.3.2': 'Client Authentication',
  '1.3.6.1.5.5.7.3.3': 'Code Signing',
  '1.3.6.1.5.5.7.3.4': 'Email Protection',
  '1.3.6.1.5.5.7.3.8': 'Time Stamping',
  '1.3.6.1.5.5.7.3.9': 'OCSP Signing',
  '1.3.6.1.4.1.311.10.3.12': 'Document Signing',
  '2.16.840.1.101.2.1.11.10': 'Smart Card Login',
}

// ── Hex Blob Extraction ───────────────────────────────────────────

/**
 * Extract the hex-encoded PKCS#7 blob from a PDF /Contents field.
 * Returns null if not found.
 */
export function extractPkcs7Hex(pdfText: string, sigDictStart: number, sigDictEnd: number): string | null {
  const dict = pdfText.substring(sigDictStart, sigDictEnd)
  const match = dict.match(/\/Contents\s*<([0-9a-fA-F\s]+)>/)
  if (!match) return null
  return match[1].replace(/\s/g, '')
}

/**
 * Convert hex string to Uint8Array.
 */
export function hexToBytes(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2)
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.substring(i, i + 2), 16)
  }
  return bytes
}

// ── PKCS#7 / CMS Parsing ─────────────────────────────────────────

/**
 * Parse a PKCS#7 SignedData structure and extract all embedded certificates.
 */
export function parsePkcs7Certificates(derBytes: Uint8Array): CertificateInfo[] {
  try {
    const root = parseAsn1(derBytes)

    // ContentInfo ::= SEQUENCE { contentType OID, content [0] EXPLICIT }
    if (root.tag !== ASN1_TAG.SEQUENCE || root.children.length < 2) {
      log.warn('PKCS#7: not a valid ContentInfo SEQUENCE')
      return []
    }

    const contentTypeNode = root.children[0]
    if (contentTypeNode.tag !== ASN1_TAG.OID) {
      log.warn('PKCS#7: first child is not an OID')
      return []
    }

    const contentType = decodeOid(contentTypeNode.content)
    if (contentType !== OID_SIGNED_DATA) {
      log.warn(`PKCS#7: contentType is ${contentType}, not SignedData`)
      return []
    }

    // content [0] EXPLICIT → contains the SignedData SEQUENCE
    const contentWrapper = root.children[1]
    if (contentWrapper.tagClass !== 2 || contentWrapper.tagNumber !== 0) {
      log.warn('PKCS#7: missing [0] EXPLICIT wrapper for SignedData')
      return []
    }

    const signedData = contentWrapper.children[0]
    if (!signedData || signedData.tag !== ASN1_TAG.SEQUENCE) {
      log.warn('PKCS#7: SignedData is not a SEQUENCE')
      return []
    }

    // SignedData ::= SEQUENCE {
    //   version, digestAlgorithms, encapContentInfo,
    //   certificates [0] IMPLICIT,  <-- what we want
    //   crls [1] IMPLICIT (optional),
    //   signerInfos
    // }

    // Find certificates [0] IMPLICIT — tag 0xA0
    const certsNode = findContext(signedData, 0)
    if (!certsNode) {
      log.warn('PKCS#7: no certificates [0] found in SignedData')
      return []
    }

    // Parse each certificate in the set
    const certs: CertificateInfo[] = []
    for (const child of certsNode.children) {
      try {
        const cert = parseCertificate(child)
        if (cert) certs.push(cert)
      } catch (e) {
        log.warn(`PKCS#7: failed to parse certificate: ${e}`)
      }
    }

    return certs
  } catch (e) {
    log.warn(`PKCS#7 parse error: ${e}`)
    return []
  }
}

// ── X.509 Certificate Parsing ─────────────────────────────────────

/**
 * Parse a single X.509 certificate from its ASN.1 node.
 */
function parseCertificate(node: Asn1Node): CertificateInfo | null {
  if (node.tag !== ASN1_TAG.SEQUENCE) return null

  // Certificate ::= SEQUENCE { tbsCertificate, signatureAlgorithm, signatureValue }
  const tbs = node.children[0]
  if (!tbs || tbs.tag !== ASN1_TAG.SEQUENCE) return null

  // TBSCertificate ::= SEQUENCE {
  //   version [0] EXPLICIT INTEGER,
  //   serialNumber INTEGER,
  //   signature AlgorithmIdentifier,
  //   issuer Name,
  //   validity SEQUENCE { notBefore, notAfter },
  //   subject Name,
  //   subjectPublicKeyInfo,
  //   ... extensions [3] ...
  // }

  let idx = 0

  // version [0] EXPLICIT (optional — v1 certs don't have it)
  if (tbs.children[idx]?.tagClass === 2 && tbs.children[idx]?.tagNumber === 0) {
    idx++
  }

  // serialNumber
  const serialNode = tbs.children[idx++]
  const serialNumber = serialNode ? decodeInteger(serialNode) : ''

  // signature (AlgorithmIdentifier) — skip
  idx++

  // issuer Name
  const issuerNode = tbs.children[idx++]
  const issuerFields = issuerNode ? parseRdnSequence(issuerNode) : {}

  // validity
  const validityNode = tbs.children[idx++]
  let validFrom: string | null = null
  let validTo: string | null = null
  if (validityNode && validityNode.children.length >= 2) {
    try {
      validFrom = decodeTime(validityNode.children[0])
    } catch {
      /* ignore */
    }
    try {
      validTo = decodeTime(validityNode.children[1])
    } catch {
      /* ignore */
    }
  }

  // subject Name
  const subjectNode = tbs.children[idx++]
  const subjectFields = subjectNode ? parseRdnSequence(subjectNode) : {}

  // Skip subjectPublicKeyInfo
  idx++

  // Parse extensions [3] for BasicConstraints, policies, and CR-specific attributes
  let isCa = false
  const policyOids: string[] = []
  const subjectAltNames: string[] = []
  const keyUsage: string[] = []
  const extKeyUsage: string[] = []
  let profesion: string | null = null
  let numeroColegiado: string | null = null

  const extensionsWrapper = findContext(tbs, 3)
  if (extensionsWrapper && extensionsWrapper.children.length > 0) {
    const extensions = extensionsWrapper.children[0]
    if (extensions) {
      for (const ext of extensions.children) {
        parseExtension(ext, {
          isCa: (v) => (isCa = v),
          policyOids,
          subjectAltNames,
          keyUsage,
          extKeyUsage,
          onCrAttribute: (key, value) => {
            if (key === 'profesion') profesion = value
            if (key === 'numeroColegiado') numeroColegiado = value
          },
        })
      }
    }
  }

  return {
    commonName: subjectFields['CN'] || 'Unknown',
    organization: subjectFields['O'] || null,
    organizationalUnit: subjectFields['OU'] || null,
    country: subjectFields['C'] || null,
    serialNumber,
    subjectSerialNumber: subjectFields['serialNumber'] || null,
    issuerCommonName: issuerFields['CN'] || 'Unknown',
    issuerOrganization: issuerFields['O'] || null,
    validFrom,
    validTo,
    email: subjectFields['email'] || null,
    isCa,
    policyOids,
    subjectAltNames,
    keyUsage,
    extKeyUsage,
    role: 'end-entity', // Will be assigned by chain builder
    profesion,
    numeroColegiado,
  }
}

/**
 * Parse a Name (RDN SEQUENCE) into a field map.
 */
function parseRdnSequence(node: Asn1Node): Record<string, string> {
  const fields: Record<string, string> = {}

  // Name ::= SEQUENCE OF RelativeDistinguishedName
  // RDN ::= SET OF AttributeTypeAndValue
  // ATV ::= SEQUENCE { type OID, value ANY }
  for (const rdn of node.children) {
    if (rdn.tag !== ASN1_TAG.SET) continue
    for (const atv of rdn.children) {
      if (atv.tag !== ASN1_TAG.SEQUENCE || atv.children.length < 2) continue
      const oidNode = atv.children[0]
      const valueNode = atv.children[1]
      if (oidNode.tag !== ASN1_TAG.OID) continue

      const oid = decodeOid(oidNode.content)
      const fieldName = RDN_OIDS[oid] || oid
      const value = decodeString(valueNode)
      fields[fieldName] = value
    }
  }

  return fields
}

/**
 * Parse a single X.509 extension.
 */
function parseExtension(
  ext: Asn1Node,
  out: {
    isCa: (v: boolean) => void
    policyOids: string[]
    subjectAltNames: string[]
    keyUsage: string[]
    extKeyUsage: string[]
    onCrAttribute: (key: string, value: string) => void
  },
): void {
  if (ext.tag !== ASN1_TAG.SEQUENCE || ext.children.length < 2) return

  const oidNode = ext.children[0]
  if (oidNode.tag !== ASN1_TAG.OID) return
  const oid = decodeOid(oidNode.content)

  // Check for CR BCCR-specific subject attribute OIDs (may not be wrapped in OCTET STRING)
  const crField = CR_SUBJECT_OIDS[oid]
  if (crField) {
    // Try to extract value from the extension
    for (const child of ext.children) {
      if (child.tag !== ASN1_TAG.OID && child.tag !== 0x01) {
        // 0x01 = BOOLEAN (critical flag)
        const value = decodeString(child)
        if (value) out.onCrAttribute(crField, value)
      }
    }
  }

  // Find the extension value (OCTET STRING — may be 2nd or 3rd child depending on critical flag)
  const valueNode = ext.children.find((c) => c.tag === ASN1_TAG.OCTET_STRING)
  if (!valueNode) return

  try {
    const inner = parseAsn1(valueNode.content)

    // 2.5.29.19 = BasicConstraints
    if (oid === '2.5.29.19') {
      if (inner.tag === ASN1_TAG.SEQUENCE) {
        const caNode = inner.children[0]
        if (caNode && caNode.tag === 0x01 && caNode.content[0] !== 0) {
          out.isCa(true)
        }
      }
    }

    // 2.5.29.32 = CertificatePolicies
    if (oid === '2.5.29.32') {
      if (inner.tag === ASN1_TAG.SEQUENCE) {
        for (const policyInfo of inner.children) {
          if (policyInfo.tag === ASN1_TAG.SEQUENCE && policyInfo.children.length > 0) {
            const policyOid = policyInfo.children[0]
            if (policyOid.tag === ASN1_TAG.OID) {
              out.policyOids.push(decodeOid(policyOid.content))
            }
          }
        }
      }
    }

    // 2.5.29.17 = SubjectAlternativeName
    if (oid === '2.5.29.17') {
      if (inner.tag === ASN1_TAG.SEQUENCE) {
        for (const name of inner.children) {
          if (name.tagClass === 2) {
            out.subjectAltNames.push(decodeString(name))
          }
        }
      }
    }

    // 2.5.29.15 = KeyUsage (BIT STRING)
    if (oid === '2.5.29.15') {
      if (inner.tag === ASN1_TAG.BIT_STRING && inner.content.length >= 2) {
        const unusedBits = inner.content[0]
        const bytes = inner.content.slice(1)
        for (let byteIdx = 0; byteIdx < bytes.length; byteIdx++) {
          for (let bit = 7; bit >= 0; bit--) {
            const bitPos = byteIdx * 8 + (7 - bit)
            if (bitPos >= KEY_USAGE_BITS.length) break
            // Skip unused trailing bits in the last byte
            if (byteIdx === bytes.length - 1 && (7 - bit) < unusedBits) continue
            if (bytes[byteIdx] & (1 << bit)) {
              out.keyUsage.push(KEY_USAGE_BITS[bitPos])
            }
          }
        }
      }
    }

    // 2.5.29.37 = ExtendedKeyUsage (SEQUENCE OF OID)
    if (oid === '2.5.29.37') {
      if (inner.tag === ASN1_TAG.SEQUENCE) {
        for (const ekuOid of inner.children) {
          if (ekuOid.tag === ASN1_TAG.OID) {
            const oidStr = decodeOid(ekuOid.content)
            out.extKeyUsage.push(EKU_OIDS[oidStr] || oidStr)
          }
        }
      }
    }
  } catch {
    // Extension parsing is best-effort
  }
}

// ── Chain Builder ─────────────────────────────────────────────────

/**
 * Build the certificate chain from signer to root.
 * Assigns roles: end-entity, intermediate, root.
 */
function buildChain(certs: CertificateInfo[]): CertificateInfo[] {
  if (certs.length === 0) return []

  // Identify roles
  for (const cert of certs) {
    if (cert.commonName === cert.issuerCommonName) {
      cert.role = 'root'
    } else if (cert.isCa) {
      cert.role = 'intermediate'
    } else {
      cert.role = 'end-entity'
    }
  }

  // Find the end-entity (signer) certificate
  const signer = certs.find((c) => c.role === 'end-entity')
  if (!signer) {
    // All are CAs — return sorted by chain
    return certs
  }

  // Build chain: signer → intermediate(s) → root
  const chain: CertificateInfo[] = [signer]
  let current = signer
  const maxDepth = certs.length // prevent infinite loops

  for (let i = 0; i < maxDepth; i++) {
    if (current.commonName === current.issuerCommonName) break // reached root
    const issuer = certs.find(
      (c) => c.commonName === current.issuerCommonName && c !== current,
    )
    if (!issuer) break
    chain.push(issuer)
    current = issuer
  }

  return chain
}

// ── PKI Recognition ───────────────────────────────────────────────

/**
 * Identify the PKI hierarchy from the certificate chain.
 * Iterates the multi-country PKI registry with 4 detection strategies:
 *   1. OID-based (most reliable) — checks certificate policy OIDs
 *   2. Root CA name matching — checks root cert CN
 *   3. Signer name heuristic — checks for known suffixes like "(FIRMA)"
 *   4. National ID prefix — checks serialNumber field prefixes
 */
function identifyPki(chain: CertificateInfo[]): PkiIdentity | null {
  const allPolicyOids = chain.flatMap((c) => c.policyOids)
  const root = chain.find((c) => c.role === 'root')
  const rootName = root?.commonName?.toUpperCase() || ''
  const signer = chain.find((c) => c.role === 'end-entity')
  const signerName = signer?.commonName?.toUpperCase() || ''
  const allCaNames = chain.map((c) => c.commonName?.toUpperCase() || '')
  const allOrgs = chain.map((c) => c.organization?.toUpperCase() || '')

  for (const entry of PKI_REGISTRY) {
    let detectedVia: PkiIdentity['detectedVia'] | null = null

    // Strategy 1: OID match (any policy OID starts with the entry's arc or matches exactly)
    const hasOid = allPolicyOids.some(
      (oid) => entry.policyOids.includes(oid) || oid.startsWith(entry.oidArc + '.'),
    )
    if (hasOid) detectedVia = 'oid'

    // Strategy 2: Root CA name match
    if (!detectedVia) {
      const hasRootName = entry.rootCaNames.some((n) => rootName.includes(n))
      if (hasRootName) detectedVia = 'ca-name'
    }

    // Strategy 3: Issuer org match (check all certs in chain)
    if (!detectedVia) {
      const hasOrg = entry.issuerOrgPatterns.some((p) => allOrgs.some((o) => o.includes(p)))
      if (hasOrg) detectedVia = 'ca-name'
    }

    // Strategy 4: Signer name pattern
    if (!detectedVia && entry.signerPatterns.length > 0) {
      const hasPattern = entry.signerPatterns.some((p) => signerName.includes(p))
      if (hasPattern) detectedVia = 'signer-heuristic'
    }

    // Strategy 5: National ID prefix
    if (!detectedVia && entry.idPrefixes.length > 0 && signer?.subjectSerialNumber) {
      const hasId = entry.idPrefixes.some((p) => signer.subjectSerialNumber!.startsWith(p))
      if (hasId) detectedVia = 'national-id'
    }

    if (!detectedVia) continue

    // ── Match found — determine certificate type ──
    const certificateType = determineCertType(entry, allPolicyOids, allCaNames)

    // Find the issuing CA
    const issuingCa = signer
      ? chain.find((c) => c.commonName === signer.issuerCommonName && c.role !== 'end-entity')
      : null

    return {
      name: entry.name,
      fullName: entry.fullName,
      country: entry.countryCode,
      rootAuthority: root?.commonName || entry.rootAuthority,
      issuingAuthority: issuingCa?.commonName || null,
      certificateType,
      detectedVia,
    }
  }

  return null
}

/**
 * Determine certificate type from a matched PKI entry.
 * Tries OID-based rules first, then CA name patterns.
 */
function determineCertType(
  entry: PkiRegistryEntry,
  policyOids: string[],
  caNames: string[],
): string | null {
  // OID rules first (most reliable)
  for (const rule of entry.certTypeRules) {
    if (rule.match === 'oid' && policyOids.includes(rule.pattern)) {
      return rule.label
    }
  }
  // CA name rules (fallback)
  for (const rule of entry.certTypeRules) {
    if (rule.match === 'ca-name' && caNames.some((n) => n.includes(rule.pattern))) {
      return rule.label
    }
  }
  return null
}

// ── Clean Display Name ────────────────────────────────────────────

/**
 * Clean up signer name — remove backslash escapes from PDF encoding.
 * e.g. "GUILLERMO CHAVARRIA CRUZ \\(FIRMA\\)" → "GUILLERMO CHAVARRIA CRUZ (FIRMA)"
 */
export function cleanSignerName(name: string): string {
  return name.replace(/\\(.)/g, '$1')
}

// ── Email Extraction ─────────────────────────────────────────────

/**
 * Extract signer email from Subject RDN (email field) or SAN (rfc822Name).
 */
function extractSignerEmail(signer: CertificateInfo | null): string | null {
  if (!signer) return null

  // 1. Subject RDN email field (OID 1.2.840.113549.1.9.1)
  if (signer.email) return signer.email.toLowerCase()

  // 2. SAN rfc822Name entries (email addresses in Subject Alternative Names)
  for (const san of signer.subjectAltNames) {
    if (san.includes('@')) return san.toLowerCase()
  }

  return null
}

// ── Main Entry Point ──────────────────────────────────────────────

/**
 * Extract and parse the certificate chain from a PKCS#7 hex blob.
 */
export function parseCertificateChain(pkcs7Hex: string): CertificateChainResult {
  const empty: CertificateChainResult = {
    certificates: [],
    signer: null,
    chain: [],
    pki: null,
    nationalId: null,
    signerDisplayName: null,
    keyUsage: [],
    extKeyUsage: [],
    signerEmail: null,
  }

  if (!pkcs7Hex || pkcs7Hex.length < 10) return empty

  try {
    const derBytes = hexToBytes(pkcs7Hex)
    log.info(`[cert] Parsing PKCS#7 blob (${derBytes.length} bytes)`)

    const certificates = parsePkcs7Certificates(derBytes)
    log.info(`[cert] Found ${certificates.length} certificate(s) in SignedData`)

    if (certificates.length === 0) return empty

    // Build chain
    const chain = buildChain(certificates)
    const signer = chain.find((c) => c.role === 'end-entity') || null

    // Log chain
    for (const cert of chain) {
      log.info(
        `[cert]   ${cert.role === 'root' ? '🏛️' : cert.role === 'intermediate' ? '🔗' : '✍️'} ${cert.role}: ${cert.commonName}${cert.organization ? ` (${cert.organization})` : ''}`,
      )
    }

    // Identify PKI
    const pki = identifyPki(chain)
    if (pki) {
      log.event(`[cert] PKI identified: ${pki.name} — ${pki.certificateType || 'Unknown type'}`)
    }

    // Extract national ID from signer cert
    const nationalId = signer?.subjectSerialNumber || null
    if (nationalId) {
      log.info(`[cert] National ID (cédula): ${nationalId}`)
    }

    // Clean display name
    const signerDisplayName = signer ? cleanSignerName(signer.commonName) : null

    // Extract signer email — from Subject RDN email field or SAN
    const signerEmail = extractSignerEmail(signer)

    return {
      certificates,
      signer,
      chain,
      pki,
      nationalId,
      signerDisplayName,
      keyUsage: signer?.keyUsage ?? [],
      extKeyUsage: signer?.extKeyUsage ?? [],
      signerEmail,
    }
  } catch (e) {
    log.warn(`Certificate chain parse error: ${e}`)
    return empty
  }
}

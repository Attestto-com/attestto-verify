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
import { validateChain, validateChainWithResolver } from './chain-validator-client.js'
import { derivePkiDids } from './pki-did-derivation.js'

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
  /**
   * Raw DER bytes of this certificate as a hex string. Captured at parse time
   * so the chain validator (`chain-validator.ts`) can re-decode the cert with
   * pkijs and run real cryptographic chain validation against bundled BCCR
   * trust anchors. Without this, only structure parsing is possible.
   */
  rawDerHex: string
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
  /**
   * SECURITY: Has the certificate chain been cryptographically verified
   * against a bundled trust anchor (root CA fingerprint pinned, signature
   * walked end-to-end with WebCrypto / pkijs)?
   *
   * As of v1.5 this is ALWAYS `false` — the parser only walks the ASN.1
   * structure and matches root CA names against `pki-registry.ts` patterns.
   * No `child.verify(parent.publicKey)` is performed and no trust anchor
   * fingerprint is pinned. UI MUST treat the signature as "structure-only"
   * and never claim cryptographic trust.
   *
   * v2 (ATT-209, `docs/v2-pkijs-implementation-guide.md`) will set this
   * to `true` once `pkijs.CertificateChainValidationEngine` is wired in.
   */
  cryptographicallyVerified: boolean
  /**
   * SECURITY: Human-readable warning surfaced when the result is consumed
   * by a UI. Set whenever `cryptographicallyVerified === false`.
   */
  cryptoVerificationWarning: string | null
  /**
   * The did:pki identifier derived for the issuing CA (ATT-438).
   * Set when PKI is identified and a did:pki path can be derived.
   * Used for resolver-backed trust anchor resolution.
   */
  pkiDid: string | null
  /**
   * How trust was established: 'bundled' (local certs) or 'resolver'
   * (dynamic resolution via resolver.attestto.com). ATT-438.
   */
  trustSource: 'bundled' | 'resolver' | null
  /** National ID format hint from did:pki resolution (e.g. "CR-cedula", "BR-cpf") */
  nationalIdFormat: string | null
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

/**
 * Convert Uint8Array to hex string (lowercase, no separators).
 */
export function bytesToHex(bytes: Uint8Array): string {
  let hex = ''
  for (let i = 0; i < bytes.length; i++) {
    hex += bytes[i].toString(16).padStart(2, '0')
  }
  return hex
}

// ── PKCS#7 / CMS Parsing ─────────────────────────────────────────

/** Issuer + serial extracted from PKCS#7 SignerInfo — identifies the actual signer cert */
export interface SignerIdentifier {
  issuerCN: string
  serial: string
}

/**
 * Parse a PKCS#7 SignedData structure and extract all embedded certificates.
 * Also extracts the SignerInfo issuer+serial to correctly identify the signer cert
 * when multiple non-CA certificates are present (e.g., CAdES with system + person certs).
 */
export function parsePkcs7Certificates(derBytes: Uint8Array): {
  certs: CertificateInfo[]
  signerIdentifier: SignerIdentifier | null
} {
  try {
    const root = parseAsn1(derBytes)

    // ContentInfo ::= SEQUENCE { contentType OID, content [0] EXPLICIT }
    if (root.tag !== ASN1_TAG.SEQUENCE || root.children.length < 2) {
      log.warn('PKCS#7: not a valid ContentInfo SEQUENCE')
      return { certs: [], signerIdentifier: null }
    }

    const contentTypeNode = root.children[0]
    if (contentTypeNode.tag !== ASN1_TAG.OID) {
      log.warn('PKCS#7: first child is not an OID')
      return { certs: [], signerIdentifier: null }
    }

    const contentType = decodeOid(contentTypeNode.content)
    if (contentType !== OID_SIGNED_DATA) {
      log.warn(`PKCS#7: contentType is ${contentType}, not SignedData`)
      return { certs: [], signerIdentifier: null }
    }

    // content [0] EXPLICIT → contains the SignedData SEQUENCE
    const contentWrapper = root.children[1]
    if (contentWrapper.tagClass !== 2 || contentWrapper.tagNumber !== 0) {
      log.warn('PKCS#7: missing [0] EXPLICIT wrapper for SignedData')
      return { certs: [], signerIdentifier: null }
    }

    const signedData = contentWrapper.children[0]
    if (!signedData || signedData.tag !== ASN1_TAG.SEQUENCE) {
      log.warn('PKCS#7: SignedData is not a SEQUENCE')
      return { certs: [], signerIdentifier: null }
    }

    // SignedData ::= SEQUENCE {
    //   version, digestAlgorithms, encapContentInfo,
    //   certificates [0] IMPLICIT,  <-- what we want
    //   crls [1] IMPLICIT (optional),
    //   signerInfos SET
    // }

    // Find certificates [0] IMPLICIT — tag 0xA0
    const certsNode = findContext(signedData, 0)
    if (!certsNode) {
      log.warn('PKCS#7: no certificates [0] found in SignedData')
      return { certs: [], signerIdentifier: null }
    }

    // Parse each certificate in the set
    const certs: CertificateInfo[] = []
    for (const child of certsNode.children) {
      try {
        const cert = parseCertificate(child)
        if (cert) {
          // Capture the raw DER bytes of THIS certificate so the chain
          // validator can re-decode and verify it cryptographically.
          const certEnd = child.contentOffset + child.contentLength
          const rawDer = derBytes.subarray(child.nodeStart, certEnd)
          cert.rawDerHex = bytesToHex(rawDer)
          certs.push(cert)
        }
      } catch (e) {
        log.warn(`PKCS#7: failed to parse certificate: ${e}`)
      }
    }

    // Extract SignerInfo issuer+serial to identify the actual signer cert.
    // signerInfos is the last SET in SignedData.
    // SignerInfo ::= SEQUENCE { version, sid SignerIdentifier, ... }
    // SignerIdentifier ::= CHOICE { issuerAndSerialNumber IssuerAndSerialNumber }
    // IssuerAndSerialNumber ::= SEQUENCE { issuer Name, serialNumber INTEGER }
    let signerIdentifier: SignerIdentifier | null = null
    try {
      const signerInfosNode = signedData.children.find(
        (c) => c.tag === ASN1_TAG.SET && c !== signedData.children[1],
      )
      if (signerInfosNode && signerInfosNode.children.length > 0) {
        const firstSignerInfo = signerInfosNode.children[0]
        if (firstSignerInfo.tag === ASN1_TAG.SEQUENCE && firstSignerInfo.children.length >= 2) {
          // Skip version (INTEGER), next should be issuerAndSerialNumber (SEQUENCE)
          const sidNode = firstSignerInfo.children[1]
          if (sidNode.tag === ASN1_TAG.SEQUENCE && sidNode.children.length >= 2) {
            const issuerFields = parseRdnSequence(sidNode.children[0])
            const serial = decodeInteger(sidNode.children[1])
            signerIdentifier = {
              issuerCN: issuerFields.CN || issuerFields.O || '',
              serial,
            }
            log.info(`[cert] SignerInfo identifies: issuer=${signerIdentifier.issuerCN}, serial=${serial.substring(0, 20)}...`)
          }
        }
      }
    } catch (e) {
      log.warn(`[cert] Could not extract SignerInfo identifier: ${e}`)
    }

    return { certs, signerIdentifier }
  } catch (e) {
    log.warn(`PKCS#7 parse error: ${e}`)
    return { certs: [], signerIdentifier: null }
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
    rawDerHex: '', // Filled in by parsePkcs7Certificates after parseCertificate returns
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
 *
 * When `signerIdentifier` is provided (from PKCS#7 SignerInfo), uses it to
 * disambiguate between multiple non-CA certificates (e.g., CAdES signatures
 * that embed both a system/service cert and the actual person's cert).
 */
function buildChain(
  certs: CertificateInfo[],
  signerIdentifier?: SignerIdentifier | null,
): CertificateInfo[] {
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

  // When multiple end-entity certs exist, use SignerInfo to pick the real signer.
  // The SignerInfo contains the issuer+serial of the cert that actually signed.
  const endEntities = certs.filter((c) => c.role === 'end-entity')
  if (endEntities.length > 1 && signerIdentifier) {
    const matched = endEntities.find(
      (c) =>
        c.serialNumber === signerIdentifier.serial ||
        (c.issuerCommonName === signerIdentifier.issuerCN &&
          c.serialNumber === signerIdentifier.serial),
    )
    if (matched) {
      // Demote all other end-entities — they are ancillary certs (service certs, TSA, etc.)
      for (const ee of endEntities) {
        if (ee !== matched) {
          ee.role = 'intermediate' // or could be 'ancillary' but intermediate keeps the chain logic working
          log.info(`[cert] Demoted ${ee.commonName} — not the SignerInfo signer`)
        }
      }
      log.info(`[cert] SignerInfo matched signer: ${matched.commonName}`)
    } else {
      log.warn(`[cert] SignerInfo serial did not match any end-entity cert`)
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
 * Extract and parse the certificate chain from a PKCS#7 hex blob, then run
 * REAL cryptographic chain validation against bundled BCCR trust anchors.
 *
 * This function is async because chain validation lazy-loads pkijs (~250KB).
 */
export async function parseCertificateChain(
  pkcs7Hex: string,
): Promise<CertificateChainResult> {
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
    cryptographicallyVerified: false,
    cryptoVerificationWarning:
      'Certificate parser v1.5: ASN.1 structure parsed only — chain signatures NOT cryptographically verified against bundled trust anchors. Treat results as informational, not as proof of trust. v2 (pkijs) wiring tracked in ATT-209.',
    pkiDid: null,
    trustSource: null,
    nationalIdFormat: null,
  }

  if (!pkcs7Hex || pkcs7Hex.length < 10) return empty

  try {
    const derBytes = hexToBytes(pkcs7Hex)
    log.info(`[cert] Parsing PKCS#7 blob (${derBytes.length} bytes)`)

    const { certs: certificates, signerIdentifier } = parsePkcs7Certificates(derBytes)
    log.info(`[cert] Found ${certificates.length} certificate(s) in SignedData`)

    if (certificates.length === 0) return empty

    // Build chain — pass signerIdentifier so it can disambiguate multiple end-entity certs
    const chain = buildChain(certificates, signerIdentifier)
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

    // Extract national ID from signer cert (default: serialNumber)
    let nationalId = signer?.subjectSerialNumber || null
    if (nationalId) {
      log.info(`[cert] National ID (cédula): ${nationalId}`)
    }

    // Clean display name
    let signerDisplayName = signer ? cleanSignerName(signer.commonName) : null

    // Extract signer email — from Subject RDN email field or SAN
    const signerEmail = extractSignerEmail(signer)

    // ── Derive did:pki for resolver-backed validation (ATT-438) ──
    const pkiDids = derivePkiDids(chain, pki)
    const pkiDid = pkiDids.issuingCaDid
    if (pkiDid) {
      log.info(`[cert] Derived did:pki: ${pkiDid} (via ${pkiDids.derivedVia})`)
    }

    // ── Chain validation: resolver-backed with bundled fallback ──
    // Uses resolver.attestto.com for dynamic trust anchor resolution (ATT-438),
    // falling back to bundled BCCR trust anchors (ATT-209).
    let cryptographicallyVerified = false
    let cryptoVerificationWarning: string | null =
      'Chain validation has not been attempted (no signer cert).'
    let trustSource: 'bundled' | 'resolver' | null = null
    let endEntityHints: Record<string, import('./pki-resolver.js').EndEntityHint> | null = null

    if (signer && signer.rawDerHex) {
      try {
        const intermediates = chain
          .filter((c) => c !== signer && c.rawDerHex)
          .map((c) => c.rawDerHex)

        // Use resolver-backed validation (falls back to bundled internally)
        const result = await validateChainWithResolver(
          signer.rawDerHex,
          intermediates,
          pkiDid,
        )

        endEntityHints = result.endEntityHints ?? null

        if (result.trusted) {
          cryptographicallyVerified = true
          cryptoVerificationWarning = null
          trustSource = result.trustSource || 'bundled'
          log.event(
            `[cert] ✓ Chain CRYPTOGRAPHICALLY VERIFIED — anchor: ${result.anchorCommonName} ` +
              `(length: ${result.chainLength}, source: ${trustSource}` +
              `${result.pkiDid ? `, did: ${result.pkiDid}` : ''})`,
          )
        } else {
          cryptographicallyVerified = false
          cryptoVerificationWarning =
            `Cryptographic chain validation FAILED: ${result.error || 'unknown error'}. ` +
            'Structure was parsed but the chain does not link to any trusted anchor ' +
            '(checked resolver.attestto.com and bundled certs). ' +
            'The signature may be forged, self-signed, or issued by a CA we do not trust.'
          log.warn(`[cert] ✗ Chain validation failed: ${result.error}`)
        }
      } catch (err) {
        const message = err instanceof Error ? err.message : String(err)
        cryptographicallyVerified = false
        cryptoVerificationWarning = `Chain validator threw: ${message}`
        log.warn(`[cert] Chain validator exception: ${message}`)
      }
    } else if (signer) {
      cryptoVerificationWarning =
        'Signer certificate raw DER not captured — chain validation skipped.'
    }

    // ── Apply endEntityHints to refine identity extraction (ATT-427) ──
    // Hints from the did:pki DID Document tell us which X.509 fields contain
    // the national ID, name, etc. for this specific cert type and country.
    let nationalIdFormat: string | null = null
    if (endEntityHints && pki?.certificateType && signer) {
      const hint = endEntityHints[pki.certificateType]
      if (hint) {
        log.info(`[cert] Applying endEntityHints for "${pki.certificateType}"`)
        nationalIdFormat = hint.nationalIdFormat || null

        // Map hint field names to CertificateInfo properties
        const fieldMap: Record<string, string | null> = {
          serialNumber: signer.subjectSerialNumber,
          CN: signer.commonName,
          O: signer.organization,
          OU: signer.organizationalUnit,
          emailAddress: signer.email,
        }

        // Override national ID if hint points to a different field
        if (hint.nationalIdField && hint.nationalIdField !== 'serialNumber') {
          const hintedId = fieldMap[hint.nationalIdField] ?? null
          if (hintedId) {
            nationalId = hintedId
            log.info(`[cert] Hint: nationalId from ${hint.nationalIdField}: ${hintedId}`)
          }
        }

        // Override display name if hint specifies a different field
        if (hint.nameField && hint.nameField !== 'CN') {
          const hintedName = fieldMap[hint.nameField] ?? null
          if (hintedName) {
            signerDisplayName = cleanSignerName(hintedName)
            log.info(`[cert] Hint: signerDisplayName from ${hint.nameField}`)
          }
        }
      }
    }

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
      cryptographicallyVerified,
      cryptoVerificationWarning,
      pkiDid,
      trustSource,
      nationalIdFormat,
    }
  } catch (e) {
    log.warn(`Certificate chain parse error: ${e}`)
    return empty
  }
}

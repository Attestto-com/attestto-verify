/**
 * Revocation Checker — OCSP + CRL parsing for offline revocation verification
 *
 * Parses OCSP responses and CRLs extracted from the PDF's /DSS dictionary.
 * Uses the minimal ASN.1 parser — no external dependencies, no network calls.
 *
 * OCSP Response structure (RFC 6960):
 *   OCSPResponse ::= SEQUENCE {
 *     responseStatus  ENUMERATED,
 *     responseBytes   [0] EXPLICIT SEQUENCE {
 *       responseType    OID (id-pkix-ocsp-basic),
 *       response        OCTET STRING (BasicOCSPResponse DER)
 *     }
 *   }
 *   BasicOCSPResponse ::= SEQUENCE {
 *     tbsResponseData  SEQUENCE {
 *       version         [0] EXPLICIT INTEGER OPTIONAL,
 *       responderID     [1] or [2],
 *       producedAt      GeneralizedTime,
 *       responses       SEQUENCE OF SingleResponse
 *     },
 *     signatureAlgorithm ...,
 *     signature          ...
 *   }
 *   SingleResponse ::= SEQUENCE {
 *     certID            SEQUENCE { hashAlgo, issuerNameHash, issuerKeyHash, serialNumber },
 *     certStatus        CHOICE { good [0], revoked [1], unknown [2] },
 *     thisUpdate        GeneralizedTime,
 *     nextUpdate        [0] EXPLICIT GeneralizedTime OPTIONAL
 *   }
 *
 * CRL structure (RFC 5280):
 *   CertificateList ::= SEQUENCE {
 *     tbsCertList  SEQUENCE {
 *       version         INTEGER OPTIONAL,
 *       signature       AlgorithmIdentifier,
 *       issuer          Name,
 *       thisUpdate      Time,
 *       nextUpdate      Time OPTIONAL,
 *       revokedCertificates SEQUENCE OF SEQUENCE {
 *         userCertificate    CertificateSerialNumber (INTEGER),
 *         revocationDate     Time,
 *         crlEntryExtensions Extensions OPTIONAL
 *       } OPTIONAL
 *     },
 *     signatureAlgorithm ...,
 *     signature          BIT STRING
 *   }
 */

import {
  parseAsn1,
  decodeInteger,
  decodeTime,
  findChild,
  findContext,
  ASN1_TAG,
  type Asn1Node,
} from './asn1-parser.js'
import { logger } from '../logger.js'

const log = logger.verify

// ── Types ──────────────────────────────────────────────────────────

export type RevocationStatus =
  | 'good'               // OCSP says good, or cert serial not in CRL
  | 'revoked'            // OCSP says revoked, or cert serial found in CRL
  | 'unknown'            // OCSP says unknown
  | 'no-data'            // No OCSP/CRL data available (no LTV)
  | 'parse-error'        // Could not parse the embedded data

export interface RevocationResult {
  status: RevocationStatus
  /** Human-readable message */
  message: string
  /** Source of the revocation data */
  source: 'ocsp' | 'crl' | 'none'
  /** When the OCSP response or CRL was produced */
  producedAt: string | null
  /** When the revocation happened (only if revoked) */
  revokedAt: string | null
}

export interface OcspSingleResponse {
  /** Serial number of the certificate (hex) */
  certSerial: string
  /** Certificate status: 0=good, 1=revoked, 2=unknown */
  status: 'good' | 'revoked' | 'unknown'
  /** thisUpdate timestamp */
  thisUpdate: string | null
  /** nextUpdate timestamp */
  nextUpdate: string | null
  /** Revocation time (only if revoked) */
  revokedAt: string | null
}

export interface ParsedOcspResponse {
  /** OCSP response status: 0=successful */
  responseStatus: number
  /** When the response was produced */
  producedAt: string | null
  /** Individual certificate responses */
  responses: OcspSingleResponse[]
}

export interface CrlRevokedEntry {
  /** Serial number of the revoked certificate (hex) */
  serial: string
  /** Date the certificate was revoked */
  revocationDate: string | null
}

export interface ParsedCrl {
  /** Issuer distinguished name (raw, for matching) */
  issuerDN: string | null
  /** When this CRL was issued */
  thisUpdate: string | null
  /** When the next CRL will be issued */
  nextUpdate: string | null
  /** List of revoked certificate entries */
  revokedCertificates: CrlRevokedEntry[]
}

// ── OCSP Response Parsing ──────────────────────────────────────────

/**
 * Parse a DER-encoded OCSP response.
 */
export function parseOcspResponse(der: Uint8Array): ParsedOcspResponse | null {
  try {
    const root = parseAsn1(der)
    if (root.tag !== ASN1_TAG.SEQUENCE || root.children.length < 1) return null

    // responseStatus is an ENUMERATED (tag 0x0a)
    const statusNode = root.children[0]
    const responseStatus = statusNode.content[0] ?? -1

    // If not successful (0), no response bytes
    if (responseStatus !== 0) {
      return { responseStatus, producedAt: null, responses: [] }
    }

    // responseBytes is [0] EXPLICIT SEQUENCE
    const responseBytesCtx = findContext(root, 0)
    if (!responseBytesCtx || responseBytesCtx.children.length === 0) return null

    const responseBytesSeq = responseBytesCtx.children[0]
    if (responseBytesSeq.children.length < 2) return null

    // response is OCTET STRING containing BasicOCSPResponse DER
    const responseOctet = responseBytesSeq.children[1]
    const basicResp = parseAsn1(responseOctet.content)

    return parseBasicOcspResponse(basicResp, responseStatus)
  } catch (err) {
    log.warn(`[revocation] Failed to parse OCSP response: ${err}`)
    return null
  }
}

function parseBasicOcspResponse(
  basicResp: Asn1Node,
  responseStatus: number,
): ParsedOcspResponse | null {
  if (basicResp.tag !== ASN1_TAG.SEQUENCE || basicResp.children.length < 1) return null

  const tbsResponseData = basicResp.children[0]
  if (tbsResponseData.tag !== ASN1_TAG.SEQUENCE) return null

  // Navigate tbsResponseData children
  // Structure varies based on whether version [0] is present
  let idx = 0

  // Skip version [0] if present
  if (
    tbsResponseData.children[idx]?.tagClass === 2 &&
    tbsResponseData.children[idx]?.tagNumber === 0
  ) {
    idx++
  }

  // Skip responderID [1] or [2]
  if (tbsResponseData.children[idx]?.tagClass === 2) {
    idx++
  }

  // producedAt — GeneralizedTime
  let producedAt: string | null = null
  if (
    idx < tbsResponseData.children.length &&
    tbsResponseData.children[idx].tag === ASN1_TAG.GENERALIZED_TIME
  ) {
    producedAt = decodeTime(tbsResponseData.children[idx])
    idx++
  }

  // responses — SEQUENCE OF SingleResponse
  const responses: OcspSingleResponse[] = []
  if (idx < tbsResponseData.children.length) {
    const responsesSeq = tbsResponseData.children[idx]
    if (responsesSeq.tag === ASN1_TAG.SEQUENCE) {
      for (const singleResp of responsesSeq.children) {
        const parsed = parseSingleResponse(singleResp)
        if (parsed) responses.push(parsed)
      }
    }
  }

  return { responseStatus, producedAt, responses }
}

function parseSingleResponse(node: Asn1Node): OcspSingleResponse | null {
  if (node.tag !== ASN1_TAG.SEQUENCE || node.children.length < 3) return null

  // certID — SEQUENCE { hashAlgo, issuerNameHash, issuerKeyHash, serialNumber }
  const certId = node.children[0]
  if (certId.tag !== ASN1_TAG.SEQUENCE || certId.children.length < 4) return null

  const serialNode = certId.children[3]
  const certSerial = decodeInteger(serialNode)

  // certStatus — context-specific: [0]=good, [1]=revoked, [2]=unknown
  const statusNode = node.children[1]
  let status: 'good' | 'revoked' | 'unknown' = 'unknown'
  let revokedAt: string | null = null

  if (statusNode.tagClass === 2) {
    switch (statusNode.tagNumber) {
      case 0:
        status = 'good'
        break
      case 1:
        status = 'revoked'
        // RevokedInfo ::= SEQUENCE { revocationTime, revocationReason OPTIONAL }
        if (statusNode.children.length > 0) {
          try {
            revokedAt = decodeTime(statusNode.children[0])
          } catch {
            // revocation time parse failed — still mark as revoked
          }
        }
        break
      case 2:
        status = 'unknown'
        break
    }
  }

  // thisUpdate — GeneralizedTime
  let thisUpdate: string | null = null
  if (node.children[2].tag === ASN1_TAG.GENERALIZED_TIME) {
    thisUpdate = decodeTime(node.children[2])
  }

  // nextUpdate — [0] EXPLICIT GeneralizedTime (optional)
  let nextUpdate: string | null = null
  const nextCtx = findContext(node, 0)
  if (nextCtx && nextCtx.children.length > 0) {
    try {
      nextUpdate = decodeTime(nextCtx.children[0])
    } catch {
      // optional, ignore
    }
  }

  return { certSerial, status, thisUpdate, nextUpdate, revokedAt }
}

// ── CRL Parsing ────────────────────────────────────────────────────

/**
 * Parse a DER-encoded X.509 CRL.
 */
export function parseCrl(der: Uint8Array): ParsedCrl | null {
  try {
    const root = parseAsn1(der)
    if (root.tag !== ASN1_TAG.SEQUENCE || root.children.length < 1) return null

    const tbsCertList = root.children[0]
    if (tbsCertList.tag !== ASN1_TAG.SEQUENCE) return null

    let idx = 0

    // version — INTEGER (optional, v2 = 1)
    if (
      tbsCertList.children[idx]?.tag === ASN1_TAG.INTEGER &&
      tbsCertList.children[idx]?.contentLength === 1
    ) {
      idx++
    }

    // signature — AlgorithmIdentifier (SEQUENCE)
    if (tbsCertList.children[idx]?.tag === ASN1_TAG.SEQUENCE) {
      idx++
    }

    // issuer — Name (SEQUENCE)
    let issuerDN: string | null = null
    if (tbsCertList.children[idx]?.tag === ASN1_TAG.SEQUENCE) {
      issuerDN = extractDN(tbsCertList.children[idx])
      idx++
    }

    // thisUpdate — Time
    let thisUpdate: string | null = null
    if (
      idx < tbsCertList.children.length &&
      (tbsCertList.children[idx].tag === ASN1_TAG.UTC_TIME ||
        tbsCertList.children[idx].tag === ASN1_TAG.GENERALIZED_TIME)
    ) {
      thisUpdate = decodeTime(tbsCertList.children[idx])
      idx++
    }

    // nextUpdate — Time (optional)
    let nextUpdate: string | null = null
    if (
      idx < tbsCertList.children.length &&
      (tbsCertList.children[idx].tag === ASN1_TAG.UTC_TIME ||
        tbsCertList.children[idx].tag === ASN1_TAG.GENERALIZED_TIME)
    ) {
      nextUpdate = decodeTime(tbsCertList.children[idx])
      idx++
    }

    // revokedCertificates — SEQUENCE OF SEQUENCE (optional)
    const revokedCertificates: CrlRevokedEntry[] = []
    if (
      idx < tbsCertList.children.length &&
      tbsCertList.children[idx].tag === ASN1_TAG.SEQUENCE
    ) {
      const revokedSeq = tbsCertList.children[idx]
      for (const entry of revokedSeq.children) {
        if (entry.tag === ASN1_TAG.SEQUENCE && entry.children.length >= 2) {
          const serial = decodeInteger(entry.children[0])
          let revocationDate: string | null = null
          try {
            revocationDate = decodeTime(entry.children[1])
          } catch {
            // ignore parse errors on individual entries
          }
          revokedCertificates.push({ serial, revocationDate })
        }
      }
    }

    return { issuerDN, thisUpdate, nextUpdate, revokedCertificates }
  } catch (err) {
    log.warn(`[revocation] Failed to parse CRL: ${err}`)
    return null
  }
}

/**
 * Extract a simple DN string from a Name node (for logging/matching).
 */
function extractDN(nameNode: Asn1Node): string {
  const parts: string[] = []
  for (const rdn of nameNode.children) {
    if (rdn.tag !== ASN1_TAG.SET || rdn.children.length === 0) continue
    const atv = rdn.children[0]
    if (atv.tag !== ASN1_TAG.SEQUENCE || atv.children.length < 2) continue
    try {
      const value = atv.children[1]
      parts.push(new TextDecoder('utf-8').decode(value.content))
    } catch {
      // skip unparseable RDN
    }
  }
  return parts.join(', ')
}

// ── High-Level Checker ─────────────────────────────────────────────

/**
 * Check revocation status for a certificate using embedded DSS data.
 *
 * @param certSerialHex — hex-encoded serial number of the cert to check
 * @param ocspResponses — raw DER OCSP responses from /DSS
 * @param crls — raw DER CRLs from /DSS
 */
export function checkRevocation(
  certSerialHex: string,
  ocspResponses: Uint8Array[],
  crls: Uint8Array[],
): RevocationResult {
  if (ocspResponses.length === 0 && crls.length === 0) {
    return {
      status: 'no-data',
      message: 'No embedded revocation data (non-LTV document)',
      source: 'none',
      producedAt: null,
      revokedAt: null,
    }
  }

  // Normalize the serial for comparison (strip leading zeros)
  const normalSerial = normalizeSerial(certSerialHex)

  // Try OCSP first (preferred — more specific, fresher)
  for (const ocspDer of ocspResponses) {
    const parsed = parseOcspResponse(ocspDer)
    if (!parsed || parsed.responseStatus !== 0) continue

    for (const resp of parsed.responses) {
      if (normalizeSerial(resp.certSerial) === normalSerial) {
        if (resp.status === 'revoked') {
          return {
            status: 'revoked',
            message: `Certificate revoked${resp.revokedAt ? ` on ${resp.revokedAt}` : ''}`,
            source: 'ocsp',
            producedAt: parsed.producedAt,
            revokedAt: resp.revokedAt,
          }
        }
        if (resp.status === 'good') {
          return {
            status: 'good',
            message: `Certificate valid at signing time (OCSP)`,
            source: 'ocsp',
            producedAt: parsed.producedAt,
            revokedAt: null,
          }
        }
        // unknown — continue to try CRL
      }
    }
  }

  // Fall back to CRL
  for (const crlDer of crls) {
    const parsed = parseCrl(crlDer)
    if (!parsed) continue

    const revoked = parsed.revokedCertificates.find(
      (entry) => normalizeSerial(entry.serial) === normalSerial,
    )

    if (revoked) {
      return {
        status: 'revoked',
        message: `Certificate revoked${revoked.revocationDate ? ` on ${revoked.revocationDate}` : ''} (CRL)`,
        source: 'crl',
        producedAt: parsed.thisUpdate,
        revokedAt: revoked.revocationDate,
      }
    }

    // Cert serial not in CRL = good (at time of CRL)
    return {
      status: 'good',
      message: `Certificate valid at signing time (CRL)`,
      source: 'crl',
      producedAt: parsed.thisUpdate,
      revokedAt: null,
    }
  }

  // Had data but couldn't match the cert serial
  return {
    status: 'no-data',
    message: 'Embedded revocation data did not cover this certificate',
    source: 'none',
    producedAt: null,
    revokedAt: null,
  }
}

/**
 * Normalize a hex serial number for comparison.
 * Strips leading zeros and lowercases.
 */
function normalizeSerial(hex: string): string {
  return hex.toLowerCase().replace(/^0+/, '') || '0'
}

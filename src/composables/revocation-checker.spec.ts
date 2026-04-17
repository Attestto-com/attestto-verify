/**
 * Tests for DSS parser + revocation checker (ATT-313)
 *
 * Tests OCSP response parsing, CRL parsing, and the high-level
 * checkRevocation() orchestrator using synthetic DER fixtures.
 */

import { describe, it, expect } from 'vitest'
import {
  parseOcspResponse,
  parseCrl,
  checkRevocation,
  type OcspSingleResponse,
} from './revocation-checker.js'
import { extractDss } from './dss-parser.js'

// ── ASN.1 DER helpers for building test fixtures ───────────────────

function seq(...children: Uint8Array[]): Uint8Array {
  const content = concat(...children)
  return tlv(0x30, content)
}

function set(...children: Uint8Array[]): Uint8Array {
  const content = concat(...children)
  return tlv(0x31, content)
}

function integer(hex: string): Uint8Array {
  const bytes = hexToBytes(hex)
  return tlv(0x02, bytes)
}

function octetString(content: Uint8Array): Uint8Array {
  return tlv(0x04, content)
}

function enumerated(val: number): Uint8Array {
  return tlv(0x0a, new Uint8Array([val]))
}

function generalizedTime(iso: string): Uint8Array {
  // Convert ISO to GeneralizedTime: YYYYMMDDHHmmSSZ
  const clean = iso.replace(/[-:T]/g, '').replace('Z', '') + 'Z'
  const bytes = new TextEncoder().encode(clean)
  return tlv(0x18, bytes)
}

function utcTime(iso: string): Uint8Array {
  // Convert ISO to UTCTime: YYMMDDHHmmSSZ
  const clean = iso.replace(/[-:T]/g, '').replace('Z', '')
  const yy = clean.substring(2, 4)
  const rest = clean.substring(4) + 'Z'
  const bytes = new TextEncoder().encode(yy + rest)
  return tlv(0x17, bytes)
}

function contextExplicit(tagNum: number, content: Uint8Array): Uint8Array {
  return tlv(0xa0 + tagNum, content)
}

function contextImplicit(tagNum: number, content: Uint8Array): Uint8Array {
  return tlv(0x80 + tagNum, content)
}

function oid(dotted: string): Uint8Array {
  const parts = dotted.split('.').map(Number)
  const bytes: number[] = [parts[0] * 40 + parts[1]]
  for (let i = 2; i < parts.length; i++) {
    let val = parts[i]
    if (val < 128) {
      bytes.push(val)
    } else {
      const enc: number[] = []
      enc.push(val & 0x7f)
      val >>= 7
      while (val > 0) {
        enc.push((val & 0x7f) | 0x80)
        val >>= 7
      }
      bytes.push(...enc.reverse())
    }
  }
  return tlv(0x06, new Uint8Array(bytes))
}

function printableString(str: string): Uint8Array {
  return tlv(0x13, new TextEncoder().encode(str))
}

function bitString(content: Uint8Array): Uint8Array {
  // Prepend unused-bits byte (0)
  const withPad = new Uint8Array(content.length + 1)
  withPad[0] = 0
  withPad.set(content, 1)
  return tlv(0x03, withPad)
}

function tlv(tag: number, content: Uint8Array): Uint8Array {
  const len = content.length
  if (len < 128) {
    const result = new Uint8Array(1 + 1 + len)
    result[0] = tag
    result[1] = len
    result.set(content, 2)
    return result
  } else if (len < 256) {
    const result = new Uint8Array(1 + 2 + len)
    result[0] = tag
    result[1] = 0x81
    result[2] = len
    result.set(content, 3)
    return result
  } else {
    const result = new Uint8Array(1 + 3 + len)
    result[0] = tag
    result[1] = 0x82
    result[2] = (len >> 8) & 0xff
    result[3] = len & 0xff
    result.set(content, 4)
    return result
  }
}

function concat(...arrays: Uint8Array[]): Uint8Array {
  const totalLen = arrays.reduce((s, a) => s + a.length, 0)
  const result = new Uint8Array(totalLen)
  let offset = 0
  for (const arr of arrays) {
    result.set(arr, offset)
    offset += arr.length
  }
  return result
}

function hexToBytes(hex: string): Uint8Array {
  const clean = hex.replace(/\s/g, '')
  const result = new Uint8Array(clean.length / 2)
  for (let i = 0; i < result.length; i++) {
    result[i] = parseInt(clean.substring(i * 2, i * 2 + 2), 16)
  }
  return result
}

// ── OCSP Response fixture builder ──────────────────────────────────

function buildOcspResponse(
  certSerial: string,
  status: 'good' | 'revoked' | 'unknown',
  producedAt = '2026-01-15T12:00:00Z',
  revokedAt?: string,
): Uint8Array {
  // Build certID (hashAlgo + issuerNameHash + issuerKeyHash + serialNumber)
  const certId = seq(
    seq(oid('1.3.14.3.2.26'), tlv(0x05, new Uint8Array(0))), // SHA-1 algo
    octetString(new Uint8Array(20)), // issuerNameHash (dummy)
    octetString(new Uint8Array(20)), // issuerKeyHash (dummy)
    integer(certSerial),
  )

  // Build certStatus
  let certStatus: Uint8Array
  if (status === 'good') {
    certStatus = contextImplicit(0, new Uint8Array(0)) // [0] IMPLICIT NULL
  } else if (status === 'revoked') {
    const revokedTime = generalizedTime(revokedAt || producedAt)
    certStatus = contextExplicit(1, revokedTime) // [1] EXPLICIT RevokedInfo
  } else {
    certStatus = contextImplicit(2, new Uint8Array(0)) // [2] IMPLICIT NULL
  }

  // SingleResponse
  const singleResponse = seq(
    certId,
    certStatus,
    generalizedTime(producedAt), // thisUpdate
  )

  // tbsResponseData (skip version, skip responderID for simplicity)
  const tbsResponseData = seq(
    contextExplicit(1, seq(printableString('Test Responder'))), // responderID [1] byName
    generalizedTime(producedAt), // producedAt
    seq(singleResponse), // responses
  )

  // BasicOCSPResponse
  const basicOcspResponse = seq(
    tbsResponseData,
    seq(oid('1.2.840.113549.1.1.11'), tlv(0x05, new Uint8Array(0))), // sha256WithRSA
    bitString(new Uint8Array(64)), // dummy signature
  )

  // OCSPResponse
  return seq(
    enumerated(0), // successful
    contextExplicit(0, seq(
      oid('1.3.6.1.5.5.7.48.1.1'), // id-pkix-ocsp-basic
      octetString(basicOcspResponse),
    )),
  )
}

// ── CRL fixture builder ────────────────────────────────────────────

function buildCrl(
  revokedSerials: Array<{ serial: string; date: string }>,
  thisUpdate = '2026-01-15T12:00:00Z',
): Uint8Array {
  const revokedEntries = revokedSerials.map((entry) =>
    seq(integer(entry.serial), utcTime(entry.date)),
  )

  const tbsCertList = seq(
    integer('01'), // version v2
    seq(oid('1.2.840.113549.1.1.11'), tlv(0x05, new Uint8Array(0))), // sigAlgo
    seq(set(seq(oid('2.5.4.3'), printableString('Test CA')))), // issuer
    utcTime(thisUpdate), // thisUpdate
    utcTime('2026-07-15T12:00:00Z'), // nextUpdate
    ...(revokedEntries.length > 0 ? [seq(...revokedEntries)] : []),
  )

  return seq(
    tbsCertList,
    seq(oid('1.2.840.113549.1.1.11'), tlv(0x05, new Uint8Array(0))),
    bitString(new Uint8Array(64)),
  )
}

// ── Tests ──────────────────────────────────────────────────────────

describe('OCSP response parsing (ATT-313)', () => {
  it('parses a successful OCSP response with good status', () => {
    const ocsp = buildOcspResponse('0a1b2c', 'good')
    const parsed = parseOcspResponse(ocsp)

    expect(parsed).not.toBeNull()
    expect(parsed!.responseStatus).toBe(0)
    expect(parsed!.responses).toHaveLength(1)
    expect(parsed!.responses[0].certSerial).toBe('0a1b2c')
    expect(parsed!.responses[0].status).toBe('good')
    expect(parsed!.responses[0].revokedAt).toBeNull()
  })

  it('parses a revoked OCSP response with revocation time', () => {
    const ocsp = buildOcspResponse('deadbeef', 'revoked', '2026-01-15T12:00:00Z', '2026-01-10T08:30:00Z')
    const parsed = parseOcspResponse(ocsp)

    expect(parsed).not.toBeNull()
    expect(parsed!.responses[0].status).toBe('revoked')
    expect(parsed!.responses[0].revokedAt).toMatch(/2026-01-10/)
  })

  it('parses an unknown OCSP status', () => {
    const ocsp = buildOcspResponse('aabbcc', 'unknown')
    const parsed = parseOcspResponse(ocsp)

    expect(parsed).not.toBeNull()
    expect(parsed!.responses[0].status).toBe('unknown')
  })

  it('returns null for garbage input', () => {
    const garbage = new Uint8Array([0x00, 0x01, 0x02, 0x03])
    expect(parseOcspResponse(garbage)).toBeNull()
  })

  it('handles a non-successful response status', () => {
    // Build an OCSP response with status = 1 (malformedRequest)
    const ocsp = seq(enumerated(1))
    const parsed = parseOcspResponse(ocsp)

    expect(parsed).not.toBeNull()
    expect(parsed!.responseStatus).toBe(1)
    expect(parsed!.responses).toHaveLength(0)
  })
})

describe('CRL parsing (ATT-313)', () => {
  it('parses a CRL with revoked certificates', () => {
    const crl = buildCrl([
      { serial: '0a0b0c', date: '2026-01-10T00:00:00Z' },
      { serial: 'deadbeef', date: '2026-01-12T00:00:00Z' },
    ])
    const parsed = parseCrl(crl)

    expect(parsed).not.toBeNull()
    expect(parsed!.revokedCertificates).toHaveLength(2)
    expect(parsed!.revokedCertificates[0].serial).toBe('0a0b0c')
    expect(parsed!.revokedCertificates[1].serial).toBe('deadbeef')
    expect(parsed!.thisUpdate).toMatch(/2026-01-15/)
  })

  it('parses a CRL with no revoked certificates', () => {
    const crl = buildCrl([])
    const parsed = parseCrl(crl)

    expect(parsed).not.toBeNull()
    expect(parsed!.revokedCertificates).toHaveLength(0)
  })

  it('returns null for garbage input', () => {
    const garbage = new Uint8Array([0xff, 0x00])
    expect(parseCrl(garbage)).toBeNull()
  })
})

describe('checkRevocation — high-level orchestrator (ATT-313)', () => {
  it('returns no-data when no OCSP or CRL provided', () => {
    const result = checkRevocation('0a1b2c', [], [])
    expect(result.status).toBe('no-data')
    expect(result.source).toBe('none')
  })

  it('returns good from OCSP when cert is not revoked', () => {
    const ocsp = buildOcspResponse('0a1b2c', 'good')
    const result = checkRevocation('0a1b2c', [ocsp], [])
    expect(result.status).toBe('good')
    expect(result.source).toBe('ocsp')
    expect(result.message).toContain('valid at signing time')
  })

  it('returns revoked from OCSP when cert is revoked', () => {
    const ocsp = buildOcspResponse('0a1b2c', 'revoked', '2026-01-15T12:00:00Z', '2026-01-10T08:30:00Z')
    const result = checkRevocation('0a1b2c', [ocsp], [])
    expect(result.status).toBe('revoked')
    expect(result.source).toBe('ocsp')
    expect(result.revokedAt).toMatch(/2026-01-10/)
  })

  it('falls back to CRL when OCSP does not cover the cert', () => {
    const ocsp = buildOcspResponse('ffffff', 'good') // different serial
    const crl = buildCrl([])
    const result = checkRevocation('0a1b2c', [ocsp], [crl])
    expect(result.status).toBe('good')
    expect(result.source).toBe('crl')
  })

  it('detects revocation via CRL', () => {
    const crl = buildCrl([
      { serial: '0a1b2c', date: '2026-01-10T00:00:00Z' },
    ])
    const result = checkRevocation('0a1b2c', [], [crl])
    expect(result.status).toBe('revoked')
    expect(result.source).toBe('crl')
  })

  it('normalizes serial numbers (leading zeros)', () => {
    const ocsp = buildOcspResponse('000a1b2c', 'good')
    const result = checkRevocation('0a1b2c', [ocsp], [])
    expect(result.status).toBe('good')
  })

  it('normalizes serial numbers (case insensitive)', () => {
    const ocsp = buildOcspResponse('0A1B2C', 'good')
    const result = checkRevocation('0a1b2c', [ocsp], [])
    expect(result.status).toBe('good')
  })
})

describe('DSS parser (ATT-313)', () => {
  it('returns found=false when no /DSS in PDF', () => {
    const fakePdf = new TextEncoder().encode('%PDF-1.7\nno dss here\n%%EOF')
    const result = extractDss(fakePdf)
    expect(result.found).toBe(false)
    expect(result.ocspResponses).toHaveLength(0)
    expect(result.crls).toHaveLength(0)
  })

  it('returns found=true with empty arrays when /DSS has no refs', () => {
    const pdf = new TextEncoder().encode(
      '%PDF-1.7\n/DSS << /OCSPs [ ] /CRLs [ ] >>\n%%EOF',
    )
    const result = extractDss(pdf)
    expect(result.found).toBe(true)
    expect(result.ocspResponses).toHaveLength(0)
    expect(result.crls).toHaveLength(0)
  })

  it('extracts stream objects referenced by /DSS /OCSPs', () => {
    // Build a minimal PDF with a DSS pointing to an object with a stream
    const streamContent = new Uint8Array([0x30, 0x03, 0x0a, 0x01, 0x00]) // SEQUENCE { ENUM 0 }
    const streamHex = Array.from(streamContent).map(b => String.fromCharCode(b)).join('')

    const pdf = new TextEncoder().encode(
      `%PDF-1.7\n` +
      `1 0 obj\n<< /Length ${streamContent.length} >>\nstream\n`,
    )

    // Build binary: pdf text + raw stream bytes + endstream + rest
    const endPart = new TextEncoder().encode(
      `\nendstream\nendobj\n` +
      `2 0 obj\n<< /Type /Catalog /DSS << /OCSPs [ 1 0 R ] /CRLs [ ] >> >>\nendobj\n%%EOF`,
    )

    const fullPdf = concat(pdf, streamContent, endPart)
    const result = extractDss(fullPdf)

    expect(result.found).toBe(true)
    expect(result.ocspResponses).toHaveLength(1)
    expect(result.ocspResponses[0].length).toBe(streamContent.length)
  })
})

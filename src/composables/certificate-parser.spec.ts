/** @vitest-environment node */
import { describe, it, expect } from 'vitest'
import {
  hexToBytes,
  cleanSignerName,
  parseCertificateChain,
  extractPkcs7Hex,
  decodeKeyUsageBits,
} from './certificate-parser.js'
import { PKI_REGISTRY, findPkiByCountry } from './pki-registry.js'

describe('certificate-parser', () => {
  describe('decodeKeyUsageBits', () => {
    // DER BIT STRING content = [unusedBits, ...valueBytes]. Bit 0 = MSB of the
    // first value byte = digitalSignature.
    it('decodes a nonRepudiation-only signing cert (the CR Firma Digital case)', () => {
      // 0x40 = 0100_0000 → bit 1 set (nonRepudiation); 6 unused trailing bits.
      expect(decodeKeyUsageBits(new Uint8Array([0x06, 0x40]))).toEqual(['Non-Repudiation'])
    })

    it('decodes digitalSignature + nonRepudiation', () => {
      // 0xC0 = 1100_0000 → bits 0,1 set; 6 unused trailing bits.
      expect(decodeKeyUsageBits(new Uint8Array([0x06, 0xc0]))).toEqual([
        'Digital Signature',
        'Non-Repudiation',
      ])
    })

    it('decodes digitalSignature only', () => {
      // 0x80 = 1000_0000 → bit 0; 7 unused trailing bits.
      expect(decodeKeyUsageBits(new Uint8Array([0x07, 0x80]))).toEqual(['Digital Signature'])
    })

    it('decodes a CA cert (keyCertSign + cRLSign)', () => {
      // 0x06 = 0000_0110 → bits 5,6 set; 1 unused trailing bit.
      expect(decodeKeyUsageBits(new Uint8Array([0x01, 0x06]))).toEqual([
        'Certificate Signing',
        'CRL Signing',
      ])
    })

    it('returns empty for a short/empty BIT STRING', () => {
      expect(decodeKeyUsageBits(new Uint8Array([]))).toEqual([])
      expect(decodeKeyUsageBits(new Uint8Array([0x00]))).toEqual([])
    })
  })

  describe('cleanSignerName', () => {
    it('strips backslash escapes from PDF encoding', () => {
      expect(cleanSignerName('GUILLERMO CHAVARRIA CRUZ \\(FIRMA\\)')).toBe(
        'GUILLERMO CHAVARRIA CRUZ (FIRMA)',
      )
    })

    it('handles names without escapes', () => {
      expect(cleanSignerName('John Doe')).toBe('John Doe')
    })

    it('handles multiple escaped characters', () => {
      expect(cleanSignerName('Test \\(A\\) \\(B\\)')).toBe('Test (A) (B)')
    })
  })

  describe('hexToBytes', () => {
    it('converts hex string to Uint8Array', () => {
      const bytes = hexToBytes('deadbeef')
      expect(bytes).toEqual(new Uint8Array([0xde, 0xad, 0xbe, 0xef]))
    })

    it('handles uppercase hex', () => {
      const bytes = hexToBytes('DEADBEEF')
      expect(bytes).toEqual(new Uint8Array([0xde, 0xad, 0xbe, 0xef]))
    })

    it('handles empty string', () => {
      const bytes = hexToBytes('')
      expect(bytes).toEqual(new Uint8Array([]))
    })
  })

  describe('extractPkcs7Hex', () => {
    it('extracts hex blob from /Contents field', () => {
      const pdfText = '<< /Type /Sig /Contents <AABBCCDD> /SubFilter /adbe.pkcs7.detached >>'
      const hex = extractPkcs7Hex(pdfText, 0, pdfText.length)
      expect(hex).toBe('AABBCCDD')
    })

    it('strips whitespace from hex blob', () => {
      const pdfText = '<< /Contents <AA BB CC DD EE FF> >>'
      const hex = extractPkcs7Hex(pdfText, 0, pdfText.length)
      expect(hex).toBe('AABBCCDDEEFF')
    })

    it('returns null when no /Contents found', () => {
      const pdfText = '<< /Type /Sig /SubFilter /adbe.pkcs7.detached >>'
      const hex = extractPkcs7Hex(pdfText, 0, pdfText.length)
      expect(hex).toBeNull()
    })
  })

  describe('parseCertificateChain', () => {
    it('returns empty result for invalid/short hex', async () => {
      const result = await parseCertificateChain('00')
      expect(result.certificates).toHaveLength(0)
      expect(result.signer).toBeNull()
      expect(result.pki).toBeNull()
      expect(result.keyUsage).toEqual([])
      expect(result.extKeyUsage).toEqual([])
      expect(result.cryptographicallyVerified).toBe(false)
      expect(result.pkiDid).toBeNull()
      expect(result.trustSource).toBeNull()
    })

    it('returns empty result for empty string', async () => {
      const result = await parseCertificateChain('')
      expect(result.certificates).toHaveLength(0)
      expect(result.keyUsage).toEqual([])
      expect(result.extKeyUsage).toEqual([])
      expect(result.cryptographicallyVerified).toBe(false)
      expect(result.pkiDid).toBeNull()
      expect(result.trustSource).toBeNull()
    })

    it('returns empty result for non-SignedData structure', async () => {
      // A simple SEQUENCE { INTEGER(1) } — not a ContentInfo
      const result = await parseCertificateChain('3003020101')
      expect(result.certificates).toHaveLength(0)
      expect(result.cryptographicallyVerified).toBe(false)
      expect(result.pkiDid).toBeNull()
      expect(result.trustSource).toBeNull()
    })

    it('handles malformed DER gracefully', async () => {
      // Random bytes that might cause parser issues
      const result = await parseCertificateChain('FFFFFFFFFFFF')
      expect(result.certificates).toHaveLength(0)
      expect(result.cryptographicallyVerified).toBe(false)
      expect(result.pkiDid).toBeNull()
      expect(result.trustSource).toBeNull()
    })
  })

  describe('CR Firma Digital detection — name-based heuristic', () => {
    it('cleanSignerName removes FIRMA suffix escapes', () => {
      const cleaned = cleanSignerName('EDUARDO CHONGKAN \\(FIRMA\\)')
      expect(cleaned).toBe('EDUARDO CHONGKAN (FIRMA)')
      expect(cleaned).toContain('(FIRMA)')
    })
  })
})

describe('pki-registry', () => {
  it('contains 9 LATAM countries', () => {
    expect(PKI_REGISTRY.length).toBe(9)
  })

  it('each entry has required fields', () => {
    for (const entry of PKI_REGISTRY) {
      expect(entry.countryCode).toMatch(/^[A-Z]{2}$/)
      expect(entry.name).toBeTruthy()
      expect(entry.fullName).toBeTruthy()
      expect(entry.oidArc).toMatch(/^2\.16\.\d+$/)
      expect(entry.rootCaNames.length).toBeGreaterThan(0)
      expect(entry.governingLaw).toBeTruthy()
      expect(entry.rootAuthority).toBeTruthy()
    }
  })

  it('all country codes are unique', () => {
    const codes = PKI_REGISTRY.map((e) => e.countryCode)
    expect(new Set(codes).size).toBe(codes.length)
  })

  it('all OID arcs are unique', () => {
    const arcs = PKI_REGISTRY.map((e) => e.oidArc)
    expect(new Set(arcs).size).toBe(arcs.length)
  })

  it('findPkiByCountry returns correct entry', () => {
    const cr = findPkiByCountry('CR')
    expect(cr?.name).toBe('CR Firma Digital')
    expect(cr?.oidArc).toBe('2.16.188')

    const mx = findPkiByCountry('MX')
    expect(mx?.name).toBe('MX e.firma / FIEL')

    const br = findPkiByCountry('BR')
    expect(br?.name).toBe('BR ICP-Brasil')
  })

  it('findPkiByCountry returns undefined for unknown country', () => {
    expect(findPkiByCountry('XX')).toBeUndefined()
  })

  const expectedCountries = ['CR', 'MX', 'CO', 'BR', 'CL', 'PE', 'AR', 'EC', 'UY']
  it.each(expectedCountries)('has entry for %s', (code) => {
    const entry = findPkiByCountry(code)
    expect(entry).toBeDefined()
    expect(entry!.policyOids.length).toBeGreaterThan(0)
  })
})

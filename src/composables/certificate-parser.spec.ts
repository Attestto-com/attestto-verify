/** @vitest-environment node */
import { describe, it, expect } from 'vitest'
import {
  hexToBytes,
  cleanSignerName,
  parseCertificateChain,
  extractPkcs7Hex,
} from './certificate-parser.js'
import { PKI_REGISTRY, findPkiByCountry } from './pki-registry.js'

describe('certificate-parser', () => {
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

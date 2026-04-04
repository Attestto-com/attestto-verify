/** @vitest-environment node */
import { describe, it, expect } from 'vitest'
import {
  hexToBytes,
  cleanSignerName,
  parseCertificateChain,
  extractPkcs7Hex,
} from './certificate-parser.js'

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
    it('returns empty result for invalid/short hex', () => {
      const result = parseCertificateChain('00')
      expect(result.certificates).toHaveLength(0)
      expect(result.signer).toBeNull()
      expect(result.pki).toBeNull()
      expect(result.keyUsage).toEqual([])
      expect(result.extKeyUsage).toEqual([])
    })

    it('returns empty result for empty string', () => {
      const result = parseCertificateChain('')
      expect(result.certificates).toHaveLength(0)
      expect(result.keyUsage).toEqual([])
      expect(result.extKeyUsage).toEqual([])
    })

    it('returns empty result for non-SignedData structure', () => {
      // A simple SEQUENCE { INTEGER(1) } — not a ContentInfo
      const result = parseCertificateChain('3003020101')
      expect(result.certificates).toHaveLength(0)
    })

    it('handles malformed DER gracefully', () => {
      // Random bytes that might cause parser issues
      const result = parseCertificateChain('FFFFFFFFFFFF')
      expect(result.certificates).toHaveLength(0)
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

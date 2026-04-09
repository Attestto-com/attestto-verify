/**
 * Tests for chain-validator — focused on Phase A (document integrity).
 *
 * The chain-validation engine itself is exercised against real BCCR PDFs in
 * regression fixtures (tracked separately). These tests cover the new
 * `verifyDocumentIntegrity` function and the `reconstructSignedBytes` helper
 * that close the ATT-309 reputational gap: until 2026-04-07
 * verify.attestto.com showed a green "verified" badge for tampered PDFs as
 * long as the certificate chain was intact. This file pins the new
 * behaviour so the regression cannot recur.
 */

import { describe, it, expect, beforeEach, vi } from 'vitest'

// pkijs / asn1js are heavy native modules. We mock them so we can test the
// wrapper logic deterministically without crafting real CMS structures.
vi.mock('pkijs', () => {
  return {
    setEngine: vi.fn(),
    CryptoEngine: vi.fn(),
    Certificate: vi.fn().mockImplementation(() => ({
      subject: { typesAndValues: [] },
    })),
    CertificateChainValidationEngine: vi.fn().mockImplementation(() => ({
      verify: vi.fn(),
    })),
    ContentInfo: vi.fn().mockImplementation(({ schema }) => ({
      content: schema,
    })),
    SignedData: vi.fn().mockImplementation(() => ({
      verify: vi.fn(),
    })),
  }
})

vi.mock('asn1js', () => {
  return {
    fromBER: vi.fn(),
  }
})

// Stub the bundled PEM imports — vite's `?raw` loader is not available in
// vitest's default Node env, so we shim them.
vi.mock('../trust-store/bccr/CA_RAIZ_NACIONAL_-_COSTA_RICA_v2.pem?raw', () => ({
  default: '-----BEGIN CERTIFICATE-----\nFAKE\n-----END CERTIFICATE-----',
}))
vi.mock('../trust-store/bccr/CA_POLITICA_PERSONA_JURIDICA_-_COSTA_RICA_v2.pem?raw', () => ({
  default: '-----BEGIN CERTIFICATE-----\nFAKE\n-----END CERTIFICATE-----',
}))
vi.mock('../trust-store/bccr/CA_SINPE_-_PERSONA_JURIDICA_v2.pem?raw', () => ({
  default: '-----BEGIN CERTIFICATE-----\nFAKE\n-----END CERTIFICATE-----',
}))

// Silence the verify logger noise during tests.
vi.mock('../logger.js', () => ({
  logger: {
    verify: {
      info: vi.fn(),
      warn: vi.fn(),
      event: vi.fn(),
    },
  },
}))

import * as asn1js from 'asn1js'
import * as pkijs from 'pkijs'
import {
  verifyDocumentIntegrity,
  reconstructSignedBytes,
  _resetChainValidatorCache,
} from './chain-validator'

beforeEach(() => {
  _resetChainValidatorCache()
  vi.clearAllMocks()
})

// ── reconstructSignedBytes ────────────────────────────────────────

describe('reconstructSignedBytes', () => {
  it('concatenates the two byte slices defined by the ByteRange', () => {
    // Bytes 0..3 = "ABCD", bytes 6..9 = "WXYZ" (skipping 4..5 = "??")
    const pdf = new Uint8Array([0x41, 0x42, 0x43, 0x44, 0x3f, 0x3f, 0x57, 0x58, 0x59, 0x5a])
    const out = reconstructSignedBytes(pdf, [0, 4, 6, 4])
    expect(out).toHaveLength(8)
    expect(new TextDecoder().decode(out)).toBe('ABCDWXYZ')
  })

  it('handles a zero-length second slice', () => {
    const pdf = new Uint8Array([1, 2, 3, 4])
    const out = reconstructSignedBytes(pdf, [0, 4, 4, 0])
    expect(out).toEqual(new Uint8Array([1, 2, 3, 4]))
  })

  it('handles a zero-length first slice', () => {
    const pdf = new Uint8Array([1, 2, 3, 4])
    const out = reconstructSignedBytes(pdf, [0, 0, 0, 4])
    expect(out).toEqual(new Uint8Array([1, 2, 3, 4]))
  })

  it('preserves byte ordering across the boundary', () => {
    const pdf = new Uint8Array([10, 20, 30, 40, 50, 60, 70, 80])
    const out = reconstructSignedBytes(pdf, [0, 2, 5, 3])
    // [10, 20] + [60, 70, 80]
    expect(Array.from(out)).toEqual([10, 20, 60, 70, 80])
  })
})

// ── verifyDocumentIntegrity ───────────────────────────────────────

describe('verifyDocumentIntegrity', () => {
  const fakeHex = 'deadbeef'
  const fakeData = new ArrayBuffer(8)

  it('returns integrityValid=null when ASN.1 parse fails (UNKNOWN, not tampered) — ATT-357', async () => {
    vi.mocked(asn1js.fromBER).mockReturnValueOnce({
      offset: -1,
      result: null,
    } as unknown as ReturnType<typeof asn1js.fromBER>)

    const r = await verifyDocumentIntegrity(fakeHex, fakeData)
    expect(r.integrityValid).toBeNull()
    expect(r.error).toMatch(/ASN\.1 parse failed/)
  })

  it('returns integrityValid=true when pkijs.SignedData.verify reports success', async () => {
    vi.mocked(asn1js.fromBER).mockReturnValueOnce({
      offset: 0,
      result: { schema: 'fake' },
    } as unknown as ReturnType<typeof asn1js.fromBER>)

    const verifyMock = vi.fn().mockResolvedValue({ signatureVerified: true })
    vi.mocked(pkijs.SignedData).mockImplementationOnce(
      () => ({ verify: verifyMock }) as unknown as InstanceType<typeof pkijs.SignedData>,
    )

    const r = await verifyDocumentIntegrity(fakeHex, fakeData)
    expect(r.integrityValid).toBe(true)
    expect(r.error).toBeNull()
    // Verify it called pkijs with the data we passed in and signer:0
    expect(verifyMock).toHaveBeenCalledWith(
      expect.objectContaining({
        signer: 0,
        data: fakeData,
        checkChain: false,
      }),
    )
  })

  it('returns integrityValid=false when pkijs reports signatureVerified=false (TAMPERED case)', async () => {
    vi.mocked(asn1js.fromBER).mockReturnValueOnce({
      offset: 0,
      result: { schema: 'fake' },
    } as unknown as ReturnType<typeof asn1js.fromBER>)

    const verifyMock = vi.fn().mockResolvedValue({ signatureVerified: false })
    vi.mocked(pkijs.SignedData).mockImplementationOnce(
      () => ({ verify: verifyMock }) as unknown as InstanceType<typeof pkijs.SignedData>,
    )

    const r = await verifyDocumentIntegrity(fakeHex, fakeData)
    expect(r.integrityValid).toBe(false)
    expect(r.error).toMatch(/tampered/i)
  })

  it('accepts a bare boolean true as success', async () => {
    vi.mocked(asn1js.fromBER).mockReturnValueOnce({
      offset: 0,
      result: { schema: 'fake' },
    } as unknown as ReturnType<typeof asn1js.fromBER>)

    const verifyMock = vi.fn().mockResolvedValue(true)
    vi.mocked(pkijs.SignedData).mockImplementationOnce(
      () => ({ verify: verifyMock }) as unknown as InstanceType<typeof pkijs.SignedData>,
    )

    const r = await verifyDocumentIntegrity(fakeHex, fakeData)
    expect(r.integrityValid).toBe(true)
  })

  it('catches thrown errors and surfaces them as integrityValid=null (UNKNOWN, not tampered) — ATT-357', async () => {
    vi.mocked(asn1js.fromBER).mockImplementationOnce(() => {
      throw new Error('boom')
    })

    const r = await verifyDocumentIntegrity(fakeHex, fakeData)
    expect(r.integrityValid).toBeNull()
    expect(r.error).toBe('boom')
  })

  it('catches non-Error throws and stringifies them as null (UNKNOWN) — ATT-357', async () => {
    vi.mocked(asn1js.fromBER).mockImplementationOnce(() => {
      throw 'literal-string-error'
    })

    const r = await verifyDocumentIntegrity(fakeHex, fakeData)
    expect(r.integrityValid).toBeNull()
    expect(r.error).toBe('literal-string-error')
  })

  it('catches errors thrown by pkijs.SignedData.verify itself as null (UNKNOWN) — ATT-357', async () => {
    vi.mocked(asn1js.fromBER).mockReturnValueOnce({
      offset: 0,
      result: { schema: 'fake' },
    } as unknown as ReturnType<typeof asn1js.fromBER>)

    const verifyMock = vi.fn().mockRejectedValue(new Error('verify exploded'))
    vi.mocked(pkijs.SignedData).mockImplementationOnce(
      () => ({ verify: verifyMock }) as unknown as InstanceType<typeof pkijs.SignedData>,
    )

    const r = await verifyDocumentIntegrity(fakeHex, fakeData)
    expect(r.integrityValid).toBeNull()
    expect(r.error).toBe('verify exploded')
  })

  it('still reports integrityValid=false for REAL crypto mismatch (regression guard) — ATT-357', async () => {
    // pkijs ran cleanly and said the signature does not match. This is the
    // ONLY path that should produce `false` — anything thrown is `null`.
    vi.mocked(asn1js.fromBER).mockReturnValueOnce({
      offset: 0,
      result: { schema: 'fake' },
    } as unknown as ReturnType<typeof asn1js.fromBER>)

    const verifyMock = vi.fn().mockResolvedValue({ signatureVerified: false })
    vi.mocked(pkijs.SignedData).mockImplementationOnce(
      () => ({ verify: verifyMock }) as unknown as InstanceType<typeof pkijs.SignedData>,
    )

    const r = await verifyDocumentIntegrity(fakeHex, fakeData)
    expect(r.integrityValid).toBe(false)
    expect(r.error).toMatch(/tampered/i)
  })
})

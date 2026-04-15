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

// Stub the bundled PEM imports from the centralized trust package.
vi.mock('@attestto/trust/cr', () => ({
  CA_RAIZ_NACIONAL_COSTA_RICA_V2: '-----BEGIN CERTIFICATE-----\nFAKE\n-----END CERTIFICATE-----',
  CA_POLITICA_PERSONA_JURIDICA_COSTA_RICA_V2: '-----BEGIN CERTIFICATE-----\nFAKE\n-----END CERTIFICATE-----',
  CA_POLITICA_PERSONA_FISICA_COSTA_RICA_V2: '-----BEGIN CERTIFICATE-----\nFAKE\n-----END CERTIFICATE-----',
  CA_SINPE_PERSONA_JURIDICA_V2: '-----BEGIN CERTIFICATE-----\nFAKE\n-----END CERTIFICATE-----',
  CA_SINPE_PERSONA_FISICA_V2: '-----BEGIN CERTIFICATE-----\nFAKE\n-----END CERTIFICATE-----',
  CA_SINPE_PERSONA_FISICA_V2_2023: '-----BEGIN CERTIFICATE-----\nFAKE\n-----END CERTIFICATE-----',
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
// Mock the pki-resolver module for validateChainWithResolver tests.
vi.mock('./pki-resolver.js', () => ({
  resolveAndMatchChain: vi.fn(),
}))

import { resolveAndMatchChain } from './pki-resolver'
import {
  verifyDocumentIntegrity,
  reconstructSignedBytes,
  validateChain,
  validateChainWithResolver,
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

// ── validateChain ─────────────────────────────────────────────────

describe('validateChain', () => {
  it('returns trusted=false with "No trust anchors bundled" when all anchor loads fail', async () => {
    // The mock pkijs.Certificate constructor works (returns {subject:{typesAndValues:[]}}),
    // but asn1js.fromBER returns offset:-1 for every anchor PEM parse, so no anchors load.
    vi.mocked(asn1js.fromBER).mockReturnValue({
      offset: -1,
      result: null,
    } as unknown as ReturnType<typeof asn1js.fromBER>)

    const r = await validateChain('aabb', [])
    expect(r.trusted).toBe(false)
    expect(r.error).toMatch(/No trust anchors/)
    expect(r.chainLength).toBe(0)
  })

  it('returns trusted=false when signer cert ASN.1 parse fails', async () => {
    // First 6 calls: anchor loading succeeds
    for (let i = 0; i < 6; i++) {
      vi.mocked(asn1js.fromBER).mockReturnValueOnce({
        offset: 0,
        result: { mock: `anchor-${i}` },
      } as unknown as ReturnType<typeof asn1js.fromBER>)
    }
    // 7th call: signer cert parse fails
    vi.mocked(asn1js.fromBER).mockReturnValueOnce({
      offset: -1,
      result: null,
    } as unknown as ReturnType<typeof asn1js.fromBER>)

    const r = await validateChain('aabb', [])
    expect(r.trusted).toBe(false)
    expect(r.error).toMatch(/Signer certificate ASN\.1 parse failed/)
  })

  it('returns trusted=false with resultMessage when engine.verify fails', async () => {
    // All fromBER calls succeed
    vi.mocked(asn1js.fromBER).mockReturnValue({
      offset: 0,
      result: { mock: 'cert' },
    } as unknown as ReturnType<typeof asn1js.fromBER>)

    // Engine verify returns failure
    vi.mocked(pkijs.CertificateChainValidationEngine).mockImplementationOnce(
      () =>
        ({
          verify: vi.fn().mockResolvedValue({
            result: false,
            resultMessage: 'Certificate expired',
          }),
        }) as unknown as InstanceType<typeof pkijs.CertificateChainValidationEngine>,
    )

    const r = await validateChain('aabb', [])
    expect(r.trusted).toBe(false)
    expect(r.error).toBe('Certificate expired')
    expect(r.chainLength).toBe(0)
  })

  it('returns trusted=true with anchor CN when chain validates', async () => {
    vi.mocked(asn1js.fromBER).mockReturnValue({
      offset: 0,
      result: { mock: 'cert' },
    } as unknown as ReturnType<typeof asn1js.fromBER>)

    const fakeCert = {
      subject: {
        typesAndValues: [
          { type: '2.5.4.3', value: { valueBlock: { value: 'CA RAIZ NACIONAL' } } },
        ],
      },
    }

    vi.mocked(pkijs.CertificateChainValidationEngine).mockImplementationOnce(
      () =>
        ({
          verify: vi.fn().mockResolvedValue({
            result: true,
            certificatePath: [{ subject: { typesAndValues: [] } }, fakeCert],
          }),
        }) as unknown as InstanceType<typeof pkijs.CertificateChainValidationEngine>,
    )

    const r = await validateChain('aabb', [])
    expect(r.trusted).toBe(true)
    expect(r.anchorCommonName).toBe('CA RAIZ NACIONAL')
    expect(r.chainLength).toBe(2)
  })

  it('returns trusted=true with null CN when root has no CN attribute', async () => {
    vi.mocked(asn1js.fromBER).mockReturnValue({
      offset: 0,
      result: { mock: 'cert' },
    } as unknown as ReturnType<typeof asn1js.fromBER>)

    vi.mocked(pkijs.CertificateChainValidationEngine).mockImplementationOnce(
      () =>
        ({
          verify: vi.fn().mockResolvedValue({
            result: true,
            certificatePath: [{ subject: { typesAndValues: [] } }],
          }),
        }) as unknown as InstanceType<typeof pkijs.CertificateChainValidationEngine>,
    )

    const r = await validateChain('aabb', [])
    expect(r.trusted).toBe(true)
    expect(r.anchorCommonName).toBeNull()
    expect(r.chainLength).toBe(1)
  })

  it('catches thrown errors and returns trusted=false', async () => {
    vi.mocked(asn1js.fromBER).mockReturnValue({
      offset: 0,
      result: { mock: 'cert' },
    } as unknown as ReturnType<typeof asn1js.fromBER>)

    vi.mocked(pkijs.CertificateChainValidationEngine).mockImplementationOnce(() => {
      throw new Error('engine construction boom')
    })

    const r = await validateChain('aabb', [])
    expect(r.trusted).toBe(false)
    expect(r.error).toBe('engine construction boom')
  })

  it('skips malformed intermediate certs without failing', async () => {
    // Anchors load fine
    vi.mocked(asn1js.fromBER).mockReturnValue({
      offset: 0,
      result: { mock: 'cert' },
    } as unknown as ReturnType<typeof asn1js.fromBER>)

    // After anchors + signer, the intermediate parse throws
    let callCount = 0
    vi.mocked(asn1js.fromBER).mockImplementation(() => {
      callCount++
      // 8th call is intermediate — make it fail with offset:-1
      if (callCount === 8) {
        return { offset: -1, result: null } as unknown as ReturnType<typeof asn1js.fromBER>
      }
      return { offset: 0, result: { mock: `cert-${callCount}` } } as unknown as ReturnType<typeof asn1js.fromBER>
    })

    vi.mocked(pkijs.CertificateChainValidationEngine).mockImplementationOnce(
      () =>
        ({
          verify: vi.fn().mockResolvedValue({
            result: true,
            certificatePath: [{ subject: { typesAndValues: [] } }],
          }),
        }) as unknown as InstanceType<typeof pkijs.CertificateChainValidationEngine>,
    )

    const r = await validateChain('aabb', ['ccdd'])
    expect(r.trusted).toBe(true)
  })
})

// ── validateChainWithResolver (ATT-438) ──────────────────────────────

describe('validateChainWithResolver', () => {
  // Helper: make asn1js.fromBER and pkijs work for N anchor loads + signer parse
  function setupPkijsForChainValidation(engineResult: {
    result: boolean
    resultMessage?: string
    certificatePath?: Array<{ subject: { typesAndValues: Array<{ type: string; value: { valueBlock: { value: string } } }> } }>
  }) {
    vi.mocked(asn1js.fromBER).mockReturnValue({
      offset: 0,
      result: { mock: 'cert' },
    } as unknown as ReturnType<typeof asn1js.fromBER>)

    vi.mocked(pkijs.CertificateChainValidationEngine).mockImplementation(
      () =>
        ({
          verify: vi.fn().mockResolvedValue(engineResult),
        }) as unknown as InstanceType<typeof pkijs.CertificateChainValidationEngine>,
    )
  }

  it('uses resolver when pkiDid is provided and fingerprint matches', async () => {
    // Mock: resolver finds a fingerprint match at index 0
    vi.mocked(resolveAndMatchChain).mockResolvedValueOnce({
      matched: true,
      matchedCertIndex: 0,
      matchedKey: {
        keyId: '#key-2023',
        publicKeyJwk: { kty: 'RSA' },
        fingerprint: 'abc123',
        status: 'active',
      },
      resolution: {
        did: 'did:pki:cr:sinpe:persona-fisica',
        keys: [],
        metadata: { country: 'CR', countryName: 'Costa Rica', hierarchy: 'Test', administrator: 'Test', level: 'issuing', parentDid: 'did:pki:cr:politica:persona-fisica' },
        cached: false,
      },
    })

    // Mock: pkijs chain validation succeeds with the dynamic anchor
    setupPkijsForChainValidation({
      result: true,
      certificatePath: [
        { subject: { typesAndValues: [] } },
        { subject: { typesAndValues: [{ type: '2.5.4.3', value: { valueBlock: { value: 'CA SINPE - PERSONA FISICA v2' } } }] } },
      ],
    })

    const r = await validateChainWithResolver('aabb', ['ccdd'], 'did:pki:cr:sinpe:persona-fisica')

    expect(r.trusted).toBe(true)
    expect(r.trustSource).toBe('resolver')
    expect(r.pkiDid).toBe('did:pki:cr:sinpe:persona-fisica')
    expect(r.anchorCommonName).toBe('CA SINPE - PERSONA FISICA v2')
    expect(resolveAndMatchChain).toHaveBeenCalledWith(
      'did:pki:cr:sinpe:persona-fisica',
      ['ccdd'],
      undefined,
    )
  })

  it('falls back to bundled certs when resolver returns no match', async () => {
    // Mock: resolver found keys but no fingerprint match
    vi.mocked(resolveAndMatchChain).mockResolvedValueOnce({
      matched: false,
      matchedCertIndex: -1,
      matchedKey: null,
      resolution: {
        did: 'did:pki:cr:sinpe:persona-fisica',
        keys: [{ keyId: '#key-1', publicKeyJwk: { kty: 'RSA' }, fingerprint: 'xxx', status: 'active' }],
        metadata: { country: 'CR', countryName: 'Costa Rica', hierarchy: 'Test', administrator: 'Test', level: 'issuing' },
        cached: false,
      },
    })

    // Mock: bundled chain validation succeeds
    setupPkijsForChainValidation({
      result: true,
      certificatePath: [
        { subject: { typesAndValues: [] } },
        { subject: { typesAndValues: [{ type: '2.5.4.3', value: { valueBlock: { value: 'CA RAIZ NACIONAL' } } }] } },
      ],
    })

    const r = await validateChainWithResolver('aabb', ['ccdd'], 'did:pki:cr:sinpe:persona-fisica')

    expect(r.trusted).toBe(true)
    expect(r.trustSource).toBe('bundled')
    expect(r.pkiDid).toBeUndefined() // bundled path doesn't set pkiDid
  })

  it('falls back to bundled certs when resolver fails (network error)', async () => {
    // Mock: resolver throws
    vi.mocked(resolveAndMatchChain).mockRejectedValueOnce(new Error('network down'))

    // Mock: bundled chain validation succeeds
    setupPkijsForChainValidation({
      result: true,
      certificatePath: [
        { subject: { typesAndValues: [] } },
      ],
    })

    const r = await validateChainWithResolver('aabb', [], 'did:pki:cr:sinpe:persona-fisica')

    expect(r.trusted).toBe(true)
    expect(r.trustSource).toBe('bundled')
  })

  it('falls back to bundled certs when no pkiDid provided', async () => {
    // No pkiDid → skip resolver entirely, go straight to bundled
    setupPkijsForChainValidation({
      result: true,
      certificatePath: [{ subject: { typesAndValues: [] } }],
    })

    const r = await validateChainWithResolver('aabb', [], null)

    expect(r.trusted).toBe(true)
    expect(r.trustSource).toBe('bundled')
    expect(resolveAndMatchChain).not.toHaveBeenCalled()
  })

  it('tries parent DID when issuing CA fingerprint does not match', async () => {
    // First call (issuing CA): no match but has parentDid
    vi.mocked(resolveAndMatchChain)
      .mockResolvedValueOnce({
        matched: false,
        matchedCertIndex: -1,
        matchedKey: null,
        resolution: {
          did: 'did:pki:cr:sinpe:persona-fisica',
          keys: [{ keyId: '#key-1', publicKeyJwk: { kty: 'RSA' }, fingerprint: 'xxx', status: 'active' }],
          metadata: {
            country: 'CR', countryName: 'Costa Rica', hierarchy: 'Test',
            administrator: 'Test', level: 'issuing',
            parentDid: 'did:pki:cr:politica:persona-fisica',
          },
          cached: false,
        },
      })
      // Second call (parent DID): fingerprint match!
      .mockResolvedValueOnce({
        matched: true,
        matchedCertIndex: 0,
        matchedKey: {
          keyId: '#key-1',
          publicKeyJwk: { kty: 'RSA' },
          fingerprint: 'parent-match',
          status: 'active',
        },
        resolution: null,
      })

    // Mock: pkijs validates the chain with the parent's matched cert
    setupPkijsForChainValidation({
      result: true,
      certificatePath: [
        { subject: { typesAndValues: [] } },
        { subject: { typesAndValues: [{ type: '2.5.4.3', value: { valueBlock: { value: 'CA POLITICA PERSONA FISICA' } } }] } },
      ],
    })

    const r = await validateChainWithResolver('aabb', ['ccdd'], 'did:pki:cr:sinpe:persona-fisica')

    expect(r.trusted).toBe(true)
    expect(r.trustSource).toBe('resolver')
    expect(r.pkiDid).toBe('did:pki:cr:politica:persona-fisica')
    // Should have called resolveAndMatchChain twice
    expect(resolveAndMatchChain).toHaveBeenCalledTimes(2)
    expect(resolveAndMatchChain).toHaveBeenNthCalledWith(
      2,
      'did:pki:cr:politica:persona-fisica',
      ['ccdd'],
      undefined,
    )
  })

  it('returns trusted=false when both resolver and bundled fail', async () => {
    // Resolver: no match
    vi.mocked(resolveAndMatchChain).mockResolvedValueOnce({
      matched: false,
      matchedCertIndex: -1,
      matchedKey: null,
      resolution: {
        did: 'did:pki:cr:sinpe:persona-fisica',
        keys: [],
        metadata: { country: 'CR', countryName: 'Costa Rica', hierarchy: 'Test', administrator: 'Test', level: 'issuing' },
        cached: false,
      },
    })

    // Bundled: also fails (no matching anchors)
    vi.mocked(asn1js.fromBER).mockReturnValue({
      offset: -1,
      result: null,
    } as unknown as ReturnType<typeof asn1js.fromBER>)

    const r = await validateChainWithResolver('aabb', [], 'did:pki:cr:sinpe:persona-fisica')

    expect(r.trusted).toBe(false)
    expect(r.trustSource).toBeUndefined()
  })

  it('returns trusted=false when resolver matches but pkijs chain validation fails', async () => {
    // Resolver: fingerprint match
    vi.mocked(resolveAndMatchChain).mockResolvedValueOnce({
      matched: true,
      matchedCertIndex: 0,
      matchedKey: {
        keyId: '#key-2023',
        publicKeyJwk: { kty: 'RSA' },
        fingerprint: 'abc123',
        status: 'active',
      },
      resolution: {
        did: 'did:pki:cr:sinpe:persona-fisica',
        keys: [],
        metadata: { country: 'CR', countryName: 'Costa Rica', hierarchy: 'Test', administrator: 'Test', level: 'issuing' },
        cached: false,
      },
    })

    // pkijs: chain validation fails (e.g., cert expired)
    setupPkijsForChainValidation({
      result: false,
      resultMessage: 'Certificate has expired',
    })

    // Also make bundled path fail
    vi.mocked(asn1js.fromBER).mockReturnValue({
      offset: -1,
      result: null,
    } as unknown as ReturnType<typeof asn1js.fromBER>)

    const r = await validateChainWithResolver('aabb', ['ccdd'], 'did:pki:cr:sinpe:persona-fisica')

    // Should fall through to bundled (which also fails)
    expect(r.trusted).toBe(false)
  })

  it('resolver resolution returns null → falls back to bundled', async () => {
    // Resolver: returns null (DID not found)
    vi.mocked(resolveAndMatchChain).mockResolvedValueOnce({
      matched: false,
      matchedCertIndex: -1,
      matchedKey: null,
      resolution: null,
    })

    // Bundled: succeeds
    setupPkijsForChainValidation({
      result: true,
      certificatePath: [{ subject: { typesAndValues: [] } }],
    })

    const r = await validateChainWithResolver('aabb', [], 'did:pki:xx:unknown')

    expect(r.trusted).toBe(true)
    expect(r.trustSource).toBe('bundled')
  })
})

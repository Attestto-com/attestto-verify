/**
 * Tests for chain-validator — document integrity + resolver-only chain trust.
 *
 * The chain-validation engine is exercised through mocked pkijs so the wrapper
 * logic is deterministic. Two behaviours are pinned here:
 *
 *  1. `verifyDocumentIntegrity` / `reconstructSignedBytes` — the ATT-309 gap:
 *     until 2026-04-07 verify.attestto.com showed a green "verified" badge for
 *     tampered PDFs as long as the certificate chain was intact.
 *
 *  2. `validateChainWithResolver` — trust is RESOLVER-ONLY. The FE bundles NO
 *     national PKI certs; the only trust anchor is a PDF-embedded CA cert whose
 *     key fingerprint matches what resolver.attestto.com publishes for the
 *     issuing did:pki. If the resolver does not resolve/match, the result is an
 *     honest `trusted: false` — there is no bundled fallback.
 */

import { describe, it, expect, beforeEach, vi } from 'vitest'

// pkijs / asn1js are heavy native modules. We mock them so we can test the
// wrapper logic deterministically without crafting real CMS structures.
// NOTE (vitest 4): every mock below is invoked with `new` by the code under
// test, so its implementation MUST be a `function` (or class), never an arrow.
// Arrows are not constructible, and vitest 4 stopped silently tolerating them:
// it warns "The vi.fn() mock did not use 'function' or 'class' in its
// implementation" and the constructed value comes back empty, which surfaces as
// `integrityValid: null` rather than as a mocking error. That failure mode looks
// exactly like a real verification regression, so keep these as `function`.
vi.mock('pkijs', () => {
  return {
    setEngine: vi.fn(),
    CryptoEngine: vi.fn(),
    // `tbsView` matters: validateChainWithDynamicAnchor proves the validated
    // path begins at the signer by comparing raw DER, and that check fails
    // CLOSED on an empty view. A mock cert with no tbsView would therefore be
    // unidentifiable, so every constructed cert here carries SIGNER_TBS and a
    // test that wants a different certificate supplies its own bytes.
    Certificate: vi.fn().mockImplementation(function () {
      return { subject: { typesAndValues: [] }, tbsView: new Uint8Array([1, 2, 3]) }
    }),
    CertificateChainValidationEngine: vi.fn().mockImplementation(function () {
      return { verify: vi.fn() }
    }),
    ContentInfo: vi.fn().mockImplementation(function ({ schema }: { schema: unknown }) {
      return { content: schema }
    }),
    SignedData: vi.fn().mockImplementation(function () {
      return { verify: vi.fn() }
    }),
  }
})

vi.mock('asn1js', () => {
  return {
    fromBER: vi.fn(),
  }
})

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
  validateChainWithResolver,
  _resetChainValidatorCache,
} from './chain-validator'

/**
 * The DER bytes every mocked certificate carries by default, so the
 * leaf-identity guard in validateChainWithDynamicAnchor can identify them.
 * A test that needs a DIFFERENT or an UNIDENTIFIABLE certificate overrides the
 * `Certificate` implementation, which is why it gets reset below.
 */
const MOCK_SIGNER_TBS = new Uint8Array([1, 2, 3])

beforeEach(() => {
  _resetChainValidatorCache()
  vi.clearAllMocks()
  // `clearAllMocks` clears recorded calls but KEEPS implementations, so an
  // override set by one test silently leaks into the next. Re-establish the
  // default here rather than relying on every test to clean up after itself.
  vi.mocked(pkijs.Certificate).mockImplementation(function () {
    return {
      subject: { typesAndValues: [] },
      tbsView: MOCK_SIGNER_TBS,
    } as unknown as InstanceType<typeof pkijs.Certificate>
  })
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
    vi.mocked(pkijs.SignedData).mockImplementationOnce(function () {
      return { verify: verifyMock } as unknown as InstanceType<typeof pkijs.SignedData>
    })

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
    vi.mocked(pkijs.SignedData).mockImplementationOnce(function () {
      return { verify: verifyMock } as unknown as InstanceType<typeof pkijs.SignedData>
    })

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
    vi.mocked(pkijs.SignedData).mockImplementationOnce(function () {
      return { verify: verifyMock } as unknown as InstanceType<typeof pkijs.SignedData>
    })

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
    vi.mocked(pkijs.SignedData).mockImplementationOnce(function () {
      return { verify: verifyMock } as unknown as InstanceType<typeof pkijs.SignedData>
    })

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
    vi.mocked(pkijs.SignedData).mockImplementationOnce(function () {
      return { verify: verifyMock } as unknown as InstanceType<typeof pkijs.SignedData>
    })

    const r = await verifyDocumentIntegrity(fakeHex, fakeData)
    expect(r.integrityValid).toBe(false)
    expect(r.error).toMatch(/tampered/i)
  })
})

// ── validateChainWithResolver (resolver-only) ─────────────────────────

describe('validateChainWithResolver', () => {
  // Helper: make asn1js.fromBER + pkijs return a given engine result for the
  // dynamic-anchor validation step.
  function setupPkijsForChainValidation(engineResult: {
    result: boolean
    resultMessage?: string
    certificatePath?: Array<{
      subject: { typesAndValues: Array<{ type: string; value: { valueBlock: { value: string } } }> }
      tbsView?: Uint8Array
    }>
  }) {
    vi.mocked(asn1js.fromBER).mockReturnValue({
      offset: 0,
      result: { mock: 'cert' },
    } as unknown as ReturnType<typeof asn1js.fromBER>)

    // Default every path entry to the signer's DER, so the leaf-identity guard
    // sees a path that legitimately starts at the signer. A test exercising the
    // guard passes its own `tbsView` to say "this leaf is somebody else".
    const path = engineResult.certificatePath?.map((c) => ({
      ...c,
      tbsView: c.tbsView ?? new Uint8Array([1, 2, 3]),
    }))

    vi.mocked(pkijs.CertificateChainValidationEngine).mockImplementation(function () {
      return {
        verify: vi.fn().mockResolvedValue({ ...engineResult, certificatePath: path }),
      } as unknown as InstanceType<typeof pkijs.CertificateChainValidationEngine>
    })
  }

  it('trusts via resolver when pkiDid is provided and a fingerprint matches', async () => {
    // Resolver finds a fingerprint match at index 0 (a PDF-embedded CA cert)
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
        metadata: {
          country: 'CR',
          countryName: 'Costa Rica',
          hierarchy: 'Test',
          administrator: 'Test',
          level: 'issuing',
          parentDid: 'did:pki:cr:politica:persona-fisica',
        },
        cached: false,
        endEntityHints: null,
        ocspEndpoints: [],
      },
    })

    // pkijs chain validation succeeds using the resolver-matched cert as anchor
    setupPkijsForChainValidation({
      result: true,
      certificatePath: [
        { subject: { typesAndValues: [] } },
        {
          subject: {
            typesAndValues: [
              { type: '2.5.4.3', value: { valueBlock: { value: 'CA SINPE - PERSONA FISICA v2' } } },
            ],
          },
        },
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

  it('returns an honest trusted=false (no bundled fallback) when resolver returns no match', async () => {
    // Resolver found keys but no fingerprint match, and no parent DID to retry
    vi.mocked(resolveAndMatchChain).mockResolvedValueOnce({
      matched: false,
      matchedCertIndex: -1,
      matchedKey: null,
      resolution: {
        did: 'did:pki:cr:sinpe:persona-fisica',
        keys: [
          { keyId: '#key-1', publicKeyJwk: { kty: 'RSA' }, fingerprint: 'xxx', status: 'active' },
        ],
        metadata: {
          country: 'CR',
          countryName: 'Costa Rica',
          hierarchy: 'Test',
          administrator: 'Test',
          level: 'issuing',
        },
        cached: false,
        endEntityHints: null,
        ocspEndpoints: [],
      },
    })

    const r = await validateChainWithResolver('aabb', ['ccdd'], 'did:pki:cr:sinpe:persona-fisica')

    expect(r.trusted).toBe(false)
    expect(r.trustSource).toBeUndefined()
    expect(r.error).toMatch(/resolver-verified trust anchor/i)
    // The dynamic-anchor validation step must NOT run when nothing matched.
    expect(pkijs.CertificateChainValidationEngine).not.toHaveBeenCalled()
  })

  it('returns an honest trusted=false when the resolver call throws (network error)', async () => {
    vi.mocked(resolveAndMatchChain).mockRejectedValueOnce(new Error('network down'))

    const r = await validateChainWithResolver('aabb', [], 'did:pki:cr:sinpe:persona-fisica')

    expect(r.trusted).toBe(false)
    expect(r.trustSource).toBeUndefined()
    expect(r.error).toMatch(/resolver-verified trust anchor/i)
  })

  it('returns an honest trusted=false when no pkiDid provided (resolver skipped)', async () => {
    const r = await validateChainWithResolver('aabb', [], null)

    expect(r.trusted).toBe(false)
    expect(r.trustSource).toBeUndefined()
    expect(r.error).toMatch(/no issuing did:pki/i)
    expect(resolveAndMatchChain).not.toHaveBeenCalled()
  })

  it('refuses to trust a path that does not begin at the signer, even when pkijs says OK', async () => {
    // THE LEAF-IDENTITY GUARD. pkijs selects the end entity POSITIONALLY, from
    // the last element of [...trustedCerts, ...certs], and that behaviour is
    // undocumented. If a version bump ever shifts it, pkijs will happily
    // validate some OTHER certificate against the anchor and report success:
    // measured against real CR certs, anchoring one level up returns
    // result:true for a FORGED signer, and for a pool with no signer in it at
    // all. `cryptographicallyVerified` is the input every downstream trust
    // floor keys off, so this must be caught here and not further down.
    //
    // Simulated by having pkijs return success with a certificatePath whose
    // leaf carries different DER to the signer.
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
        metadata: { country: 'CR', level: 'issuing' },
      },
    } as unknown as Awaited<ReturnType<typeof resolveAndMatchChain>>)

    setupPkijsForChainValidation({
      result: true,
      certificatePath: [
        {
          subject: { typesAndValues: [] },
          // NOT the signer's DER: some other certificate entirely.
          tbsView: new Uint8Array([9, 9, 9]),
        },
      ],
    })

    const r = await validateChainWithResolver('aabb', ['ccdd'], 'did:pki:cr:sinpe:persona-fisica')

    expect(r.trusted).toBe(false)
    expect(r.error).toMatch(/does not begin at the signer/i)
  })

  it('refuses to trust when the leaf certificate cannot be identified at all', async () => {
    // Fail CLOSED on an unidentifiable certificate. `new Uint8Array(undefined)`
    // produces an EMPTY array, so a naive byte comparison would find two
    // unidentifiable certs "equal" and wave the chain through. "I could not
    // identify either certificate" must never be reported as "they match".
    vi.mocked(resolveAndMatchChain).mockResolvedValueOnce({
      matched: true,
      matchedCertIndex: 0,
      matchedKey: { keyId: '#key-2023', fingerprint: 'abc123', status: 'active' },
      resolution: { did: 'did:pki:cr:sinpe:persona-fisica', keys: [], metadata: {} },
    } as unknown as Awaited<ReturnType<typeof resolveAndMatchChain>>)

    setupPkijsForChainValidation({
      result: true,
      certificatePath: [{ subject: { typesAndValues: [] }, tbsView: new Uint8Array([]) }],
    })
    // BOTH sides unidentifiable: the parsed signer must also come back with an
    // empty view, otherwise the length comparison rejects it for the wrong
    // reason and this test would pass without the fail-closed check present.
    vi.mocked(pkijs.Certificate).mockImplementation(function () {
      return {
        subject: { typesAndValues: [] },
        tbsView: new Uint8Array([]),
      } as unknown as InstanceType<typeof pkijs.Certificate>
    })

    const r = await validateChainWithResolver('aabb', ['ccdd'], 'did:pki:cr:sinpe:persona-fisica')

    expect(r.trusted).toBe(false)
    expect(r.error).toMatch(/does not begin at the signer/i)
  })

  it('tries the parent DID when the issuing CA fingerprint does not match', async () => {
    // First call (issuing CA): no match but has parentDid
    vi.mocked(resolveAndMatchChain)
      .mockResolvedValueOnce({
        matched: false,
        matchedCertIndex: -1,
        matchedKey: null,
        resolution: {
          did: 'did:pki:cr:sinpe:persona-fisica',
          keys: [
            { keyId: '#key-1', publicKeyJwk: { kty: 'RSA' }, fingerprint: 'xxx', status: 'active' },
          ],
          metadata: {
            country: 'CR',
            countryName: 'Costa Rica',
            hierarchy: 'Test',
            administrator: 'Test',
            level: 'issuing',
            parentDid: 'did:pki:cr:politica:persona-fisica',
          },
          cached: false,
          endEntityHints: null,
          ocspEndpoints: [],
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

    // pkijs validates the chain with the parent's matched cert
    setupPkijsForChainValidation({
      result: true,
      certificatePath: [
        { subject: { typesAndValues: [] } },
        {
          subject: {
            typesAndValues: [
              { type: '2.5.4.3', value: { valueBlock: { value: 'CA POLITICA PERSONA FISICA' } } },
            ],
          },
        },
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

  it('returns trusted=false when resolver matches but pkijs chain validation fails', async () => {
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
        metadata: {
          country: 'CR',
          countryName: 'Costa Rica',
          hierarchy: 'Test',
          administrator: 'Test',
          level: 'issuing',
        },
        cached: false,
        endEntityHints: null,
        ocspEndpoints: [],
      },
    })

    // pkijs: chain validation fails (e.g., cert expired). No parent DID to retry.
    setupPkijsForChainValidation({
      result: false,
      resultMessage: 'Certificate has expired',
    })

    const r = await validateChainWithResolver('aabb', ['ccdd'], 'did:pki:cr:sinpe:persona-fisica')

    expect(r.trusted).toBe(false)
    expect(r.trustSource).toBeUndefined()
    expect(r.error).toMatch(/resolver-verified trust anchor/i)
  })

  it('resolver resolution returns null → honest trusted=false', async () => {
    vi.mocked(resolveAndMatchChain).mockResolvedValueOnce({
      matched: false,
      matchedCertIndex: -1,
      matchedKey: null,
      resolution: null,
    })

    const r = await validateChainWithResolver('aabb', [], 'did:pki:xx:unknown')

    expect(r.trusted).toBe(false)
    expect(r.trustSource).toBeUndefined()
    expect(r.error).toMatch(/resolver-verified trust anchor/i)
  })
})

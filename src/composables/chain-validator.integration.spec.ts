/**
 * chain-validator, exercised for real: genuine pkijs, genuine CR certificates,
 * with ONLY the resolver mocked.
 *
 * WHY THIS FILE EXISTS. Two sibling specs cover this module and neither one
 * actually executes the code that broke:
 *
 *   - `chain-validator.spec.ts` mocks pkijs wholesale, so the candidate-pool
 *     construction and the leaf-identity guard never run.
 *   - `chain-validator.cr-anchor.spec.ts` uses real certificates but drives
 *     `CertificateChainValidationEngine` directly through its own helper, so it
 *     pins *pkijs behaviour* rather than our use of it.
 *
 * Proven by mutation: reverting the candidate pool to the pre-fix ordering left
 * both suites fully green, as did deleting the leaf-identity guard. A fix that
 * no test can miss the absence of is not a fixed bug, it is a coincidence.
 *
 * Everything here goes through the public `validateChainWithResolver`, so the
 * ordering and the guard are on the executed path. The resolver is mocked
 * because it is a network dependency, not because the crypto needs faking.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest'

vi.mock('./pki-resolver.js', () => ({
  resolveAndMatchChain: vi.fn(),
}))

import { resolveAndMatchChain } from './pki-resolver'
import { validateChainWithResolver, _resetChainValidatorCache } from './chain-validator'
import {
  SIGNER_PF_DER_HEX,
  POLITICA_PF_DER_HEX,
  SINPE_PF_DER_HEX,
  FORGED_SINPE_DER_HEX,
} from '../../tests/fixtures/cr-persona-fisica-certs.js'

/** The chain order a real CR Firma Digital PDF embeds: issuing CA, then policy CA. */
const INTERMEDIATES = [SINPE_PF_DER_HEX, POLITICA_PF_DER_HEX]
const DID = 'did:pki:cr:sinpe:persona-fisica'

/** Resolver says: fingerprint matched the CA cert at `index` of the pool. */
function resolverMatches(index: number) {
  vi.mocked(resolveAndMatchChain).mockResolvedValue({
    matched: true,
    matchedCertIndex: index,
    matchedKey: { keyId: '#key-2023', status: 'active' },
    resolution: { keys: [], endEntityHints: null, metadata: {} },
  } as unknown as Awaited<ReturnType<typeof resolveAndMatchChain>>)
}

beforeEach(() => {
  vi.clearAllMocks()
  _resetChainValidatorCache()
})

describe('validateChainWithResolver, real pkijs and real CR certificates', () => {
  it('verifies a genuine chain anchored at the fingerprint-matched issuing CA', async () => {
    // THIS IS THE REGRESSION TEST FOR THE CR BUG. It fails if the candidate
    // pool goes back to [signerCert, ...intermediates, anchorCert], because
    // pkijs takes the LAST entry as the leaf and would try to build a path up
    // from a CA instead of from the signer.
    resolverMatches(0) // index 0 of INTERMEDIATES is CA SINPE, the issuing CA

    const r = await validateChainWithResolver(SIGNER_PF_DER_HEX, INTERMEDIATES, DID)

    expect(r.trusted).toBe(true)
    expect(r.anchorCommonName).toContain('CA SINPE')
    expect(r.trustSource).toBe('resolver')
    expect(r.error).toBeNull()
    // The built path must start at the signer, not at some CA that merely
    // happens to chain to the anchor.
    expect(r.chainLength).toBeGreaterThan(1)
  })

  it('verifies when the resolver matches the policy CA above the issuing CA', async () => {
    resolverMatches(1) // CA POLITICA

    const r = await validateChainWithResolver(SIGNER_PF_DER_HEX, INTERMEDIATES, DID)

    expect(r.trusted).toBe(true)
    expect(r.error).toBeNull()
  })

  it('rejects a forged signer against a genuine anchor', async () => {
    // The self-signed cert impersonating CA SINPE, offered as the end entity.
    resolverMatches(0)

    const r = await validateChainWithResolver(FORGED_SINPE_DER_HEX, INTERMEDIATES, DID)

    expect(r.trusted).toBe(false)
    expect(r.error).toBeTruthy()
  })

  it('rejects when the PDF embeds no CA certificates at all', async () => {
    // Leaf-only PDF. There is no candidate anchor, so the resolver cannot match
    // anything and the chain must not be trusted. See ATT-1282.
    vi.mocked(resolveAndMatchChain).mockResolvedValue({
      matched: false,
      matchedCertIndex: -1,
      matchedKey: null,
      resolution: { keys: [], endEntityHints: null, metadata: {} },
    } as unknown as Awaited<ReturnType<typeof resolveAndMatchChain>>)

    const r = await validateChainWithResolver(SIGNER_PF_DER_HEX, [], DID)

    expect(r.trusted).toBe(false)
  })

  it('reports an honest, specific error when the resolver is unreachable', async () => {
    vi.mocked(resolveAndMatchChain).mockRejectedValue(new Error('network down'))

    const r = await validateChainWithResolver(SIGNER_PF_DER_HEX, INTERMEDIATES, DID)

    expect(r.trusted).toBe(false)
    // Must NOT claim a fingerprint mismatch: that was the misleading message
    // this module used to return for every failure mode alike.
    expect(r.error).toMatch(/could not be reached|unusable response/)
    expect(r.error).not.toMatch(/no matching key fingerprint/)
  })

  it('distinguishes "no fingerprint matched" from "resolver unreachable"', async () => {
    vi.mocked(resolveAndMatchChain).mockResolvedValue({
      matched: false,
      matchedCertIndex: -1,
      matchedKey: null,
      resolution: { keys: [{ keyId: '#key-1' }], endEntityHints: null, metadata: {} },
    } as unknown as Awaited<ReturnType<typeof resolveAndMatchChain>>)

    const r = await validateChainWithResolver(SIGNER_PF_DER_HEX, INTERMEDIATES, DID)

    expect(r.trusted).toBe(false)
    expect(r.error).toMatch(/none\s+matched the fingerprint|no fingerprint/i)
  })
})

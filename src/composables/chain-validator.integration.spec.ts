/**
 * Integration tests for chain-validator — real pkijs crypto, no mocks.
 *
 * These tests use actual certificate DER bytes extracted from a public
 * CR government procurement document (SICOP public record) and verify
 * them against the bundled @attestto/trust/cr trust anchors.
 *
 * ATT-311: Regression fixtures for clean + forged chain validation.
 */

import { describe, it, expect, beforeEach } from 'vitest'
import {
  validateChain,
  _resetChainValidatorCache,
} from './chain-validator'
import {
  SIGNER_PF_DER_HEX,
  INTERMEDIATES_PF,
  FORGED_SINPE_DER_HEX,
} from '../../tests/fixtures/cr-persona-fisica-certs'

beforeEach(() => {
  _resetChainValidatorCache()
})

describe('chain-validator integration (real crypto)', () => {
  it('validates a real CR Persona Física chain against bundled trust anchors', async () => {
    const result = await validateChain(SIGNER_PF_DER_HEX, INTERMEDIATES_PF)

    expect(result.trusted).toBe(true)
    expect(result.chainLength).toBeGreaterThanOrEqual(2)
    expect(result.anchorCommonName).toBeTruthy()
    expect(result.error).toBeNull()
  }, 15_000)

  it('rejects a forged cert that mimics CA SINPE CN but has wrong key', async () => {
    // Forged cert is self-signed with CN="CA SINPE - PERSONA FISICA v2"
    // It should NOT validate because its key doesn't chain to the real root
    const result = await validateChain(FORGED_SINPE_DER_HEX, [])

    expect(result.trusted).toBe(false)
    expect(result.error).toBeTruthy()
  }, 15_000)

  it('rejects a forged cert even when real intermediates are provided', async () => {
    // Attacker provides real intermediates but a forged signer cert —
    // the signer's issuer signature won't match any intermediate's key
    const result = await validateChain(FORGED_SINPE_DER_HEX, INTERMEDIATES_PF)

    expect(result.trusted).toBe(false)
    expect(result.error).toBeTruthy()
  }, 15_000)

  it('rejects an empty signer cert hex', async () => {
    const result = await validateChain('', [])

    expect(result.trusted).toBe(false)
    expect(result.error).toBeTruthy()
  })

  it('rejects garbage hex as signer cert', async () => {
    const result = await validateChain('deadbeefcafebabe', [])

    expect(result.trusted).toBe(false)
    expect(result.error).toBeTruthy()
  })
})

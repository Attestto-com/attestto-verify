/**
 * CR Firma Digital chain validation — the pkijs candidate-pool contract.
 *
 * REGRESSION (2026-08-12): every Costa Rican PAdES signature was stuck at
 * level 'parsed' and could never reach 'verified'. Everything upstream worked
 * — did:pki derivation, the live resolver, and the SHA-256 fingerprint match
 * against the embedded CA SINPE cert all succeeded — but
 * `validateChainWithDynamicAnchor` built its candidate pool as
 * `[signerCert, ...intermediates, anchorCert]`.
 *
 * pkijs concatenates `[...trustedCerts, ...certs]`, dedupes, and treats the
 * LAST element as the end-entity to validate (build/index.es.js:14929-14942).
 * With the signer first, the leaf was whichever CA landed last, so pkijs tried
 * to build a path upward from an intermediate and returned "Incorrect name
 * chaining" / "No valid certificate paths found".
 *
 * These tests pin the engine contract directly, with no network: if a pkijs
 * upgrade changes its positional leaf selection, they go red here rather than
 * silently turning every CR signature yellow in production.
 *
 * THE SECURITY TEST IS `rejects a forged signer`. The tempting "fix" for the
 * original bug — anchoring at the topmost embedded CA — makes pkijs validate
 * the SINPE→POLITICA link and return trusted:true while never touching the
 * end-entity, which greenlights an arbitrary or forged signer cert. That is
 * why validateChainWithDynamicAnchor asserts the built path starts at our
 * signer, and why that assertion is exercised below.
 */

import { describe, it, expect } from 'vitest'
import * as pkijs from 'pkijs'
import * as asn1js from 'asn1js'
import {
  SIGNER_PF_DER_HEX,
  POLITICA_PF_DER_HEX,
  SINPE_PF_DER_HEX,
  FORGED_SINPE_DER_HEX,
} from '../../tests/fixtures/cr-persona-fisica-certs.js'

function parseCert(hex: string): pkijs.Certificate {
  const clean = hex.replace(/\s+/g, '')
  const bytes = new Uint8Array(clean.length / 2)
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(clean.substring(i * 2, i * 2 + 2), 16)
  }
  const asn1 = asn1js.fromBER(bytes.buffer as ArrayBuffer)
  expect(asn1.offset).not.toBe(-1)
  return new pkijs.Certificate({ schema: asn1.result })
}

const signer = parseCert(SIGNER_PF_DER_HEX)
const sinpe = parseCert(SINPE_PF_DER_HEX)
const politica = parseCert(POLITICA_PF_DER_HEX)
const forged = parseCert(FORGED_SINPE_DER_HEX)

/** The cert pool shape that chain-validator.ts:629-632 builds. */
async function verifyWithPool(
  anchor: pkijs.Certificate,
  certs: pkijs.Certificate[],
): Promise<{ ok: boolean; message: string; leafIsSigner: boolean }> {
  const engine = new pkijs.CertificateChainValidationEngine({
    trustedCerts: [anchor],
    certs,
  })
  const result = await engine.verify()
  const path = result.certificatePath || []
  const leaf = path[0]
  const leafIsSigner =
    !!leaf &&
    new Uint8Array(leaf.tbsView).length === new Uint8Array(signer.tbsView).length &&
    new Uint8Array(leaf.tbsView).every((b, i) => b === new Uint8Array(signer.tbsView)[i])
  return { ok: result.result, message: result.resultMessage || '', leafIsSigner }
}

describe('CR chain validation — pkijs candidate pool ordering', () => {
  it('verifies a real 3-cert CR chain when the signer is LAST', async () => {
    // The shipped shape: [...intermediates, signerCert], anchored at the
    // fingerprint-matched issuing CA. A cert ABOVE the anchor (POLITICA) is
    // harmless in this ordering.
    const { ok, leafIsSigner } = await verifyWithPool(sinpe, [politica, sinpe, signer])
    expect(ok).toBe(true)
    expect(leafIsSigner).toBe(true)
  })

  it('verifies a 2-cert CR chain (leaf + issuing CA only)', async () => {
    const { ok, leafIsSigner } = await verifyWithPool(sinpe, [politica, signer])
    expect(ok).toBe(true)
    expect(leafIsSigner).toBe(true)
  })

  it('FAILS with the old ordering — signer first, anchor duplicated', async () => {
    // This is the exact pool the code built before the fix. Pinned so nobody
    // "tidies" the array back into this shape.
    const { ok, message } = await verifyWithPool(sinpe, [signer, politica, sinpe, sinpe])
    expect(ok).toBe(false)
    expect(message).toMatch(/Incorrect name chaining|No valid certificate paths/)
  })

  it('rejects a forged signer', async () => {
    const { ok } = await verifyWithPool(sinpe, [politica, sinpe, forged])
    expect(ok).toBe(false)
  })

  it('rejects a forged anchor', async () => {
    // Self-signed cert whose CN impersonates CA SINPE. It can never be the
    // anchor in production (the resolver fingerprint would not match), but if
    // it somehow were, the real signer must still not chain to it.
    const { ok } = await verifyWithPool(forged, [politica, sinpe, signer])
    expect(ok).toBe(false)
  })

  it('SECURITY: anchoring above the signer validates a path that excludes it', async () => {
    // Documents precisely why validateChainWithDynamicAnchor needs its
    // leaf-identity guard. Anchoring at POLITICA with the signer NOT last makes
    // pkijs happily verify SINPE -> POLITICA and report success, with the
    // end-entity never examined. `ok` is true; `leafIsSigner` is false.
    // The guard keys off leafIsSigner, which is the only thing standing
    // between this pkijs result and a green badge on a forged signature.
    const { ok, leafIsSigner } = await verifyWithPool(politica, [signer, sinpe, politica])
    expect(ok).toBe(true)
    expect(leafIsSigner).toBe(false)

    // Same pool, but with a FORGED signer — pkijs still returns true, because
    // it never looks at the end-entity. This is the bypass in one assertion.
    const forgedRun = await verifyWithPool(politica, [forged, sinpe, politica])
    expect(forgedRun.ok).toBe(true)
    expect(forgedRun.leafIsSigner).toBe(false)
  })
})

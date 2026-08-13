/**
 * ATT-361 — Attestto self-attested signature verifier spec.
 *
 * The load-bearing test reads the actual signed carta MICITT/MOPT and
 * confirms the verifier extracts + cryptographically validates the
 * Attestto signature. If this test does NOT pass, verify.attestto.com
 * displays "UNSIGNED" for the carta and the document cannot ship.
 */

import { describe, it, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import {
  extractAttesttoSelfAttestedSignatures,
  isSmallOrderEd25519Key,
} from './attestto-self-attested'

// The committed self-attested reference fixture (ATT-1270).
//
// This was a HARDCODED ABSOLUTE PATH containing a developer username, committed
// to a public repo, pointing into the folder that holds real PII. It also
// degraded silently to describe.skip when absent, so the case its own comment
// called "the test that matters for the carta ship decision" ran on exactly one
// machine and nothing reported that it had not run anywhere else.
//
// src/__fixtures__/self-attested-reference.pdf is an equivalent with a
// synthetic signer and a throwaway Ed25519 key, produced by
// scripts/make-self-attested-fixture.mjs. Only the signed PDF is committed.
// The signature is real: the extractor rebuilds the canonical payload and
// verifies Ed25519 over it, so these cases cover the crypto path.
const CARTA_PATH = fileURLToPath(
  new URL('../__fixtures__/self-attested-reference.pdf', import.meta.url),
)

describe('extractAttesttoSelfAttestedSignatures', () => {
  it('returns empty for a PDF without an Attestto keyword', async () => {
    const fakePdf = new TextEncoder().encode('%PDF-1.7\n%nothing here\n')
    const sigs = await extractAttesttoSelfAttestedSignatures(fakePdf)
    expect(sigs).toEqual([])
  })

  it('detects an Attestto keyword token in raw bytes', async () => {
    // Manufactured token — base64 of an obviously broken JSON. We
    // expect detection (returns 1 row) but not crypto verification.
    const fakePdf = new TextEncoder().encode('%PDF-1.7\n/Keywords (attestto-sig-v1:bm90anNvbg==)\n')
    const sigs = await extractAttesttoSelfAttestedSignatures(fakePdf)
    expect(sigs).toHaveLength(1)
    expect(sigs[0].level).toBe('detected')
    expect(sigs[0].subFilter).toBe('attestto.self-attested.v1')
    expect(sigs[0].integrityError).toMatch(/decode failed/)
  })

  // ── Real fixture: the actual signed carta. This is the test that ──
  // ── matters for the carta ship decision. Skipped if not present. ──

  it('detects unsupported version (v !== 1)', async () => {
    const payload = {
      v: 2,
      type: ['VerifiableCredential', 'AttesttoPdfSignature'],
      issuer: 'did:key:z6Mk',
      signedAt: '2026-01-01T00:00:00Z',
      documentHash: 'abc',
      fileName: 'test.pdf',
      level: 'self-attested',
      mock: false,
      mode: 'final',
      proof: {
        type: 'Other',
        created: '',
        verificationMethod: '',
        proofPurpose: 'assertionMethod',
        proofValue: '',
        publicKey: '',
      },
    }
    const b64 = Buffer.from(JSON.stringify(payload)).toString('base64')
    const fakePdf = new TextEncoder().encode(`%PDF-1.7\n/Keywords (attestto-sig-v1:${b64})\n`)
    const sigs = await extractAttesttoSelfAttestedSignatures(fakePdf)
    expect(sigs).toHaveLength(1)
    expect(sigs[0].level).toBe('detected')
    expect(sigs[0].integrityError).toMatch(/Unsupported/)
  })

  it('detects bad public key length', async () => {
    const payload = {
      v: 1,
      type: ['VerifiableCredential', 'AttesttoPdfSignature'],
      issuer: 'did:key:z6Mk',
      signedAt: '2026-01-01T00:00:00Z',
      documentHash: 'abc',
      fileName: 'test.pdf',
      level: 'self-attested',
      mock: false,
      mode: 'final',
      proof: {
        type: 'Ed25519Signature2020',
        created: '2026-01-01T00:00:00Z',
        verificationMethod: 'did:key:z6Mk#key-1',
        proofPurpose: 'assertionMethod',
        proofValue: Buffer.alloc(64).toString('base64'),
        publicKey: Buffer.alloc(16).toString('base64'), // wrong length
      },
    }
    const b64 = Buffer.from(JSON.stringify(payload)).toString('base64')
    const fakePdf = new TextEncoder().encode(`%PDF-1.7\n/Keywords (attestto-sig-v1:${b64})\n`)
    const sigs = await extractAttesttoSelfAttestedSignatures(fakePdf)
    expect(sigs).toHaveLength(1)
    expect(sigs[0].level).toBe('detected')
    expect(sigs[0].integrityError).toMatch(/Public key length is 16/)
  })

  it('detects bad signature length', async () => {
    const payload = {
      v: 1,
      type: ['VerifiableCredential', 'AttesttoPdfSignature'],
      issuer: 'did:key:z6Mk',
      signedAt: '2026-01-01T00:00:00Z',
      documentHash: 'abc',
      fileName: 'test.pdf',
      level: 'self-attested',
      mock: false,
      mode: 'final',
      proof: {
        type: 'Ed25519Signature2020',
        created: '2026-01-01T00:00:00Z',
        verificationMethod: 'did:key:z6Mk#key-1',
        proofPurpose: 'assertionMethod',
        proofValue: Buffer.alloc(32).toString('base64'), // wrong length
        publicKey: Buffer.alloc(32).toString('base64'),
      },
    }
    const b64 = Buffer.from(JSON.stringify(payload)).toString('base64')
    const fakePdf = new TextEncoder().encode(`%PDF-1.7\n/Keywords (attestto-sig-v1:${b64})\n`)
    const sigs = await extractAttesttoSelfAttestedSignatures(fakePdf)
    expect(sigs).toHaveLength(1)
    expect(sigs[0].level).toBe('detected')
    expect(sigs[0].integrityError).toMatch(/Signature length is 32/)
  })

  it('rejects a small-order (all-zero) public key as tampered, never verified', async () => {
    const payload = {
      v: 1,
      type: ['VerifiableCredential', 'AttesttoPdfSignature'],
      issuer: 'did:key:z6Mk',
      issuerName: 'Test User',
      signedAt: '2026-01-01T00:00:00Z',
      documentHash: 'abc',
      fileName: 'test.pdf',
      level: 'self-attested',
      mock: false,
      mode: 'final',
      proof: {
        type: 'Ed25519Signature2020',
        created: '2026-01-01T00:00:00Z',
        verificationMethod: 'did:key:z6Mk#key-1',
        proofPurpose: 'assertionMethod',
        proofValue: Buffer.alloc(64).toString('base64'),
        publicKey: Buffer.alloc(32).toString('base64'),
      },
    }
    const b64 = Buffer.from(JSON.stringify(payload)).toString('base64')
    const fakePdf = new TextEncoder().encode(`%PDF-1.7\n/Keywords (attestto-sig-v1:${b64})\n`)
    const sigs = await extractAttesttoSelfAttestedSignatures(fakePdf)
    expect(sigs).toHaveLength(1)
    // SECURITY: an all-zero public key is a small-order curve point. Web
    // Crypto's cofactored verification accepts it for ~1 message in 4, so
    // an attacker with NO private key can grind `signedAt` a few times and
    // forge a signature. This must be a hard rejection — exactly
    // 'tampered', never 'verified' and never the softer 'parsed'.
    expect(sigs[0].level).toBe('tampered')
    expect(sigs[0].documentIntegrityVerified).toBe(false)
    // It got past the length checks and reached verification.
    expect(sigs[0].subFilter).toBe('attestto.self-attested.v1')
    expect(sigs[0].name).toBe('Test User')
  })

  it('rejects every known small-order Ed25519 point, with either sign bit', () => {
    // libsodium's ge25519_has_small_order blocklist. None of these can be a
    // genuine signing key; all are forgery vectors under cofactored verify.
    const smallOrder = [
      '0000000000000000000000000000000000000000000000000000000000000000',
      '0100000000000000000000000000000000000000000000000000000000000000',
      '26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05',
      'c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a',
      'ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f',
      'edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f',
      'eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f',
    ]
    for (const hex of smallOrder) {
      const key = Uint8Array.from(Buffer.from(hex, 'hex'))
      expect(isSmallOrderEd25519Key(key), `canonical ${hex}`).toBe(true)
      // Same point with the x-sign bit set — equally forgeable, must also go.
      const flipped = new Uint8Array(key)
      flipped[31] |= 0x80
      expect(isSmallOrderEd25519Key(flipped), `sign-flipped ${hex}`).toBe(true)
    }
  })

  it('accepts a real large-order Ed25519 public key', async () => {
    // A genuine generated key must NOT be caught by the small-order filter,
    // otherwise the fix would break every legitimate signature.
    const { publicKey } = (await crypto.subtle.generateKey({ name: 'Ed25519' }, true, [
      'sign',
      'verify',
    ])) as CryptoKeyPair
    const raw = new Uint8Array(await crypto.subtle.exportKey('raw', publicKey))
    expect(raw.length).toBe(32)
    expect(isSmallOrderEd25519Key(raw)).toBe(false)
  })

  it('round-trips a genuinely signed payload to verified', async () => {
    // The positive control: proves the small-order rejection does not block
    // real signatures, and that `level: 'verified'` is actually reachable.
    const keyPair = (await crypto.subtle.generateKey({ name: 'Ed25519' }, true, [
      'sign',
      'verify',
    ])) as CryptoKeyPair
    const rawPub = new Uint8Array(await crypto.subtle.exportKey('raw', keyPair.publicKey))

    const unsigned = {
      v: 1,
      type: ['VerifiableCredential', 'AttesttoPdfSignature'],
      issuer: 'did:key:z6MkTest',
      issuerName: 'Real Signer',
      signedAt: '2026-01-01T00:00:00Z',
      documentHash: 'abc',
      fileName: 'test.pdf',
      level: 'self-attested',
      mock: false,
      mode: 'final',
    }
    // Canonicalization must match canonicalPayloadBytes(): proof stripped,
    // object keys sorted, compact JSON.
    const sortedReplacer = (_k: string, value: unknown): unknown => {
      if (value && typeof value === 'object' && !Array.isArray(value)) {
        const sorted: Record<string, unknown> = {}
        for (const k of Object.keys(value as Record<string, unknown>).sort()) {
          sorted[k] = (value as Record<string, unknown>)[k]
        }
        return sorted
      }
      return value
    }
    const canonical = new TextEncoder().encode(JSON.stringify(unsigned, sortedReplacer))
    const sigBytes = new Uint8Array(
      await crypto.subtle.sign({ name: 'Ed25519' }, keyPair.privateKey, canonical),
    )

    const payload = {
      ...unsigned,
      proof: {
        type: 'Ed25519Signature2020',
        created: '2026-01-01T00:00:00Z',
        verificationMethod: 'did:key:z6MkTest#key-1',
        proofPurpose: 'assertionMethod',
        proofValue: Buffer.from(sigBytes).toString('base64'),
        publicKey: Buffer.from(rawPub).toString('base64'),
      },
    }
    const b64 = Buffer.from(JSON.stringify(payload)).toString('base64')
    const fakePdf = new TextEncoder().encode(`%PDF-1.7\n/Keywords (attestto-sig-v1:${b64})\n`)
    const sigs = await extractAttesttoSelfAttestedSignatures(fakePdf)
    expect(sigs).toHaveLength(1)
    expect(sigs[0].level).toBe('verified')
    expect(sigs[0].documentIntegrityVerified).toBe(true)

    // Flip one byte of the signed content — must become tampered.
    const tamperedPayload = { ...payload, documentHash: 'abd' }
    const tb64 = Buffer.from(JSON.stringify(tamperedPayload)).toString('base64')
    const tamperedPdf = new TextEncoder().encode(`%PDF-1.7\n/Keywords (attestto-sig-v1:${tb64})\n`)
    const tamperedSigs = await extractAttesttoSelfAttestedSignatures(tamperedPdf)
    expect(tamperedSigs[0].level).toBe('tampered')
  })

  it('extracts from hex-encoded /Keywords (UTF-16BE with BOM)', async () => {
    const token = 'attestto-sig-v1:bm90anNvbg=='
    // Encode as UTF-16BE with FEFF BOM
    let hex = 'FEFF'
    for (const c of token) {
      hex += '00' + c.charCodeAt(0).toString(16).padStart(2, '0')
    }
    const fakePdf = new TextEncoder().encode(`%PDF-1.7\n/Keywords <${hex}>\n`)
    const sigs = await extractAttesttoSelfAttestedSignatures(fakePdf)
    expect(sigs).toHaveLength(1)
    expect(sigs[0].subFilter).toBe('attestto.self-attested.v1')
  })

  describe('against the committed self-attested reference fixture', () => {
    it('finds at least one Attestto self-attested signature', async () => {
      const bytes = new Uint8Array(readFileSync(CARTA_PATH))
      const sigs = await extractAttesttoSelfAttestedSignatures(bytes)
      expect(sigs.length).toBeGreaterThan(0)
    })

    it('cryptographically verifies the Attestto signature', async () => {
      const bytes = new Uint8Array(readFileSync(CARTA_PATH))
      const sigs = await extractAttesttoSelfAttestedSignatures(bytes)
      const attesttoSig = sigs.find((s) => s.subFilter === 'attestto.self-attested.v1')
      expect(attesttoSig).toBeDefined()
      expect(attesttoSig?.level).toBe('verified')
      expect(attesttoSig?.documentIntegrityVerified).toBe(true)
      expect(attesttoSig?.integrityError).toBeNull()
      // Issuer should be a did:key
      expect(attesttoSig?.did).toMatch(/^did:key:z/)
    })

    it('extracts the signer name from the embedded VC', async () => {
      const bytes = new Uint8Array(readFileSync(CARTA_PATH))
      const sigs = await extractAttesttoSelfAttestedSignatures(bytes)
      const attesttoSig = sigs.find((s) => s.subFilter === 'attestto.self-attested.v1')
      // Guards against the unparseable-stub fallback, which emits the generic
      // 'Attestto signature (unparseable)' instead of the embedded issuerName.
      expect(attesttoSig?.name).toBe('Attestto Test Signer')
      expect(attesttoSig?.name).not.toMatch(/unparseable/i)
    })
  })
})

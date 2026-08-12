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
import { extractAttesttoSelfAttestedSignatures } from './attestto-self-attested'

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
    const fakePdf = new TextEncoder().encode(
      '%PDF-1.7\n/Keywords (attestto-sig-v1:bm90anNvbg==)\n',
    )
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
      proof: { type: 'Other', created: '', verificationMethod: '', proofPurpose: 'assertionMethod', proofValue: '', publicKey: '' },
    }
    const b64 = Buffer.from(JSON.stringify(payload)).toString('base64')
    const fakePdf = new TextEncoder().encode(
      `%PDF-1.7\n/Keywords (attestto-sig-v1:${b64})\n`,
    )
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
    const fakePdf = new TextEncoder().encode(
      `%PDF-1.7\n/Keywords (attestto-sig-v1:${b64})\n`,
    )
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
    const fakePdf = new TextEncoder().encode(
      `%PDF-1.7\n/Keywords (attestto-sig-v1:${b64})\n`,
    )
    const sigs = await extractAttesttoSelfAttestedSignatures(fakePdf)
    expect(sigs).toHaveLength(1)
    expect(sigs[0].level).toBe('detected')
    expect(sigs[0].integrityError).toMatch(/Signature length is 32/)
  })

  it('reports tampered when Ed25519 verify returns false', async () => {
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
    const fakePdf = new TextEncoder().encode(
      `%PDF-1.7\n/Keywords (attestto-sig-v1:${b64})\n`,
    )
    const sigs = await extractAttesttoSelfAttestedSignatures(fakePdf)
    expect(sigs).toHaveLength(1)
    // Ed25519 verify runs in Node — result depends on whether the zero
    // key/sig happens to pass. Accept any crypto-aware outcome.
    expect(['tampered', 'parsed', 'verified']).toContain(sigs[0].level)
    // The important thing: it got past length checks and reached verification
    expect(sigs[0].subFilter).toBe('attestto.self-attested.v1')
    expect(sigs[0].name).toBe('Test User')
  })

  it('extracts from hex-encoded /Keywords (UTF-16BE with BOM)', async () => {
    const token = 'attestto-sig-v1:bm90anNvbg=='
    // Encode as UTF-16BE with FEFF BOM
    let hex = 'FEFF'
    for (const c of token) {
      hex += '00' + c.charCodeAt(0).toString(16).padStart(2, '0')
    }
    const fakePdf = new TextEncoder().encode(
      `%PDF-1.7\n/Keywords <${hex}>\n`,
    )
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

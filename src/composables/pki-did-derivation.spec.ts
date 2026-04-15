/**
 * Tests for pki-did-derivation — ATT-438
 *
 * Verifies that CA common names from parsed certificate chains are correctly
 * mapped to did:pki identifiers for resolver-backed trust anchor resolution.
 */

import { describe, it, expect } from 'vitest'
import { derivePkiDids } from './pki-did-derivation'
import type { CertificateInfo, PkiIdentity } from './certificate-parser'

// ── Helpers ──────────────────────────────────────────────────────────

function makeCert(overrides: Partial<CertificateInfo> = {}): CertificateInfo {
  return {
    commonName: 'Test Cert',
    organization: null,
    organizationalUnit: null,
    country: null,
    serialNumber: '',
    subjectSerialNumber: null,
    issuerCommonName: 'Unknown',
    issuerOrganization: null,
    validFrom: null,
    validTo: null,
    isCa: false,
    policyOids: [],
    email: null,
    subjectAltNames: [],
    keyUsage: [],
    extKeyUsage: [],
    role: 'end-entity',
    profesion: null,
    numeroColegiado: null,
    rawDerHex: 'aabb',
    ...overrides,
  }
}

function makePki(overrides: Partial<PkiIdentity> = {}): PkiIdentity {
  return {
    name: 'CR Firma Digital',
    fullName: 'Sistema Nacional de Certificación Digital',
    country: 'CR',
    rootAuthority: 'CA RAIZ NACIONAL - COSTA RICA',
    issuingAuthority: null,
    certificateType: null,
    detectedVia: 'oid',
    ...overrides,
  }
}

// ── CR Derivation ───────────────────────────────────────────────────

describe('derivePkiDids — CR (Costa Rica)', () => {
  it('derives did:pki:cr:sinpe:persona-fisica from SINPE PF chain', () => {
    const chain = [
      makeCert({
        commonName: 'JUAN PEREZ (FIRMA)',
        issuerCommonName: 'CA SINPE - PERSONA FISICA v2',
        role: 'end-entity',
      }),
      makeCert({
        commonName: 'CA SINPE - PERSONA FISICA v2',
        issuerCommonName: 'CA POLITICA PERSONA FISICA - COSTA RICA v2',
        role: 'intermediate',
        isCa: true,
      }),
      makeCert({
        commonName: 'CA POLITICA PERSONA FISICA - COSTA RICA v2',
        issuerCommonName: 'CA RAIZ NACIONAL - COSTA RICA v2',
        role: 'intermediate',
        isCa: true,
      }),
      makeCert({
        commonName: 'CA RAIZ NACIONAL - COSTA RICA v2',
        issuerCommonName: 'CA RAIZ NACIONAL - COSTA RICA v2',
        role: 'root',
        isCa: true,
      }),
    ]
    const pki = makePki({ certificateType: 'Persona Física' })

    const result = derivePkiDids(chain, pki)

    expect(result.issuingCaDid).toBe('did:pki:cr:sinpe:persona-fisica')
    expect(result.derivedVia).toBe('ca-name-mapping')
    expect(result.chainDids).toContain('did:pki:cr:sinpe:persona-fisica')
    expect(result.chainDids).toContain('did:pki:cr:politica:persona-fisica')
    expect(result.chainDids).toContain('did:pki:cr:raiz-nacional')
  })

  it('derives did:pki:cr:sinpe:persona-juridica from SINPE PJ chain', () => {
    const chain = [
      makeCert({
        commonName: 'EMPRESA S.A.',
        issuerCommonName: 'CA SINPE - PERSONA JURIDICA v2',
        role: 'end-entity',
      }),
      makeCert({
        commonName: 'CA SINPE - PERSONA JURIDICA v2',
        issuerCommonName: 'CA POLITICA PERSONA JURIDICA - COSTA RICA v2',
        role: 'intermediate',
        isCa: true,
      }),
    ]
    const pki = makePki({ certificateType: 'Persona Jurídica' })

    const result = derivePkiDids(chain, pki)
    expect(result.issuingCaDid).toBe('did:pki:cr:sinpe:persona-juridica')
  })

  it('derives did:pki:cr:politica:persona-fisica from POLITICA PF cert', () => {
    const chain = [
      makeCert({
        commonName: 'Test',
        issuerCommonName: 'CA POLITICA PERSONA FISICA - COSTA RICA v2',
        role: 'end-entity',
      }),
      makeCert({
        commonName: 'CA POLITICA PERSONA FISICA - COSTA RICA v2',
        issuerCommonName: 'CA RAIZ NACIONAL - COSTA RICA v2',
        role: 'intermediate',
        isCa: true,
      }),
    ]
    const pki = makePki({ certificateType: 'Persona Física' })

    const result = derivePkiDids(chain, pki)
    expect(result.issuingCaDid).toBe('did:pki:cr:politica:persona-fisica')
  })

  it('derives did:pki:cr:raiz-nacional from root cert', () => {
    const chain = [
      makeCert({
        commonName: 'Test',
        issuerCommonName: 'CA RAIZ NACIONAL - COSTA RICA v2',
        role: 'end-entity',
      }),
      makeCert({
        commonName: 'CA RAIZ NACIONAL - COSTA RICA v2',
        issuerCommonName: 'CA RAIZ NACIONAL - COSTA RICA v2',
        role: 'root',
        isCa: true,
      }),
    ]
    const pki = makePki()

    const result = derivePkiDids(chain, pki)
    expect(result.issuingCaDid).toBe('did:pki:cr:raiz-nacional')
  })
})

// ── Edge Cases ──────────────────────────────────────────────────────

describe('derivePkiDids — edge cases', () => {
  it('returns null when no PKI identified', () => {
    const chain = [makeCert()]
    const result = derivePkiDids(chain, null)
    expect(result.issuingCaDid).toBeNull()
    expect(result.derivedVia).toBeNull()
  })

  it('returns null when chain is empty', () => {
    const pki = makePki()
    const result = derivePkiDids([], pki)
    expect(result.issuingCaDid).toBeNull()
  })

  it('returns null when signer has no matching issuer in chain', () => {
    const chain = [
      makeCert({
        commonName: 'Signer',
        issuerCommonName: 'Missing CA',
        role: 'end-entity',
      }),
    ]
    const pki = makePki()

    const result = derivePkiDids(chain, pki)
    expect(result.issuingCaDid).toBeNull()
  })

  it('uses heuristic derivation for unsupported country', () => {
    const chain = [
      makeCert({
        commonName: 'Signer',
        issuerCommonName: 'AC SERPRO SSF',
        role: 'end-entity',
      }),
      makeCert({
        commonName: 'AC SERPRO SSF',
        issuerCommonName: 'AC RAIZ BRASILEIRA V5',
        role: 'intermediate',
        isCa: true,
      }),
    ]
    const pki = makePki({
      country: 'BR',
      issuingAuthority: 'AC SERPRO SSF',
      certificateType: 'e-CPF A3 (Pessoa Física)',
    })

    const result = derivePkiDids(chain, pki)
    // Should attempt heuristic derivation
    expect(result.derivedVia).toBe('heuristic')
    expect(result.issuingCaDid).toMatch(/^did:pki:br:/)
  })

  it('handles accented characters in cert type', () => {
    const chain = [
      makeCert({
        commonName: 'Test',
        issuerCommonName: 'CA SINPE - PERSONA FÍSICA v2',
        role: 'end-entity',
      }),
      makeCert({
        commonName: 'CA SINPE - PERSONA FÍSICA v2',
        issuerCommonName: 'Root',
        role: 'intermediate',
        isCa: true,
      }),
    ]
    const pki = makePki({ certificateType: 'Persona Física' })

    const result = derivePkiDids(chain, pki)
    expect(result.issuingCaDid).toBe('did:pki:cr:sinpe:persona-fisica')
  })
})

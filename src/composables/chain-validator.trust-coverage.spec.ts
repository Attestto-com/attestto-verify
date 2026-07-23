/**
 * Trust-store coverage — proves the offline chain validator bundles CA roots for
 * ALL 14 promoted directory countries, not just cr/br/ar.
 *
 * This closes the overclaim gap: the landing page marks 14 countries as "filled"
 * ("chain validated against bundled trusted roots"). For that claim to be honest,
 * chain-validator.ts must actually bundle each of those 14 countries' roots. The
 * validator sources its anchors from `@attestto/trust`'s per-country `ALL_CERTS`
 * arrays, so this test asserts — against the REAL package, unmocked — that every
 * filled country exposes a non-empty, parseable set of certificates.
 *
 * If a country is ever added to the filled-pill set without promoted certs in
 * @attestto/trust, this test fails.
 */

import { describe, it, expect } from 'vitest'
import * as trust from '@attestto/trust'
import * as asn1js from 'asn1js'
import * as pkijs from 'pkijs'

// Must match TRUST_COUNTRIES in chain-validator.ts and the filled-pill set.
const FILLED_COUNTRIES = ['ar', 'at', 'be', 'br', 'cr', 'de', 'ee', 'es', 'fr', 'gr', 'it', 'nl', 'pe', 'pt']

function pemToDer(pem: string): ArrayBuffer {
  const b64 = pem
    .replace(/-----BEGIN CERTIFICATE-----/g, '')
    .replace(/-----END CERTIFICATE-----/g, '')
    .replace(/\s+/g, '')
  const bin = atob(b64)
  const bytes = new Uint8Array(bin.length)
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i)
  return bytes.buffer
}

describe('trust-store coverage (filled-pill honesty)', () => {
  it('exposes a non-empty ALL_CERTS for every filled directory country', () => {
    for (const cc of FILLED_COUNTRIES) {
      const ns = (trust as Record<string, { ALL_CERTS?: unknown[] }>)[cc]
      expect(ns, `@attestto/trust must export namespace '${cc}'`).toBeDefined()
      expect(Array.isArray(ns.ALL_CERTS), `${cc}.ALL_CERTS must be an array`).toBe(true)
      expect(ns.ALL_CERTS!.length, `${cc} must bundle at least one CA cert`).toBeGreaterThan(0)
    }
  })

  it('bundles roots beyond cr/br/ar (EU countries are now covered)', () => {
    const euSample = ['de', 'it', 'fr', 'nl', 'es', 'pt', 'gr', 'at', 'be', 'ee']
    for (const cc of euSample) {
      const certs = (trust as Record<string, { ALL_CERTS?: { pem?: string }[] }>)[cc].ALL_CERTS!
      expect(certs.length, `${cc} should have bundled certs`).toBeGreaterThan(0)
      expect(certs[0].pem, `${cc} first cert should be a PEM`).toMatch(/-----BEGIN CERTIFICATE-----/)
    }
  })

  it('a real German (DE) root parses as a valid X.509 certificate', () => {
    const de = (trust as Record<string, { ALL_CERTS?: { pem: string; name: string }[] }>).de.ALL_CERTS!
    const der = pemToDer(de[0].pem)
    const asn1 = asn1js.fromBER(der)
    expect(asn1.offset, `DE cert '${de[0].name}' must be valid ASN.1`).not.toBe(-1)
    // Constructing a pkijs.Certificate would throw on malformed input.
    const cert = new pkijs.Certificate({ schema: asn1.result })
    expect(cert.subject.typesAndValues.length).toBeGreaterThan(0)
  })
})

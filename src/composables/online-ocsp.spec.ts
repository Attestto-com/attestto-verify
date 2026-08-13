/**
 * Tests for the OPT-IN online OCSP check (online-ocsp.ts).
 *
 * These cover the guard + failure contract that the product depends on:
 *   - with no responder URL, it never touches the network and reports unreachable
 *   - a fetch rejection (the real-world CORS case) is caught and reported as
 *     'unreachable', never thrown, never a false 'good'
 * The happy path needs a live responder + real certs and is not unit-tested here.
 */

import { describe, it, expect, afterEach, vi } from 'vitest'
import { checkOcspOnline } from './online-ocsp.js'

const origFetch = globalThis.fetch

afterEach(() => {
  globalThis.fetch = origFetch
  vi.restoreAllMocks()
})

describe('checkOcspOnline — opt-in online revocation', () => {
  it('returns unreachable (never throws) when no responder URL is given', async () => {
    // No network call should happen; a bad URL short-circuits before crypto.
    const spy = vi.fn()
    globalThis.fetch = spy as unknown as typeof fetch

    const res = await checkOcspOnline('aabb', 'ccdd', '', 'en')

    expect(res.status).toBe('unreachable')
    expect(res.revokedAt).toBeNull()
    expect(spy).not.toHaveBeenCalled()
    expect(typeof res.checkedAt).toBe('string')
  })

  it('rejects non-http(s) responder URLs without a network call', async () => {
    const spy = vi.fn()
    globalThis.fetch = spy as unknown as typeof fetch

    const res = await checkOcspOnline('aabb', 'ccdd', 'ftp://example/ocsp', 'es')

    expect(res.status).toBe('unreachable')
    expect(spy).not.toHaveBeenCalled()
    // Spanish message requested — must not contain an em-dash.
    expect(res.message).not.toContain('—')
  })

  it('never claims success and never throws when the fetch rejects (CORS)', async () => {
    // A rejected fetch is the exact real-world CORS failure. We must degrade to
    // 'unreachable' or 'unknown' (request could not complete) — never 'good'.
    globalThis.fetch = vi
      .fn()
      .mockRejectedValue(new TypeError('Failed to fetch')) as unknown as typeof fetch

    // Certs are junk, so this may fail at request-build ('unknown') or at fetch
    // ('unreachable'). Either way it must be a safe, non-throwing, non-good result.
    const res = await checkOcspOnline('aabb', 'ccdd', 'https://ocsp.example/', 'en')

    expect(['unreachable', 'unknown']).toContain(res.status)
    expect(res.status).not.toBe('good')
    expect(res.status).not.toBe('revoked')
  })
})

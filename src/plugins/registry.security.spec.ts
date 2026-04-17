/**
 * Security tests for plugin registry (ATT-312).
 *
 * Three attack vectors:
 *   1. Plugin level escalation — plugin sets 'trusted'/'qualified' without crypto verification
 *   2. Trust plugin crypto floor — checkTrust() caps trust level when chain not verified
 *   3. Plugin overwrite protection — frozen plugins can't be silently replaced
 */

import { describe, it, expect, beforeEach, vi } from 'vitest'
import {
  attesttoPlugins,
  _resetPluginRegistry,
  type TrustPlugin,
  type VerifierPlugin,
} from './registry'
import { gatePluginLevel } from '../composables/pdf-verifier'
import type { PdfSignatureInfo } from '../composables/pdf-verifier'

beforeEach(() => {
  _resetPluginRegistry()
})

// ── Flaw 1: Plugin Level Escalation Gate ──────────────────────────

describe('gatePluginLevel (ATT-312 Flaw 1)', () => {
  const baseSig: PdfSignatureInfo = {
    name: 'Test Signer',
    reason: null,
    location: null,
    contactInfo: null,
    signDate: null,
    level: 'parsed',
    documentIntegrityVerified: null,
    integrityError: null,
    did: null,
    lei: null,
    organization: null,
    subFilter: null,
    certChain: null,
    pkcs7Hex: null,
  }

  it('downgrades "trusted" to "parsed" when chain is not cryptographically verified', () => {
    const sig = {
      ...baseSig,
      level: 'trusted' as const,
      certChain: { cryptographicallyVerified: false } as PdfSignatureInfo['certChain'],
    }
    const gated = gatePluginLevel(sig)
    expect(gated.level).toBe('parsed')
  })

  it('downgrades "qualified" to "parsed" when chain is not cryptographically verified', () => {
    const sig = {
      ...baseSig,
      level: 'qualified' as const,
      certChain: { cryptographicallyVerified: false } as PdfSignatureInfo['certChain'],
    }
    const gated = gatePluginLevel(sig)
    expect(gated.level).toBe('parsed')
  })

  it('downgrades "trusted" to "parsed" when certChain is null', () => {
    const sig = { ...baseSig, level: 'trusted' as const, certChain: null }
    const gated = gatePluginLevel(sig)
    expect(gated.level).toBe('parsed')
  })

  it('allows "trusted" when chain IS cryptographically verified', () => {
    const sig = {
      ...baseSig,
      level: 'trusted' as const,
      certChain: { cryptographicallyVerified: true } as PdfSignatureInfo['certChain'],
    }
    const gated = gatePluginLevel(sig)
    expect(gated.level).toBe('trusted')
  })

  it('allows "qualified" when chain IS cryptographically verified', () => {
    const sig = {
      ...baseSig,
      level: 'qualified' as const,
      certChain: { cryptographicallyVerified: true } as PdfSignatureInfo['certChain'],
    }
    const gated = gatePluginLevel(sig)
    expect(gated.level).toBe('qualified')
  })

  it('does not touch levels below trusted (parsed, verified, tampered, unknown)', () => {
    for (const level of ['parsed', 'verified', 'tampered', 'unknown', 'detected'] as const) {
      const sig = { ...baseSig, level }
      const gated = gatePluginLevel(sig)
      expect(gated.level).toBe(level)
    }
  })
})

// ── Flaw 2: Trust Plugin Crypto Floor ─────────────────────────────

describe('checkTrust crypto floor (ATT-312 Flaw 2)', () => {
  it('caps "qualified" to "unknown" when cryptographicallyVerified is false', async () => {
    const maliciousPlugin: TrustPlugin = {
      name: 'fake-tsl',
      label: 'Fake TSL',
      type: 'trust',
      isTrusted: async () => ({ trusted: true, trustLevel: 'qualified', trustSource: 'fake' }),
    }
    attesttoPlugins.register(maliciousPlugin)

    const result = await attesttoPlugins.checkTrust([], false)
    expect(result.trustLevel).not.toBe('qualified')
  })

  it('caps "recognized" to "unknown" when cryptographicallyVerified is false', async () => {
    const plugin: TrustPlugin = {
      name: 'test-trust',
      label: 'Test',
      type: 'trust',
      isTrusted: async () => ({ trusted: true, trustLevel: 'recognized' }),
    }
    attesttoPlugins.register(plugin)

    const result = await attesttoPlugins.checkTrust([], false)
    expect(result.trustLevel).not.toBe('recognized')
  })

  it('allows "qualified" when cryptographicallyVerified is true', async () => {
    const plugin: TrustPlugin = {
      name: 'real-tsl',
      label: 'EU TSL',
      type: 'trust',
      isTrusted: async () => ({ trusted: true, trustLevel: 'qualified', trustSource: 'EU TSL' }),
    }
    attesttoPlugins.register(plugin)

    const result = await attesttoPlugins.checkTrust([], true)
    expect(result.trusted).toBe(true)
    expect(result.trustLevel).toBe('qualified')
  })

  it('allows "self-signed" regardless of crypto verification', async () => {
    const plugin: TrustPlugin = {
      name: 'self-check',
      label: 'Self Check',
      type: 'trust',
      isTrusted: async () => ({ trusted: true, trustLevel: 'self-signed' }),
    }
    attesttoPlugins.register(plugin)

    const result = await attesttoPlugins.checkTrust([], false)
    expect(result.trusted).toBe(true)
    expect(result.trustLevel).toBe('self-signed')
  })
})

// ── Flaw 3: Plugin Overwrite Protection ───────────────────────────

describe('plugin overwrite protection (ATT-312 Flaw 3)', () => {
  it('rejects overwrite of a frozen plugin', () => {
    const original: VerifierPlugin = {
      name: 'did-verifier',
      label: 'DID Verifier',
      type: 'verifier',
      check: async () => ({ valid: true }),
    }
    const malicious: VerifierPlugin = {
      name: 'did-verifier',
      label: 'Fake',
      type: 'verifier',
      check: async () => ({ valid: true, message: 'hacked' }),
    }

    attesttoPlugins.register(original)
    attesttoPlugins.register(malicious) // should be rejected

    const registered = attesttoPlugins.get('did-verifier')
    expect(registered?.label).toBe('DID Verifier') // original preserved
  })

  it('allows overwrite with explicit allowOverwrite option', () => {
    const original: VerifierPlugin = {
      name: 'test-plugin',
      label: 'Original',
      type: 'verifier',
      check: async () => ({ valid: true }),
    }
    const replacement: VerifierPlugin = {
      name: 'test-plugin',
      label: 'Replacement',
      type: 'verifier',
      check: async () => ({ valid: true }),
    }

    attesttoPlugins.register(original)
    attesttoPlugins.register(replacement, { allowOverwrite: true })

    const registered = attesttoPlugins.get('test-plugin')
    expect(registered?.label).toBe('Replacement')
  })

  it('allows re-registration after unregister', () => {
    const plugin: VerifierPlugin = {
      name: 'temp-plugin',
      label: 'Temp',
      type: 'verifier',
      check: async () => ({ valid: true }),
    }
    const updated: VerifierPlugin = {
      name: 'temp-plugin',
      label: 'Updated',
      type: 'verifier',
      check: async () => ({ valid: false }),
    }

    attesttoPlugins.register(plugin)
    attesttoPlugins.unregister('temp-plugin')
    attesttoPlugins.register(updated)

    const registered = attesttoPlugins.get('temp-plugin')
    expect(registered?.label).toBe('Updated')
  })
})

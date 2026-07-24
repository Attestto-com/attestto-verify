/**
 * Regression guard — the verify FE trust path must NOT bundle national PKI certs.
 *
 * ARCHITECTURE (non-negotiable, per repo owner): trust anchors are resolved on
 * demand via did:pki at resolver.attestto.com. The resolver returns key
 * FINGERPRINTS; the validator matches the PDF's own embedded intermediate/CA
 * certs against those fingerprints and uses the matched cert as the pkijs trust
 * anchor. The FE must never `import ... from '@attestto/trust'` in the chain
 * validation path — doing so bundles every promoted country's `ALL_CERTS` into
 * the worker (the 2026 regression that shipped ~1 MB gz of PEM certs to every
 * visitor).
 *
 * Two things are pinned here, both as cheap source-level assertions (no heavy
 * component mount / crypto):
 *
 *  1. `chain-validator.ts` does not import `@attestto/trust` (nor reference
 *     bundled-anchor machinery), and the whole non-test `src/` tree is free of
 *     that import.
 *
 *  2. `attestto-verify.ts` performs no SURPRISE auto-fetch by default. Revocation
 *     is opt-in: nothing runs unless the user acts (per-card button, the
 *     document-level "check all" control) OR has explicitly enabled the
 *     remembered `attestto:autoRevocation` preference (default OFF). The
 *     preference-gated auto path IS allowed; what is banned is any UNconditional
 *     auto-run on verify/load. The online-revocation model still starts empty.
 */

import { describe, it, expect } from 'vitest'
import { readFileSync, readdirSync, statSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { dirname, join } from 'node:path'

const here = dirname(fileURLToPath(import.meta.url))
const srcRoot = join(here, '..') // src/

function read(rel: string): string {
  return readFileSync(join(srcRoot, rel), 'utf8')
}

/** Recursively collect every non-test .ts file under src/. */
function allSourceTsFiles(dir: string, acc: string[] = []): string[] {
  for (const entry of readdirSync(dir)) {
    const full = join(dir, entry)
    const st = statSync(full)
    if (st.isDirectory()) {
      allSourceTsFiles(full, acc)
    } else if (
      entry.endsWith('.ts') &&
      !entry.endsWith('.spec.ts') &&
      !entry.endsWith('.test.ts') &&
      !entry.endsWith('.d.ts')
    ) {
      acc.push(full)
    }
  }
  return acc
}

describe('no bundled national PKI certs (resolver-only trust)', () => {
  it('chain-validator.ts does not import @attestto/trust', () => {
    const src = read('composables/chain-validator.ts')
    expect(src).not.toMatch(/from\s+['"]@attestto\/trust['"]/)
    expect(src).not.toMatch(/import\s+.*['"]@attestto\/trust['"]/)
  })

  it('chain-validator.ts has no bundled-anchor machinery', () => {
    const src = read('composables/chain-validator.ts')
    // These symbols only existed to load/iterate bundled ALL_CERTS anchors.
    expect(src).not.toContain('loadTrustAnchors')
    expect(src).not.toContain('TRUST_COUNTRIES')
    expect(src).not.toContain('ALL_CERTS')
  })

  it('no non-test file in src/ imports @attestto/trust', () => {
    const offenders = allSourceTsFiles(srcRoot).filter((f) =>
      /from\s+['"]@attestto\/trust['"]/.test(readFileSync(f, 'utf8')),
    )
    expect(
      offenders,
      `@attestto/trust must not be imported in the FE trust path. Offending files:\n${offenders.join('\n')}`,
    ).toEqual([])
  })
})

describe('revocation is opt-in — no SURPRISE auto-fetch by default', () => {
  it('the online-revocation model starts empty (user action only)', () => {
    const src = read('components/attestto-verify.ts')
    // The per-signature online-revocation state is an empty Map by default and
    // is only ever written from the card's request-online-revocation handler or
    // the document-level batch control.
    expect(src).toMatch(/_onlineRev\b/)
    expect(src).toMatch(/request-online-revocation/)
    expect(src).toMatch(/new Map\(\)/)
  })

  it('any auto-run on verify is gated behind the persisted preference', () => {
    const src = read('components/attestto-verify.ts')
    // The revocation batch may be auto-triggered, but ONLY inside a guard on the
    // remembered preference — never unconditionally. We assert every
    // fire-and-forget `void this.runAllCrRevocation()` is preceded by an
    // `_autoRevocation` check, so removing the guard would fail this test.
    const autoCalls = [...src.matchAll(/void\s+this\.runAllCrRevocation\(\)/g)]
    expect(autoCalls.length).toBeGreaterThan(0)
    for (const m of autoCalls) {
      // The lines just before each auto-call must sit inside a guard on the
      // preference — either the `_autoRevocation` field itself, or the `on`
      // param that carries the same just-enabled preference in the toggle.
      const before = src.slice(Math.max(0, m.index! - 160), m.index!)
      expect(
        before,
        'auto-revocation call must be guarded by the auto-revocation preference',
      ).toMatch(/_autoRevocation|if \(on /)
    }
  })

  it('the auto-revocation preference defaults OFF (opt-in, remembered)', () => {
    const src = read('components/attestto-verify.ts')
    // Persisted key + a default-false field: a fresh visitor with no stored
    // preference gets no auto-fetch.
    expect(src).toContain("'attestto:autoRevocation'")
    expect(src).toMatch(/_autoRevocation\s*=\s*false/)
    // The stored value is only "on" when explicitly set to '1'.
    expect(src).toMatch(/getItem\(AUTO_REVOCATION_KEY\)\s*===\s*'1'/)
  })
})

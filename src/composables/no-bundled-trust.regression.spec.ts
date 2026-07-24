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
 *  2. `attestto-verify.ts` does not auto-run revocation on verify — the online
 *     revocation check is strictly opt-in (user clicks "Check revocation
 *     online"); the model starts empty.
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

describe('revocation is opt-in, never automatic on verify', () => {
  it('attestto-verify.ts has no autoCheckCrRevocation / auto-revocation call', () => {
    const src = read('components/attestto-verify.ts')
    // The removed anti-pattern: auto-fetching the CR CRL on every verify.
    expect(src).not.toContain('autoCheckCrRevocation')
    expect(src).not.toMatch(/void\s+this\.autoCheck/)
  })

  it('the online-revocation model starts empty (user action only)', () => {
    const src = read('components/attestto-verify.ts')
    // The per-signature online-revocation state is an empty Map by default and
    // is only ever written from the card's request-online-revocation handler.
    expect(src).toMatch(/_onlineRev\b/)
    expect(src).toMatch(/request-online-revocation/)
  })
})

#!/usr/bin/env node
/**
 * CI bundle-size tripwire.
 *
 * The verify FE must NOT bundle national PKI certs — trust anchors are resolved
 * on demand via did:pki at resolver.attestto.com. A 2026 regression
 * (commit 7b20945) re-introduced `import * as trust from '@attestto/trust'` into
 * chain-validator.ts, bundling every promoted country's `ALL_CERTS` (hundreds of
 * PEM certs) into the worker: the built `verify-worker-*.js` ballooned to
 * ~2.87 MB raw / ~1.18 MB gzipped.
 *
 * This script fails the build if the gzipped verify worker exceeds a sane budget
 * comfortably above the resolver-only size (~pkijs+asn1js only) but far below the
 * re-bundling regression. It is the tripwire that catches re-bundling.
 *
 * Usage: node scripts/check-bundle-size.mjs [distDir ...]
 *   Defaults to scanning both dist/ and dist-pages/ (whichever exist).
 */

import { readdirSync, readFileSync, existsSync, statSync } from 'node:fs'
import { join } from 'node:path'
import { gzipSync } from 'node:zlib'

// Gzipped budget for the verify worker. Resolver-only + pkijs/asn1js sits well
// under this; the ~1.18 MB gz re-bundling regression blows past it.
const MAX_WORKER_GZIP_BYTES = 250 * 1024 // 250 KB

const distDirs = process.argv.slice(2)
const targets = distDirs.length ? distDirs : ['dist', 'dist-pages']

function findWorkerBundles(distDir) {
  const assets = join(distDir, 'assets')
  if (!existsSync(assets)) return []
  return readdirSync(assets)
    .filter((f) => /^verify-worker-.*\.js$/.test(f))
    .map((f) => join(assets, f))
}

let checked = 0
let failed = false

for (const dir of targets) {
  if (!existsSync(dir)) continue
  for (const bundle of findWorkerBundles(dir)) {
    checked++
    const raw = readFileSync(bundle)
    const gz = gzipSync(raw).length
    const rawKb = (raw.length / 1024).toFixed(1)
    const gzKb = (gz / 1024).toFixed(1)
    const budgetKb = (MAX_WORKER_GZIP_BYTES / 1024).toFixed(0)
    if (gz > MAX_WORKER_GZIP_BYTES) {
      failed = true
      console.error(
        `FAIL  ${bundle}\n      gzipped ${gzKb} KB (raw ${rawKb} KB) exceeds budget ${budgetKb} KB.\n` +
          `      This almost always means national PKI certs were re-bundled into the worker\n` +
          `      (e.g. an 'import ... from "@attestto/trust"' crept back into the trust path).\n` +
          `      Trust must be resolver-only; see src/composables/chain-validator.ts.`,
      )
    } else {
      console.log(`OK    ${bundle}  gzipped ${gzKb} KB (raw ${rawKb} KB) < ${budgetKb} KB budget`)
    }
  }
}

if (checked === 0) {
  console.error(
    'ERROR: no verify-worker-*.js bundle found in ' +
      targets.filter((d) => existsSync(d)).join(', ') +
      '. Run the build first (pnpm build / build:pages).',
  )
  process.exit(2)
}

process.exit(failed ? 1 : 0)

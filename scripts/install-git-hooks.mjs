#!/usr/bin/env node
/**
 * Point git at the repo's tracked hooks directory.
 *
 * Not husky: this is one built-in git command (`core.hooksPath`), and a package
 * whose entire pitch is client-side crypto has a reason to keep its install-time
 * dependency count at zero.
 *
 * ## Every failure path exits 0, deliberately
 *
 * This runs from `prepare`, which also runs for anyone doing
 * `npm install github:Attestto-com/attestto-verify`. A hook that failed to
 * install is a local nuisance; a `prepare` that exits non-zero is a BROKEN
 * INSTALL for every downstream consumer. Those are not the same severity, so
 * this never fails the install — it just says what it did.
 */
import { execFileSync } from 'node:child_process'
import { existsSync } from 'node:fs'
import { dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..')

// CI checks out fresh every run and pushes nothing; installing hooks there is
// pure noise, and GitHub Actions sets CI=true.
if (process.env.CI) {
  process.exit(0)
}

try {
  // A consumer installing us as a dependency has no .git of ours. Also covers
  // tarball installs and vendored copies.
  execFileSync('git', ['rev-parse', '--git-dir'], { cwd: ROOT, stdio: 'ignore' })
} catch {
  process.exit(0)
}

if (!existsSync(resolve(ROOT, '.githooks/pre-push'))) {
  process.exit(0)
}

try {
  execFileSync('git', ['config', 'core.hooksPath', '.githooks'], {
    cwd: ROOT,
    stdio: 'ignore',
  })
  console.log('git hooks installed: core.hooksPath -> .githooks (pre-push runs the coverage ratchet)')
} catch (err) {
  console.warn(
    `could not set core.hooksPath (${err instanceof Error ? err.message : String(err)}); ` +
      'the pre-push coverage gate will not run locally. CI still enforces it.',
  )
}

process.exit(0)

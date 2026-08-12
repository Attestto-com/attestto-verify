#!/usr/bin/env node
/**
 * Coverage ratchet — coverage may go up, never down.
 *
 * ## Why not `vitest --coverage.thresholds.autoUpdate`
 *
 * vitest can enforce thresholds and rewrite them upward itself. It was
 * rejected here for three reasons, each of which makes it strictly weaker than
 * a tracked baseline file:
 *
 *  1. It rewrites `vite.config.ts` as a side effect of a PASSING run. In a
 *     pre-push hook that edit lands AFTER the commit being pushed, so the
 *     raised bar is never actually pushed; in CI it dirties the runner.
 *  2. Four bare numbers inline in a config file cannot be mechanically diffed
 *     against the base branch, so nothing stops a PR from simply lowering them
 *     in the same commit that drops coverage. That is the whole threat model.
 *  3. It is skipped entirely when not all tests ran, which is silent.
 *
 * ## The three rules
 *
 *  FLOOR    every metric >= the committed baseline.        (pre-push AND CI)
 *  NO-DROP  the committed baseline is itself >= the        (CI only — needs
 *           baseline at the merge-base with the base         the base branch)
 *           branch, so a PR cannot lower the bar.
 *  DRIFT    if coverage rose more than DRIFT_PP above the  (both)
 *           baseline, the baseline is stale and must be
 *           updated, otherwise the bar sticks forever.
 *
 * ## Usage
 *
 *   node scripts/coverage-ratchet.mjs            # check (assumes coverage/ is fresh)
 *   node scripts/coverage-ratchet.mjs --update   # rewrite the baseline
 *
 * Reads `coverage/coverage-summary.json`, so a coverage run must precede it.
 * `pnpm coverage:check` does both.
 */
import { execFileSync } from 'node:child_process'
import { existsSync, readFileSync, writeFileSync } from 'node:fs'
import { dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const SUMMARY = resolve(ROOT, 'coverage/coverage-summary.json')
const BASELINE = resolve(ROOT, 'coverage-baseline.json')
const METRICS = ['statements', 'branches', 'functions', 'lines']

/** How far above the baseline coverage may drift before the baseline is stale. */
const DRIFT_PP = 2.0

const update = process.argv.includes('--update')

if (!existsSync(SUMMARY)) {
  console.error(
    'coverage-ratchet: coverage/coverage-summary.json not found.\n' +
      "Run `pnpm coverage` first, or use `pnpm coverage:check` which does both.",
  )
  process.exit(1)
}

const summary = JSON.parse(readFileSync(SUMMARY, 'utf-8')).total
const current = Object.fromEntries(METRICS.map((m) => [m, round(summary[m].pct)]))

// The Node major version is recorded because V8 attributes statements and
// branches slightly differently across major versions, so a baseline is only
// strictly comparable on the engine that produced it. Generate it on the
// version pinned in .nvmrc (`nvm use`), which is what CI runs.
//
// This USED to downgrade a FLOOR failure to a warning whenever the running
// major differed from the baseline's, to avoid an unreproducible local red.
// That was a mistake, and CI caught it on the very first run: the baseline had
// been captured on Node 25, CI runs the Node 22 from .nvmrc, so every FLOOR
// breach silently became a warning and gate-self-test correctly reported that
// `coverage:check` PASSED with a deliberate violation seeded in it.
//
// A gate that cannot fail is worse than a gate that occasionally fails
// confusingly. A mismatch now warns and STILL enforces.
const nodeMajor = Number(process.versions.node.split('.')[0])

if (update) {
  writeBaseline(current, nodeMajor)
  console.log(`coverage-ratchet: baseline updated (node ${nodeMajor})`)
  for (const m of METRICS) console.log(`  ${m.padEnd(11)} ${current[m].toFixed(2)}%`)
  process.exit(0)
}

if (!existsSync(BASELINE)) {
  // Deliberately not a failure: this is the bootstrap path. Landing the ratchet
  // and the baseline in one commit means the baseline comes from whichever
  // machine happened to run it; letting CI emit these numbers first is safer.
  console.log(
    'coverage-ratchet: no coverage-baseline.json yet — nothing to enforce.\n' +
      'Current coverage:',
  )
  for (const m of METRICS) console.log(`  ${m.padEnd(11)} ${current[m].toFixed(2)}%`)
  console.log('\nCommit these as the baseline with: pnpm coverage:update')
  process.exit(0)
}

const baselineFile = JSON.parse(readFileSync(BASELINE, 'utf-8'))
const baseline = baselineFile.metrics ?? baselineFile
const baselineNode = baselineFile.nodeMajor ?? null
const engineMismatch = baselineNode !== null && baselineNode !== nodeMajor

const failures = []
const warnings = []

if (engineMismatch) {
  warnings.push(
    `the baseline was captured on Node ${baselineNode} and this is Node ${nodeMajor}. ` +
      'V8 attributes coverage slightly differently across majors, so a small ' +
      'unexplained delta may be the engine rather than your change. This is ' +
      'still enforced: run `nvm use` to match .nvmrc before trusting a failure.',
  )
}

// ── FLOOR ───────────────────────────────────────────────────────────
for (const m of METRICS) {
  const now = current[m]
  const floor = round(baseline[m] ?? 0)
  if (now + 1e-9 >= floor) continue
  failures.push(
    `${m} dropped ${(floor - now).toFixed(2)}pp: ${now.toFixed(2)}% < baseline ${floor.toFixed(2)}%`,
  )
}

// ── NO-DROP ─────────────────────────────────────────────────────────
// Compare the committed baseline against the same file at the MERGE-BASE, not
// at the tip of the base branch: a branch cut before an unrelated rise must not
// be failed for a rise it does not contain.
const baseRef = process.env.COVERAGE_BASE_REF || ''
if (baseRef) {
  try {
    const mergeBase = git(['merge-base', 'HEAD', baseRef])
    const previous = git(['show', `${mergeBase}:coverage-baseline.json`])
    const prevFile = JSON.parse(previous)
    const prev = prevFile.metrics ?? prevFile
    for (const m of METRICS) {
      const nowFloor = round(baseline[m] ?? 0)
      const wasFloor = round(prev[m] ?? 0)
      if (nowFloor + 1e-9 < wasFloor) {
        failures.push(
          `NO-DROP: the committed baseline for ${m} was LOWERED from ` +
            `${wasFloor.toFixed(2)}% to ${nowFloor.toFixed(2)}% relative to ${baseRef}. ` +
            'Lowering the bar is the one thing this gate exists to prevent.',
        )
      }
    }
  } catch (err) {
    // A missing baseline at the merge-base is the normal case on the commit
    // that introduces this file. Anything else is worth surfacing.
    const message = err instanceof Error ? err.message : String(err)
    if (/exists on disk, but not in|does not exist|unknown revision|Not a valid object/i.test(message)) {
      console.log(`coverage-ratchet: no baseline at the merge-base with ${baseRef} — NO-DROP skipped (first run).`)
    } else {
      warnings.push(`NO-DROP could not run against ${baseRef}: ${message}`)
    }
  }
} else {
  console.log('coverage-ratchet: COVERAGE_BASE_REF unset — NO-DROP skipped (it needs the base branch).')
}

// ── DRIFT ───────────────────────────────────────────────────────────
const risen = METRICS.filter((m) => current[m] - round(baseline[m] ?? 0) > DRIFT_PP)
if (risen.length > 0) {
  const detail = risen
    .map((m) => `${m} ${round(baseline[m]).toFixed(2)}% -> ${current[m].toFixed(2)}%`)
    .join(', ')
  failures.push(
    `coverage rose more than ${DRIFT_PP}pp above the baseline (${detail}), so the ` +
      'baseline is stale and the bar would stick at the old value. ' +
      'Run `pnpm coverage:update` and commit coverage-baseline.json.',
  )
}

// ── Report ──────────────────────────────────────────────────────────
console.log('coverage-ratchet:')
for (const m of METRICS) {
  const now = current[m]
  const floor = round(baseline[m] ?? 0)
  const delta = now - floor
  const sign = delta > 0 ? '+' : ''
  console.log(
    `  ${m.padEnd(11)} ${now.toFixed(2)}%  (baseline ${floor.toFixed(2)}%, ${sign}${delta.toFixed(2)}pp)`,
  )
}

for (const w of warnings) console.warn(`\nwarning: ${w}`)

if (failures.length === 0) {
  console.log('\ncoverage-ratchet: OK')
  process.exit(0)
}

console.error(`\ncoverage-ratchet: ${failures.length} problem(s)\n`)
for (const f of failures) console.error(`  - ${f}`)
console.error(
  '\nAdd tests for what you changed. If the drop is genuinely correct ' +
    '(e.g. you deleted well-covered code), run `pnpm coverage:update` and say ' +
    'so in the commit message.\n',
)
process.exit(1)

function round(value) {
  return Math.round((Number(value) + Number.EPSILON) * 100) / 100
}

function writeBaseline(metrics, major) {
  const body = {
    // Written by scripts/coverage-ratchet.mjs --update. Do not hand-edit:
    // lowering these numbers is exactly what the NO-DROP rule rejects.
    generatedBy: 'scripts/coverage-ratchet.mjs',
    nodeMajor: major,
    metrics,
  }
  writeFileSync(BASELINE, `${JSON.stringify(body, null, 2)}\n`)
}

function git(args) {
  return execFileSync('git', args, { cwd: ROOT, encoding: 'utf-8' }).trim()
}

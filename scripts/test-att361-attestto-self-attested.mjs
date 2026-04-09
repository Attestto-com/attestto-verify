/**
 * Smoke test for ATT-361 — Attestto self-attested signature recognition.
 *
 * Loads the signed carta MICITT/MOPT, runs the new extractor, and
 * prints the result. This is the load-bearing manual check before the
 * carta ships: if this script does NOT report a verified Attestto sig,
 * verify.attestto.com is still going to display "UNSIGNED" and the
 * carta cannot go out.
 *
 *   node --experimental-strip-types scripts/test-att361-attestto-self-attested.mjs <path-to-pdf>
 *
 * Defaults to the carta path if no arg supplied.
 */

import { readFileSync, existsSync } from 'node:fs'
import { extractAttesttoSelfAttestedSignatures } from '../src/composables/attestto-self-attested.ts'

const DEFAULT = '/Users/eduardochongkan/Attestto/1-research/Licencia-Digital/carta-ejecutiva-micitt-mopt-v1 (firmado).pdf'
const path = process.argv[2] ?? DEFAULT

if (!existsSync(path)) {
  console.error(`No file at: ${path}`)
  process.exit(1)
}

const bytes = new Uint8Array(readFileSync(path))
console.log(`Verifying: ${path}`)
console.log(`Size: ${bytes.length} bytes`)
console.log()

const sigs = await extractAttesttoSelfAttestedSignatures(bytes)

if (sigs.length === 0) {
  console.log('✗ NO Attestto self-attested signatures found.')
  console.log('  This means either:')
  console.log('   - the PDF was not signed with attestto-desktop')
  console.log('   - /Keywords field was compressed (object streams enabled)')
  console.log('   - the keyword prefix changed')
  process.exit(1)
}

for (const sig of sigs) {
  console.log(`Signature: ${sig.name}`)
  console.log(`  level             : ${sig.level}`)
  console.log(`  did               : ${sig.did}`)
  console.log(`  signDate          : ${sig.signDate}`)
  console.log(`  reason            : ${sig.reason}`)
  console.log(`  contactInfo       : ${sig.contactInfo}`)
  console.log(`  organization      : ${sig.organization}`)
  console.log(`  subFilter         : ${sig.subFilter}`)
  console.log(`  integrityVerified : ${sig.documentIntegrityVerified}`)
  if (sig.integrityError) console.log(`  integrityError    : ${sig.integrityError}`)
  console.log()
}

const verified = sigs.filter((s) => s.level === 'verified').length
const tampered = sigs.filter((s) => s.level === 'tampered').length

console.log(`Summary: ${sigs.length} Attestto sig(s) — ${verified} verified, ${tampered} tampered`)
process.exit(verified > 0 ? 0 : 1)

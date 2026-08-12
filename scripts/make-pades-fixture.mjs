#!/usr/bin/env node
/**
 * Generate the committed PAdES test fixture.
 *
 * ATT-1270. The PAdES tests used to read
 * `$HOME/Attestto/CORTEX/api/tmp/pades-reference_digitally_signed.pdf` — a
 * gitignored tmp directory inside a different, private repo. They passed on one
 * workstation and failed everywhere else, so the whole of PAdES signature
 * extraction, this package's core capability, was unverified in CI.
 *
 * The original fixture cannot be committed: it carries a real Firma Digital
 * signer identity and this is a public repo. This script produces an equivalent
 * one with a SYNTHETIC signer and a throwaway self-signed certificate.
 *
 * WHAT IS COMMITTED IS THE PDF, NOT THE KEY. A fresh keypair is generated on
 * every run and discarded; nothing here is a real credential, and no private
 * key is written into the repository. Regenerating produces a byte-different
 * but behaviourally identical fixture, so do not regenerate casually — the
 * committed file is the referent the tests assert against.
 *
 * The signature is REAL, not a mock. `verifyPdf` reconstructs the ByteRange and
 * runs `pkijs.SignedData.verify()` over it, so a hand-waved /Contents blob
 * would leave `documentIntegrityVerified` false and the fixture would prove
 * nothing about the code path that matters.
 *
 * Usage: node scripts/make-pades-fixture.mjs
 */
import { execFileSync } from 'node:child_process'
import { mkdtempSync, writeFileSync, readFileSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join, resolve, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const OUT = resolve(REPO_ROOT, 'src/__fixtures__/pades-reference.pdf')

// The synthetic signer. Deliberately not a real person: these values are
// asserted verbatim by pdf-verifier.spec.ts.
const SIGNER_CN = 'ATTESTTO TEST SIGNER'
const REASON = 'PAdES reference fixture for automated tests'
const LOCATION = 'Attestto Platform'
const CONTACT = 'https://attestto.com/verify'
const SIGN_DATE = "D:20260812000000+00'00'"

// Big enough for a 2048-bit RSA CMS with one certificate, with headroom. The
// value must be fixed BEFORE the ByteRange is computed, because the placeholder
// occupies the gap the ByteRange describes.
const CONTENTS_HEX_LEN = 8192

const work = mkdtempSync(join(tmpdir(), 'pades-fixture-'))
try {
  // ── 1. throwaway self-signed certificate ────────────────────────────────
  execFileSync(
    'openssl',
    [
      'req', '-x509', '-newkey', 'rsa:2048',
      '-keyout', join(work, 'key.pem'),
      '-out', join(work, 'cert.pem'),
      '-days', '3650', '-nodes', '-sha256',
      '-subj', `/C=CR/O=Attestto Test Fixtures/CN=${SIGNER_CN}`,
    ],
    { stdio: 'pipe' },
  )

  // ── 2. PDF body with a placeholder signature ────────────────────────────
  // Hand-built rather than produced by pdf-lib: the signature dictionary has to
  // sit at a known offset so the ByteRange can be computed over it, and the
  // placeholder has to survive untouched until it is overwritten in place.
  const placeholder = '0'.repeat(CONTENTS_HEX_LEN)

  const objects = [
    '1 0 obj\n<< /Type /Catalog /Pages 2 0 R /AcroForm << /Fields [4 0 R] /SigFlags 3 >> >>\nendobj\n',
    '2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n',
    '3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Annots [4 0 R] >>\nendobj\n',
    '4 0 obj\n<< /Type /Annot /Subtype /Widget /FT /Sig /Rect [0 0 0 0] /T (Signature1) /V 5 0 R /P 3 0 R /F 132 >>\nendobj\n',
    // object 5 is the signature dictionary, assembled below
  ]

  const sigDictHead =
    '5 0 obj\n<< /Type /Sig /Filter /Adobe.PPKLite /SubFilter /adbe.pkcs7.detached ' +
    `/Name (${SIGNER_CN}) /Reason (${REASON}) /Location (${LOCATION}) ` +
    `/ContactInfo (${CONTACT}) /M (${SIGN_DATE}) ` +
    '/ByteRange [BYTERANGE_PLACEHOLDER] /Contents <'
  const sigDictTail = '>\n>>\nendobj\n'

  const header = '%PDF-1.7\n%\xE2\xE3\xCF\xD3\n'

  // Lay the file out once with a ByteRange placeholder of a FIXED width, so
  // patching it later cannot shift any offset.
  const byteRangeWidth = 'BYTERANGE_PLACEHOLDER'.length

  const buildLayout = (byteRangeText) => {
    const padded = byteRangeText.padEnd(byteRangeWidth, ' ')
    let body = header
    const offsets = []
    for (const obj of objects) {
      offsets.push(body.length)
      body += obj
    }
    const sigOffset = body.length
    offsets.push(sigOffset)
    const head = sigDictHead.replace('BYTERANGE_PLACEHOLDER', padded)
    const contentsStart = body.length + head.length // index of the byte after '<'
    body += head + placeholder + sigDictTail

    const xrefOffset = body.length
    let xref = `xref\n0 ${offsets.length + 1}\n0000000000 65535 f \n`
    for (const off of offsets) xref += `${String(off).padStart(10, '0')} 00000 n \n`
    xref += `trailer\n<< /Size ${offsets.length + 1} /Root 1 0 R >>\nstartxref\n${xrefOffset}\n%%EOF\n`
    body += xref
    return { body, contentsStart, total: body.length }
  }

  // First pass: discover the offsets the ByteRange must describe.
  const first = buildLayout('0 0 0 0')
  const gapStart = first.contentsStart // first byte of the hex placeholder
  const gapEnd = gapStart + CONTENTS_HEX_LEN // first byte after it
  const byteRange = [0, gapStart - 1, gapEnd + 1, first.total - (gapEnd + 1)]
  // -1 / +1 because the ByteRange excludes the angle brackets around /Contents.

  // Second pass: same layout, real ByteRange. Widths are identical by
  // construction, so every offset above still holds.
  const final = buildLayout(byteRange.join(' '))
  if (final.total !== first.total || final.contentsStart !== first.contentsStart) {
    throw new Error('layout shifted between passes; ByteRange would be wrong')
  }

  const pdf = Buffer.from(final.body, 'latin1')

  // ── 3. sign exactly the bytes the ByteRange covers ──────────────────────
  const signed = Buffer.concat([
    pdf.subarray(byteRange[0], byteRange[0] + byteRange[1]),
    pdf.subarray(byteRange[2], byteRange[2] + byteRange[3]),
  ])
  writeFileSync(join(work, 'signed.bin'), signed)

  execFileSync(
    'openssl',
    [
      'cms', '-sign', '-binary',
      '-in', join(work, 'signed.bin'),
      '-signer', join(work, 'cert.pem'),
      '-inkey', join(work, 'key.pem'),
      '-outform', 'DER', '-md', 'sha256',
      '-out', join(work, 'sig.der'),
    ],
    { stdio: 'pipe' },
  )

  const der = readFileSync(join(work, 'sig.der'))
  const hex = der.toString('hex').toUpperCase()
  if (hex.length > CONTENTS_HEX_LEN) {
    throw new Error(`CMS is ${hex.length} hex chars, placeholder is ${CONTENTS_HEX_LEN}`)
  }

  // Overwrite the placeholder IN PLACE. Padding with '0' keeps the length, and
  // trailing zero bytes are ignored by DER readers.
  pdf.write(hex.padEnd(CONTENTS_HEX_LEN, '0'), gapStart, 'latin1')

  writeFileSync(OUT, pdf)
  console.log(`wrote ${OUT}`)
  console.log(`  size        ${pdf.length} bytes`)
  console.log(`  ByteRange   [${byteRange.join(' ')}]`)
  console.log(`  CMS         ${der.length} bytes (${hex.length} of ${CONTENTS_HEX_LEN} hex chars used)`)
  console.log(`  signer      ${SIGNER_CN}`)
} finally {
  rmSync(work, { recursive: true, force: true })
}

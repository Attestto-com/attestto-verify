#!/usr/bin/env node
/**
 * Generate the committed Attestto self-attested test fixture.
 *
 * ATT-1270. These cases used to read
 *   /Users/<username>/Attestto/1-research/Licencia-Digital/carta-...(firmado).pdf
 * a HARDCODED ABSOLUTE PATH, containing a developer username, committed to this
 * public repo, pointing into the folder that holds real PII. It also degraded
 * silently: `const describeCarta = hasCarta ? describe : describe.skip`, so the
 * case its own comment calls "the test that matters for the carta ship
 * decision" never ran anywhere except one machine, and nothing said so.
 *
 * This produces an equivalent fixture with a SYNTHETIC signer and a throwaway
 * Ed25519 key. Only the signed PDF is committed; the key is discarded.
 *
 * The signature is REAL. `extractAttesttoSelfAttestedSignatures` rebuilds the
 * canonical payload and verifies Ed25519 over it via Web Crypto, so a fabricated
 * proofValue would land as `parsed` rather than `verified` and the fixture would
 * not cover the path it exists to cover.
 *
 * Usage: node scripts/make-self-attested-fixture.mjs
 */
import { generateKeyPairSync, sign as edSign } from 'node:crypto'
import { writeFileSync } from 'node:fs'
import { resolve, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const OUT = resolve(REPO_ROOT, 'src/__fixtures__/self-attested-reference.pdf')

const SIGNER_NAME = 'Attestto Test Signer'
const SIGNER_HANDLE = 'test.attestto'
const FILE_NAME = 'self-attested-reference.pdf'

const B58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'

/**
 * base58btc encode.
 *
 * The leading-zero handling is not decoration. An earlier hand-written encoder
 * in this estate counted leading zero bytes twice, so `00` encoded as `11`, and
 * round-tripping through its own decoder could not catch it because encode and
 * decode were wrong symmetrically. Leading zero BYTES become '1' characters;
 * the big-endian digit accumulator must not contribute its own high-order
 * zeros.
 */
function base58btc(bytes) {
  const digits = [0]
  for (const byte of bytes) {
    let carry = byte
    for (let i = 0; i < digits.length; i++) {
      carry += digits[i] << 8
      digits[i] = carry % 58
      carry = (carry / 58) | 0
    }
    while (carry > 0) {
      digits.push(carry % 58)
      carry = (carry / 58) | 0
    }
  }
  let significant = digits.length
  while (significant > 0 && digits[significant - 1] === 0) significant--

  let out = ''
  for (const byte of bytes) {
    if (byte !== 0) break
    out += '1'
  }
  for (let i = significant - 1; i >= 0; i--) out += B58[digits[i]]
  return out
}

// Canonicalization MUST match attestto-self-attested.ts canonicalPayloadBytes:
// strip `proof`, stringify with every object's keys sorted.
function canonicalBytes(sig) {
  const { proof, ...rest } = sig
  void proof
  const sortedReplacer = (_key, value) => {
    if (value && typeof value === 'object' && !Array.isArray(value)) {
      const sorted = {}
      for (const k of Object.keys(value).sort()) sorted[k] = value[k]
      return sorted
    }
    return value
  }
  return Buffer.from(JSON.stringify(rest, sortedReplacer), 'utf8')
}

const { publicKey, privateKey } = generateKeyPairSync('ed25519')
// generateKeyPairSync already hands back KeyObjects. The raw 32 bytes are the
// tail of the SPKI DER (RFC 8410 §4: a fixed 12-byte prefix then the key).
const rawPub = publicKey.export({ type: 'spki', format: 'der' }).subarray(-32)

// did:key for ed25519: multicodec 0xed 0x01 then base58btc, multibase prefix 'z'.
const did = `did:key:z${base58btc(Buffer.concat([Buffer.from([0xed, 0x01]), rawPub]))}`

const unsigned = {
  v: 1,
  type: ['VerifiableCredential', 'AttesttoPdfSignature'],
  issuer: did,
  issuerName: SIGNER_NAME,
  issuerHandle: SIGNER_HANDLE,
  country: 'CR',
  signedAt: '2026-08-12T00:00:00.000Z',
  // Not cross-checked against the file by the verifier, and it could not be:
  // the hash would have to cover the payload that contains it.
  documentHash: '0'.repeat(64),
  fileName: FILE_NAME,
  level: 'self-attested',
  mock: false,
  reason: 'Self-attested reference fixture for automated tests',
  location: 'Attestto Platform',
  mode: 'final',
}

const signature = edSign(null, canonicalBytes(unsigned), privateKey)

const signed = {
  ...unsigned,
  proof: {
    type: 'Ed25519Signature2020',
    created: '2026-08-12T00:00:00.000Z',
    verificationMethod: `${did}#key-1`,
    proofPurpose: 'assertionMethod',
    proofValue: signature.toString('base64'),
    publicKey: Buffer.from(rawPub).toString('base64'),
  },
}

const token = `attestto-sig-v1:${Buffer.from(JSON.stringify(signed), 'utf8').toString('base64')}`

// Minimal PDF. /Keywords must be uncompressed so a latin1 scan of the raw bytes
// finds the token, which is what the extractor does and why the desktop signer
// writes with useObjectStreams: false.
const header = '%PDF-1.7\n%\xE2\xE3\xCF\xD3\n'
const objects = [
  '1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n',
  '2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n',
  '3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>\nendobj\n',
  `4 0 obj\n<< /Keywords (${token}) /Producer (Attestto test fixture) >>\nendobj\n`,
]

let body = header
const offsets = []
for (const obj of objects) {
  offsets.push(body.length)
  body += obj
}
const xrefOffset = body.length
let xref = `xref\n0 ${offsets.length + 1}\n0000000000 65535 f \n`
for (const off of offsets) xref += `${String(off).padStart(10, '0')} 00000 n \n`
xref += `trailer\n<< /Size ${offsets.length + 1} /Root 1 0 R /Info 4 0 R >>\nstartxref\n${xrefOffset}\n%%EOF\n`
body += xref

writeFileSync(OUT, Buffer.from(body, 'latin1'))
console.log(`wrote ${OUT}`)
console.log(`  size    ${body.length} bytes`)
console.log(`  issuer  ${did}`)
console.log(`  signer  ${SIGNER_NAME}`)

/**
 * Browser-side Attestto self-attested PDF signer.
 *
 * This is the in-browser counterpart to attestto-desktop's
 * src/main/pdf/pdf-attestto.ts. It exists so verify.attestto.com/sign/
 * can produce PDFs that the verify.attestto.com/ verifier (post-ATT-361)
 * actually recognizes — instead of leaking pdf-lib Producer and writing
 * a full-rewrite with no canonical embed.
 *
 * **MUST stay byte-for-byte in lockstep with**:
 *   - desktop: `attestto-desktop/src/main/pdf/pdf-attestto.ts:canonicalPayload`
 *   - verify:  `attestto-verify/src/composables/attestto-self-attested.ts:canonicalPayloadBytes`
 *
 * If any of those three places diverge, every signature stops verifying.
 *
 * Crypto: ephemeral Ed25519 keypair generated per signature via Web Crypto
 * (Chrome 113+, Firefox 130+, Safari 17+). The private key never leaves
 * the browser session. The wallet/extension path is NOT YET supported —
 * filed as ATT-364 — because the extension currently produces ECDSA P-256
 * signatures the verifier rejects.
 */

import { PDFDocument } from 'pdf-lib'

const KEYWORD_PREFIX = 'attestto-sig-v1:'
const PRODUCER = 'Attestto Online Signer'

/**
 * The wire shape — IDENTICAL to AttesttoPdfSignature in
 * attestto-self-attested.ts and pdf-attestto.ts. Do not edit one
 * without editing the other two.
 */
export interface AttesttoPdfSignature {
  v: 1
  type: ['VerifiableCredential', 'AttesttoPdfSignature']
  issuer: string
  issuerName?: string
  issuerHandle?: string
  country?: string
  signedAt: string
  documentHash: string
  fileName: string
  level: 'self-attested' | 'firma-digital-mocked' | 'firma-digital-pkcs11'
  mock: boolean
  reason?: string
  location?: string
  mode: 'final' | 'open'
  proof: {
    type: 'Ed25519Signature2020'
    created: string
    verificationMethod: string
    proofPurpose: 'assertionMethod'
    proofValue: string
    publicKey: string
  }
}

export interface SelfSignOptions {
  signerName?: string
  signerHandle?: string
  signerCountry?: string
  reason?: string
  location?: string
  /** 'final' locks the doc; 'open' permits counter-signatures. */
  mode?: 'final' | 'open'
}

export interface SelfSignResult {
  pdfBytes: Uint8Array
  signature: AttesttoPdfSignature
  documentHash: string
}

// ── helpers ────────────────────────────────────────────────────────

function bytesToBase64(bytes: Uint8Array): string {
  let bin = ''
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i])
  return btoa(bin)
}

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes).map((b) => b.toString(16).padStart(2, '0')).join('')
}

async function sha256Hex(bytes: ArrayBuffer): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', bytes)
  return bytesToHex(new Uint8Array(digest))
}

/**
 * Canonicalize EXACTLY as desktop pdf-attestto.ts:canonicalPayload does:
 * lexicographic key sort at every dict level, compact JSON, no `proof`.
 */
function canonicalPayloadBytes(unsigned: Omit<AttesttoPdfSignature, 'proof'>): Uint8Array {
  const sortedReplacer = (_key: string, value: unknown): unknown => {
    if (value && typeof value === 'object' && !Array.isArray(value)) {
      const sorted: Record<string, unknown> = {}
      for (const k of Object.keys(value as Record<string, unknown>).sort()) {
        sorted[k] = (value as Record<string, unknown>)[k]
      }
      return sorted
    }
    return value
  }
  return new TextEncoder().encode(JSON.stringify(unsigned, sortedReplacer))
}

/**
 * Sign a PDF File with an ephemeral Ed25519 keypair and embed the
 * canonical Attestto signature in /Keywords. Returns the modified PDF
 * bytes plus the signature object for downstream UI.
 */
export async function signPdfSelfAttested(
  file: File,
  opts: SelfSignOptions = {},
): Promise<SelfSignResult> {
  if (typeof crypto === 'undefined' || !crypto.subtle) {
    throw new Error('Web Crypto API is not available in this browser')
  }

  // 1. Read & hash the original bytes — this is what gets bound into
  //    the credential as documentHash. The verifier recomputes it.
  const buffer = await file.arrayBuffer()
  const documentHash = await sha256Hex(buffer)

  // 2. Generate the ephemeral Ed25519 keypair. This key lives only for
  //    this signature — we don't persist it. Each signature is bound to
  //    a fresh key, which is the right semantic for a public no-account
  //    "sign this once" flow.
  let keyPair: CryptoKeyPair
  try {
    keyPair = (await crypto.subtle.generateKey(
      { name: 'Ed25519' },
      true,
      ['sign', 'verify'],
    )) as CryptoKeyPair
  } catch (err) {
    throw new Error(
      `Ed25519 not supported in this browser. Use a recent Chrome/Firefox/Safari. (${(err as Error).message})`,
    )
  }

  const rawPub = new Uint8Array(await crypto.subtle.exportKey('raw', keyPair.publicKey))
  if (rawPub.length !== 32) {
    throw new Error(`Unexpected Ed25519 public key length: ${rawPub.length}`)
  }

  // 3. Build the unsigned VC payload. The DID is a transparent
  //    "browser-ephemeral" placeholder — honest about what it is,
  //    not a fake did:key. The verifier doesn't resolve DIDs; it
  //    only uses the embedded publicKey for verification.
  const signedAt = new Date().toISOString()
  const issuer = `did:key-ephemeral:browser-${bytesToHex(rawPub).slice(0, 16)}`

  const unsigned: Omit<AttesttoPdfSignature, 'proof'> = {
    v: 1,
    type: ['VerifiableCredential', 'AttesttoPdfSignature'],
    issuer,
    issuerName: opts.signerName,
    issuerHandle: opts.signerHandle,
    country: opts.signerCountry,
    signedAt,
    documentHash,
    fileName: file.name,
    level: 'self-attested',
    mock: false,
    reason: opts.reason,
    location: opts.location,
    mode: opts.mode ?? 'final',
  }

  // 4. Canonicalize and sign the canonical bytes (NOT the document hash).
  //    This is the same protocol the desktop signer uses. The signature
  //    proves the signer asserted the entire VC payload, including the
  //    documentHash, signedAt, and DID, as one atomic statement.
  const payloadBytes = canonicalPayloadBytes(unsigned)
  const sigBuf = await crypto.subtle.sign(
    { name: 'Ed25519' },
    keyPair.privateKey,
    payloadBytes as BufferSource,
  )
  const sigBytes = new Uint8Array(sigBuf)
  if (sigBytes.length !== 64) {
    throw new Error(`Unexpected Ed25519 signature length: ${sigBytes.length}`)
  }

  const signature: AttesttoPdfSignature = {
    ...unsigned,
    proof: {
      type: 'Ed25519Signature2020',
      created: signedAt,
      verificationMethod: `${issuer}#key-1`,
      proofPurpose: 'assertionMethod',
      proofValue: bytesToBase64(sigBytes),
      publicKey: bytesToBase64(rawPub),
    },
  }

  // 5. Embed in /Keywords and write the PDF. We MUST use
  //    useObjectStreams: false so the verifier's raw-bytes scan can
  //    find the keyword without decompressing object streams.
  const sigJson = JSON.stringify(signature)
  const sigB64Payload = btoa(sigJson)
  const keywordEntry = `${KEYWORD_PREFIX}${sigB64Payload}`

  const doc = await PDFDocument.load(buffer)

  // Set Producer so the verifier's "Producer = pdf-lib" smell-test
  // shows our brand instead of leaking the underlying library. Same
  // override the desktop signer applies (ATT-356).
  doc.setProducer(PRODUCER)
  doc.setModificationDate(new Date())

  // Preserve any pre-existing keywords; append ours.
  const existing = (doc.getKeywords() ?? '')
    .split(/\s+/)
    .filter((k) => k && !k.startsWith(KEYWORD_PREFIX))
  doc.setKeywords([...existing, keywordEntry])

  const pdfBytes = await doc.save({ useObjectStreams: false })

  return { pdfBytes, signature, documentHash }
}

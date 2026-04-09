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

/**
 * External signer contract — given the canonical payload bytes,
 * return the 64-byte Ed25519 signature + 32-byte raw public key
 * (both base64). The verify-side composable does NOT care where the
 * key lives (browser-ephemeral, extension vault, hardware token);
 * it only cares that the resulting signature verifies.
 */
export interface ExternalSigner {
  did: string
  sign(payload: Uint8Array): Promise<{ signatureB64: string; publicKeyB64: string }>
}

export interface SelfSignOptions {
  signerName?: string
  signerHandle?: string
  signerCountry?: string
  reason?: string
  location?: string
  /** 'final' locks the doc; 'open' permits counter-signatures. */
  mode?: 'final' | 'open'
  /**
   * If provided, the canonical payload is signed by this external signer
   * (e.g. an Attestto ID extension). If omitted, an ephemeral browser
   * Ed25519 keypair is generated and used.
   */
  externalSigner?: ExternalSigner
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

  // 2. Determine signer + DID. Two paths:
  //
  //    (a) externalSigner provided (e.g. extension vault Ed25519 key)
  //        — we'll call signer.sign(payload) below; DID comes from
  //        signer.did.
  //
  //    (b) no externalSigner — we generate an ephemeral Ed25519 keypair
  //        for this single signature. Honest "did:key-ephemeral" DID.
  let signedKeyPair: CryptoKeyPair | null = null
  let issuer: string

  if (opts.externalSigner) {
    issuer = opts.externalSigner.did
  } else {
    try {
      signedKeyPair = (await crypto.subtle.generateKey(
        { name: 'Ed25519' },
        true,
        ['sign', 'verify'],
      )) as CryptoKeyPair
    } catch (err) {
      throw new Error(
        `Ed25519 not supported in this browser. Use a recent Chrome/Firefox/Safari. (${(err as Error).message})`,
      )
    }

    const rawPub = new Uint8Array(await crypto.subtle.exportKey('raw', signedKeyPair.publicKey))
    if (rawPub.length !== 32) {
      throw new Error(`Unexpected Ed25519 public key length: ${rawPub.length}`)
    }

    issuer = `did:key-ephemeral:browser-${bytesToHex(rawPub).slice(0, 16)}`
  }

  const signedAt = new Date().toISOString()

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

  let proofValueB64: string
  let publicKeyB64: string

  if (opts.externalSigner) {
    // Hand the canonical bytes to the external signer (e.g. extension
    // vault). It is responsible for returning a valid 64-byte Ed25519
    // signature + 32-byte raw public key, both base64.
    const result = await opts.externalSigner.sign(payloadBytes)
    proofValueB64 = result.signatureB64
    publicKeyB64 = result.publicKeyB64
  } else {
    if (!signedKeyPair) {
      throw new Error('internal: no signing keypair available')
    }
    const sigBuf = await crypto.subtle.sign(
      { name: 'Ed25519' },
      signedKeyPair.privateKey,
      payloadBytes as BufferSource,
    )
    const sigBytes = new Uint8Array(sigBuf)
    if (sigBytes.length !== 64) {
      throw new Error(`Unexpected Ed25519 signature length: ${sigBytes.length}`)
    }
    proofValueB64 = bytesToBase64(sigBytes)
    const rawPub = new Uint8Array(await crypto.subtle.exportKey('raw', signedKeyPair.publicKey))
    publicKeyB64 = bytesToBase64(rawPub)
  }

  const signature: AttesttoPdfSignature = {
    ...unsigned,
    proof: {
      type: 'Ed25519Signature2020',
      created: signedAt,
      verificationMethod: `${issuer}#key-1`,
      proofPurpose: 'assertionMethod',
      proofValue: proofValueB64,
      publicKey: publicKeyB64,
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

// ── Extension-vault external signer (ATT-364) ─────────────────────

/**
 * Build an `ExternalSigner` that delegates Ed25519 signing to the
 * Attestto ID extension via window.postMessage. The extension's
 * background handler signs the canonical payload bytes with the
 * vault's Ed25519 key (lazily provisioned per ATT-364) and returns
 * the 64-byte signature + 32-byte raw public key.
 *
 * NOTE: This bypasses the @attestto/id-wallet-adapter package — the
 * canonical wire is direct postMessage. A `requestAttesttoPdfSignature`
 * helper should be added to id-wallet-adapter v0.5+ so other consumers
 * don't have to inline the protocol. Tracked in ATT-364 follow-up.
 *
 * The returned signer:
 *   - posts ATTESTTO_SIGN_PDF_REQUEST with the canonical payload
 *   - waits for ATTESTTO_SIGN_PDF_RESPONSE (matched by requestId)
 *   - times out after 120s
 *   - throws on user denial / extension absence
 */
export interface ExtensionSignerOptions {
  fileName: string
  documentHash: string
  /** Wallet DID to display to the user (e.g. eduardo.attestto.id). */
  did: string
  /** Override the timeout. Default 120s. */
  timeoutMs?: number
}

export function buildExtensionSigner(opts: ExtensionSignerOptions): ExternalSigner {
  return {
    did: opts.did,
    sign(payload: Uint8Array): Promise<{ signatureB64: string; publicKeyB64: string }> {
      return new Promise((resolve, reject) => {
        const requestId = `attestto-pdf-${Date.now()}-${Math.random().toString(36).slice(2, 10)}`
        const payloadB64 = bytesToBase64(payload)

        const onMessage = (event: MessageEvent): void => {
          if (event.source !== window) return
          const data = event.data
          if (!data || data.type !== 'ATTESTTO_SIGN_PDF_RESPONSE') return
          if (data.requestId !== requestId) return

          window.removeEventListener('message', onMessage)
          window.clearTimeout(timer)

          if (data.error) {
            reject(new Error(`Extension signing failed: ${data.error}`))
            return
          }
          if (!data.signature || !data.publicKey) {
            reject(new Error('Extension response missing signature or publicKey'))
            return
          }
          resolve({ signatureB64: data.signature, publicKeyB64: data.publicKey })
        }

        window.addEventListener('message', onMessage)

        const timer = window.setTimeout(() => {
          window.removeEventListener('message', onMessage)
          reject(new Error('Extension did not respond within timeout'))
        }, opts.timeoutMs ?? 120_000)

        window.postMessage(
          {
            type: 'ATTESTTO_SIGN_PDF_REQUEST',
            requestId,
            payloadB64,
            fileName: opts.fileName,
            documentHash: opts.documentHash,
          },
          window.location.origin,
        )
      })
    },
  }
}

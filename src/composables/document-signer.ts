/**
 * Document Signing — Client-Side
 *
 * Produces W3C Verifiable Credentials (DocumentSignatureCredential)
 * from document hashes. Supports two signing paths:
 *
 *   1. Wallet adapter — delegates to a DID wallet extension via requestSignature()
 *   2. Browser key — self-issued ECDSA P-256 via WebCrypto (did:key)
 *
 * The component (attestto-sign.ts) is UI only — all crypto and VC
 * construction lives here. v2 changes (pkijs, CA chain) only touch
 * this file and the plugin pipeline.
 */

import { requestSignature, type WalletAnnouncement } from '@attestto/id-wallet-adapter'
import { computeHash } from './pdf-verifier.js'
import { logger } from '../logger.js'

// ── Types ──────────────────────────────────────────────────────────

export interface DocumentSignatureCredential {
  '@context': string[]
  type: string[]
  issuer: string
  issuanceDate: string
  credentialSubject: {
    type: 'DocumentSignature'
    document: {
      fileName: string
      hash: string
      hashAlgorithm: 'SHA-256'
      size: number
    }
    verifyUrl: string
  }
  proof: {
    type: string
    created: string
    verificationMethod: string
    proofValue: string
    jws: string
  }
}

export interface SignResult {
  credential: DocumentSignatureCredential
  /** Whether the VC was pushed to a wallet (vs browser-key self-issued) */
  storedInWallet: boolean
}

// ── Browser Key Manager ────────────────────────────────────────────

let browserKeyPair: CryptoKeyPair | null = null

/**
 * Get or create a browser-session ECDSA P-256 keypair.
 * Persists for the page lifetime — reused across multiple signs.
 */
export async function getBrowserKeyPair(): Promise<CryptoKeyPair> {
  if (!browserKeyPair) {
    browserKeyPair = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, [
      'sign',
      'verify',
    ])
  }
  return browserKeyPair
}

// ── Hashing ────────────────────────────────────────────────────────

/** Re-export for convenience — single import for sign components */
export { computeHash }

/**
 * Compute SHA-256 hash of a File.
 */
export async function hashFile(file: File): Promise<string> {
  logger.sign.info(`[1/5] Reading file "${file.name}" (${file.size} bytes) into memory`)
  const buffer = await file.arrayBuffer()
  const hash = await computeHash(buffer)
  logger.sign.info(`[2/5] SHA-256 computed: ${hash}`)
  return hash
}

// ── Signing ────────────────────────────────────────────────────────

/**
 * Sign a document hash using a wallet extension (via adapter protocol).
 * Returns null if the user rejects or the request times out.
 */
export async function signWithWallet(
  wallet: WalletAnnouncement,
  file: File,
  hash: string,
): Promise<SignResult | null> {
  logger.sign.info(`[3/5] Requesting signature from "${wallet.name}" (${wallet.did})`)
  logger.sign.info('[3/5] Dispatching credential-wallet:sign event. Waiting for wallet response...')

  const response = await requestSignature(
    wallet,
    {
      hash,
      fileName: file.name,
      hashAlgorithm: 'SHA-256',
      fileSize: file.size,
    },
    { timeoutMs: 120_000 },
  )

  if (!response?.approved) {
    logger.sign.warn(
      '[3/5] Signature rejected or timed out. This means either: (a) no wallet extension is handling the event on this origin, (b) the user declined, or (c) the 120s timeout elapsed.',
    )
    return null
  }

  logger.sign.event(`[3/5] Signature received from ${response.did}`)

  logger.sign.info('[4/5] Building W3C DocumentSignatureCredential (Verifiable Credential)')
  const credential = buildCredential(
    hash,
    file.name,
    file.size,
    response.did!,
    response.signature!,
    response.timestamp!,
  )

  logger.sign.info('[5/5] Pushing VC to wallet storage via ATTESTTO_VC_STORE postMessage')
  window.postMessage({ type: 'ATTESTTO_VC_STORE', credential }, '*')

  logger.sign.event('[5/5] Done — signed VC stored in wallet', { issuer: response.did, hash })
  return { credential, storedInWallet: true }
}

/**
 * Sign a document hash using a browser-generated ECDSA P-256 key.
 * Produces a self-issued VC with did:key — no extension required.
 */
export async function signWithBrowserKey(file: File, hash: string): Promise<SignResult> {
  logger.sign.info('[3/5] Generating ECDSA P-256 signature via WebCrypto (no extension required)')
  const keyPair = await getBrowserKeyPair()

  const hashBytes = new Uint8Array(hash.match(/.{2}/g)!.map((b) => parseInt(b, 16)))
  const sigBuffer = await crypto.subtle.sign(
    { name: 'ECDSA', hash: 'SHA-256' },
    keyPair.privateKey,
    hashBytes,
  )
  logger.sign.event('[3/5] ECDSA signature computed — key never leaves browser memory')

  const jwk = await crypto.subtle.exportKey('jwk', keyPair.publicKey)
  const sigBase64 = btoa(String.fromCharCode(...new Uint8Array(sigBuffer)))
  const did = `did:key:z${btoa(JSON.stringify(jwk)).slice(0, 32)}`
  const timestamp = new Date().toISOString()

  logger.sign.info(`[4/5] Building W3C DocumentSignatureCredential — issuer: ${did} (self-issued)`)
  const credential = buildCredential(hash, file.name, file.size, did, sigBase64, timestamp)

  logger.sign.event(
    '[5/5] Done — VC ready for export. Not stored in wallet (browser key is ephemeral).',
    { issuer: did, hash },
  )

  return { credential, storedInWallet: false }
}

// ── VC Builder ─────────────────────────────────────────────────────

/**
 * Build a W3C DocumentSignatureCredential.
 * Single source of truth — wallet and browser key paths both use this.
 */
export function buildCredential(
  hash: string,
  fileName: string,
  fileSize: number,
  did: string,
  signature: string,
  timestamp: string,
): DocumentSignatureCredential {
  return {
    '@context': [
      'https://www.w3.org/2018/credentials/v1',
      'https://attestto.com/contexts/document-signature/v1',
    ],
    type: ['VerifiableCredential', 'DocumentSignatureCredential'],
    issuer: did,
    issuanceDate: timestamp,
    credentialSubject: {
      type: 'DocumentSignature',
      document: { fileName, hash, hashAlgorithm: 'SHA-256', size: fileSize },
      verifyUrl: `https://verify.attestto.com/d/${hash}`,
    },
    proof: {
      type: 'EcdsaSecp256r1Signature2019',
      created: timestamp,
      verificationMethod: did,
      proofValue: signature,
      jws: signature,
    },
  }
}

// ── Export Utility ──────────────────────────────────────────────────

/**
 * Trigger a JSON download of a signed credential.
 */
export function exportCredentialAsJson(
  credential: DocumentSignatureCredential,
  originalFileName?: string,
): void {
  const blob = new Blob([JSON.stringify(credential, null, 2)], { type: 'application/json' })
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = originalFileName?.replace(/\.pdf$/i, '.vc.json') ?? 'credential.vc.json'
  a.click()
  URL.revokeObjectURL(url)
}

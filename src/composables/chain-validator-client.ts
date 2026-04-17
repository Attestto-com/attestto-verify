/**
 * Chain Validator Client — Web Worker wrapper (ATT-316).
 *
 * Exports the same API as chain-validator.ts but runs pkijs in a Web Worker
 * to keep the main thread free. Falls back to direct (main-thread) execution
 * when Workers aren't available (Node.js tests, SSR, some sandboxed iframes).
 *
 * Usage: import from this module instead of chain-validator.ts in browser code.
 * The chain-validator.ts module remains the canonical implementation —
 * this file is a transparent proxy.
 */

import { logger } from '../logger.js'
import type { ChainValidationResult, IntegrityResult } from './chain-validator.js'
import type { PkiResolverOptions } from './pki-resolver.js'
import type { WorkerRequest, WorkerResponse } from './verify-worker.js'

const log = logger.verify

// ── Worker Lifecycle ──────────────────────────────────────────────

let worker: Worker | null = null
let workerFailed = false
let requestId = 0
const pending = new Map<number, { resolve: (v: unknown) => void; reject: (e: Error) => void }>()

function getWorker(): Worker | null {
  if (workerFailed) return null
  if (worker) return worker

  // Node.js / SSR — no Worker available
  if (typeof Worker === 'undefined' || typeof window === 'undefined') return null

  try {
    worker = new Worker(new URL('./verify-worker.ts', import.meta.url), { type: 'module' })
    worker.onmessage = (e: MessageEvent<WorkerResponse>) => {
      const { id, result, error } = e.data
      const p = pending.get(id)
      if (!p) return
      pending.delete(id)
      if (error) {
        p.reject(new Error(error))
      } else {
        p.resolve(result)
      }
    }
    worker.onerror = (e) => {
      log.warn(`[chain-validator-client] Worker error: ${e.message} — falling back to main thread`)
      workerFailed = true
      worker = null
      // Reject all pending requests so they can retry on main thread
      for (const [id, p] of pending) {
        p.reject(new Error('Worker crashed'))
        pending.delete(id)
      }
    }
    log.info('[chain-validator-client] Web Worker spawned — pkijs runs off-thread')
    return worker
  } catch {
    log.warn('[chain-validator-client] Worker spawn failed — using main thread')
    workerFailed = true
    return null
  }
}

function sendToWorker<T>(type: WorkerRequest['type'], payload: WorkerRequest['payload']): Promise<T> {
  const w = getWorker()
  if (!w) return Promise.reject(new Error('no-worker'))

  const id = ++requestId
  return new Promise<T>((resolve, reject) => {
    pending.set(id, { resolve: resolve as (v: unknown) => void, reject })
    w.postMessage({ id, type, payload } satisfies WorkerRequest)
  })
}

// ── Public API (same signatures as chain-validator.ts) ────────────

/**
 * Validate a certificate chain. Runs in Web Worker when available,
 * falls back to main-thread import.
 */
export async function validateChain(
  signerCertHex: string,
  intermediateCertsHex: string[],
): Promise<ChainValidationResult> {
  try {
    return await sendToWorker<ChainValidationResult>('validateChain', {
      signerHex: signerCertHex,
      intermediatesHex: intermediateCertsHex,
    })
  } catch {
    // Fallback: direct main-thread execution
    const mod = await import('./chain-validator.js')
    return mod.validateChain(signerCertHex, intermediateCertsHex)
  }
}

/**
 * Validate with resolver-backed trust anchors. Web Worker or fallback.
 */
export async function validateChainWithResolver(
  signerCertHex: string,
  intermediateCertsHex: string[],
  pkiDid?: string | null,
  resolverOptions?: PkiResolverOptions,
): Promise<ChainValidationResult> {
  try {
    return await sendToWorker<ChainValidationResult>('validateChainWithResolver', {
      signerHex: signerCertHex,
      intermediatesHex: intermediateCertsHex,
      pkiDid,
      resolverOptions,
    })
  } catch {
    const mod = await import('./chain-validator.js')
    return mod.validateChainWithResolver(signerCertHex, intermediateCertsHex, pkiDid, resolverOptions)
  }
}

/**
 * Verify document integrity (ByteRange hash match). Web Worker or fallback.
 */
export async function verifyDocumentIntegrity(
  pkcs7Hex: string,
  signedData: ArrayBuffer,
): Promise<IntegrityResult> {
  try {
    return await sendToWorker<IntegrityResult>('verifyDocumentIntegrity', {
      pkcs7Hex,
      signedData,
    })
  } catch {
    const mod = await import('./chain-validator.js')
    return mod.verifyDocumentIntegrity(pkcs7Hex, signedData)
  }
}

// Re-export reconstructSignedBytes (pure function, no pkijs — stays on main thread)
export { reconstructSignedBytes } from './chain-validator.js'

// Re-export types
export type { ChainValidationResult, IntegrityResult } from './chain-validator.js'

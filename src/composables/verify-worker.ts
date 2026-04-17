/**
 * Web Worker for pkijs chain validation + document integrity.
 *
 * Runs pkijs (~250 KB gzipped) off the main thread so the UI stays
 * responsive during cryptographic verification. ATT-316.
 *
 * Message protocol:
 *   Main → Worker: { id, type, payload }
 *   Worker → Main: { id, result?, error? }
 */

import {
  validateChain,
  validateChainWithResolver,
  verifyDocumentIntegrity,
  type ChainValidationResult,
  type IntegrityResult,
} from './chain-validator.js'
import type { PkiResolverOptions } from './pki-resolver.js'

export interface WorkerRequest {
  id: number
  type: 'validateChain' | 'validateChainWithResolver' | 'verifyDocumentIntegrity'
  payload: {
    signerHex?: string
    intermediatesHex?: string[]
    pkiDid?: string | null
    resolverOptions?: PkiResolverOptions
    pkcs7Hex?: string
    signedData?: ArrayBuffer
  }
}

export interface WorkerResponse {
  id: number
  result?: ChainValidationResult | IntegrityResult
  error?: string
}

self.onmessage = async (e: MessageEvent<WorkerRequest>) => {
  const { id, type, payload } = e.data
  try {
    let result: ChainValidationResult | IntegrityResult

    switch (type) {
      case 'validateChain':
        result = await validateChain(payload.signerHex!, payload.intermediatesHex ?? [])
        break
      case 'validateChainWithResolver':
        result = await validateChainWithResolver(
          payload.signerHex!,
          payload.intermediatesHex ?? [],
          payload.pkiDid,
          payload.resolverOptions,
        )
        break
      case 'verifyDocumentIntegrity':
        result = await verifyDocumentIntegrity(payload.pkcs7Hex!, payload.signedData!)
        break
      default:
        throw new Error(`Unknown message type: ${type}`)
    }

    self.postMessage({ id, result } satisfies WorkerResponse)
  } catch (err) {
    self.postMessage({
      id,
      error: err instanceof Error ? err.message : String(err),
    } satisfies WorkerResponse)
  }
}

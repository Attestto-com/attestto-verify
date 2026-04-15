/**
 * PKI Resolver Client — Dynamic trust anchor resolution via resolver.attestto.com
 *
 * Fetches DID Documents for did:pki identifiers, extracts public key fingerprints,
 * and matches them against certificate fingerprints from parsed PDF signatures.
 *
 * This enables multi-country signature verification without bundling every
 * country's CA certificates. The resolver is the source of truth for which
 * CA keys are trusted.
 *
 * ATT-438
 */

import { logger } from '../logger.js'

const log = logger.verify

// ── Configuration ─────────────────────────────────────────────────────

const DEFAULT_RESOLVER_URL = 'https://resolver.attestto.com/1.0/identifiers'
const DEFAULT_TIMEOUT_MS = 10_000

// ── Types ─────────────────────────────────────────────────────────────

export interface ResolvedPkiKey {
  /** Key ID from the DID Document (e.g. "#key-2023") */
  keyId: string
  /** JWK public key */
  publicKeyJwk: JsonWebKey & { x5t?: string }
  /** SHA-256 fingerprint of the original X.509 certificate (hex, lowercase) */
  fingerprint: string
  /** Key status from pkiMetadata.generations */
  status: 'active' | 'revoked' | 'expired' | string
  /** Validity period */
  notBefore?: string
  notAfter?: string
}

export interface PkiResolutionResult {
  /** The resolved DID */
  did: string
  /** All public keys with fingerprints */
  keys: ResolvedPkiKey[]
  /** PKI metadata from the DID Document */
  metadata: {
    country: string
    countryName: string
    hierarchy: string
    administrator: string
    level: string
    parentDid?: string
    rootDid?: string
  } | null
  /** Whether the resolution came from cache */
  cached: boolean
}

export interface PkiResolverOptions {
  /** Base URL for the resolver (default: resolver.attestto.com) */
  resolverUrl?: string
  /** Timeout in ms (default: 10000) */
  timeout?: number
  /** Custom fetch function (for testing) */
  fetchFn?: typeof fetch
}

// ── Cache ─────────────────────────────────────────────────────────────

interface CacheEntry {
  result: PkiResolutionResult
  timestamp: number
}

// Cache resolved DIDs for 5 minutes (resolver data changes rarely)
const CACHE_TTL_MS = 5 * 60 * 1000
const resolverCache = new Map<string, CacheEntry>()

// ── Public API ────────────────────────────────────────────────────────

/**
 * Resolve a did:pki identifier via resolver.attestto.com.
 *
 * Returns the DID Document's public keys with their X.509 fingerprints,
 * which can be matched against certificates extracted from a PDF.
 *
 * @param did     The did:pki identifier (e.g. "did:pki:cr:sinpe:persona-fisica")
 * @param options Resolver configuration
 * @returns       Resolved keys and metadata, or null if resolution fails
 */
export async function resolvePkiDid(
  did: string,
  options: PkiResolverOptions = {},
): Promise<PkiResolutionResult | null> {
  const resolverUrl = options.resolverUrl || DEFAULT_RESOLVER_URL
  const timeout = options.timeout || DEFAULT_TIMEOUT_MS
  const fetchFn = options.fetchFn || fetch

  // Check cache
  const cached = resolverCache.get(did)
  if (cached && Date.now() - cached.timestamp < CACHE_TTL_MS) {
    log.info(`[pki-resolver] Cache hit: ${did}`)
    return { ...cached.result, cached: true }
  }

  const url = `${resolverUrl}/${encodeURIComponent(did)}`
  log.info(`[pki-resolver] Resolving: ${url}`)

  try {
    const response = await fetchFn(url, {
      signal: AbortSignal.timeout(timeout),
      headers: { Accept: 'application/did+json, application/json' },
    })

    if (!response.ok) {
      log.warn(`[pki-resolver] Resolution failed: ${response.status} ${response.statusText}`)
      return null
    }

    const body = await response.json()
    const didDocument = body.didDocument
    if (!didDocument) {
      log.warn(`[pki-resolver] No didDocument in response for ${did}`)
      return null
    }

    // Extract keys from verificationMethod
    const keys: ResolvedPkiKey[] = []
    const verificationMethods = didDocument.verificationMethod || []
    const generations = didDocument.pkiMetadata?.generations || []

    for (const vm of verificationMethods) {
      if (!vm.publicKeyJwk) continue

      // Find the matching generation entry for this key
      const keyId = vm.id?.split('#')[1] ? `#${vm.id.split('#')[1]}` : vm.id
      const gen = generations.find(
        (g: { keyId: string }) => g.keyId === keyId,
      )

      // The fingerprint comes from the JWK's x5t field or the generation entry
      const fingerprint =
        vm.publicKeyJwk.x5t ||
        gen?.fingerprint ||
        null

      if (!fingerprint) {
        log.warn(`[pki-resolver] Key ${vm.id} has no fingerprint — skipping`)
        continue
      }

      keys.push({
        keyId,
        publicKeyJwk: vm.publicKeyJwk,
        fingerprint: fingerprint.toLowerCase(),
        status: gen?.status || 'unknown',
        notBefore: gen?.notBefore,
        notAfter: gen?.notAfter,
      })
    }

    // Extract metadata
    const pkiMeta = didDocument.pkiMetadata
    const metadata = pkiMeta
      ? {
          country: pkiMeta.country,
          countryName: pkiMeta.countryName,
          hierarchy: pkiMeta.hierarchy,
          administrator: pkiMeta.administrator,
          level: pkiMeta.level,
          parentDid: pkiMeta.parentDid,
          rootDid: pkiMeta.rootDid,
        }
      : null

    const result: PkiResolutionResult = {
      did,
      keys,
      metadata,
      cached: false,
    }

    // Cache the result
    resolverCache.set(did, { result, timestamp: Date.now() })

    log.event(
      `[pki-resolver] Resolved ${did}: ${keys.length} key(s), ` +
        `${keys.filter((k) => k.status === 'active').length} active`,
    )

    return result
  } catch (err) {
    if (err instanceof DOMException && err.name === 'TimeoutError') {
      log.warn(`[pki-resolver] Timeout resolving ${did} (${timeout}ms)`)
    } else {
      const message = err instanceof Error ? err.message : String(err)
      log.warn(`[pki-resolver] Error resolving ${did}: ${message}`)
    }
    return null
  }
}

/**
 * Match a certificate's SHA-256 fingerprint against resolved DID keys.
 *
 * @param resolved  The resolved DID with keys
 * @param certFingerprint  SHA-256 hex fingerprint of the certificate's DER bytes
 * @returns  The matching key, or null if no match
 */
export function matchKeyByFingerprint(
  resolved: PkiResolutionResult,
  certFingerprint: string,
): ResolvedPkiKey | null {
  const normalized = certFingerprint.toLowerCase()
  return resolved.keys.find((k) => k.fingerprint === normalized) || null
}

/**
 * Compute SHA-256 fingerprint of a certificate's DER bytes.
 * Works in both browser (WebCrypto) and Node (crypto module).
 *
 * @param derHex  Hex-encoded DER bytes of the certificate
 * @returns       SHA-256 fingerprint as lowercase hex string
 */
export async function computeCertFingerprint(derHex: string): Promise<string> {
  const clean = derHex.replace(/\s+/g, '')
  const bytes = new Uint8Array(clean.length / 2)
  for (let i = 0; i < clean.length; i += 2) {
    bytes[i / 2] = parseInt(clean.substring(i, i + 2), 16)
  }

  // Use WebCrypto (works in browser and Node 18+)
  const hashBuffer = await crypto.subtle.digest('SHA-256', bytes)
  const hashArray = new Uint8Array(hashBuffer)
  let hex = ''
  for (let i = 0; i < hashArray.length; i++) {
    hex += hashArray[i].toString(16).padStart(2, '0')
  }
  return hex
}

/**
 * Resolve a did:pki and try to match any CA certificate in the chain.
 *
 * This is the main integration point: given a did:pki and the CA certs
 * from a PDF, determine which (if any) CA cert the resolver trusts.
 *
 * @param pkiDid              The did:pki to resolve
 * @param caCertDerHexes      DER hex strings of CA certs from the PDF chain
 * @param options             Resolver options
 * @returns                   Index of the matched CA cert, the matched key, and the resolution result
 */
export async function resolveAndMatchChain(
  pkiDid: string,
  caCertDerHexes: string[],
  options: PkiResolverOptions = {},
): Promise<{
  matched: boolean
  matchedCertIndex: number
  matchedKey: ResolvedPkiKey | null
  resolution: PkiResolutionResult | null
}> {
  const resolution = await resolvePkiDid(pkiDid, options)
  if (!resolution || resolution.keys.length === 0) {
    return { matched: false, matchedCertIndex: -1, matchedKey: null, resolution }
  }

  // Compute fingerprints for each CA cert and try to match
  for (let i = 0; i < caCertDerHexes.length; i++) {
    try {
      const fingerprint = await computeCertFingerprint(caCertDerHexes[i])
      const matchedKey = matchKeyByFingerprint(resolution, fingerprint)
      if (matchedKey) {
        log.event(
          `[pki-resolver] ✓ Fingerprint match: cert[${i}] → ${matchedKey.keyId} (${matchedKey.status})`,
        )
        return { matched: true, matchedCertIndex: i, matchedKey, resolution }
      }
    } catch {
      // Skip certs that fail fingerprint computation
    }
  }

  log.warn(`[pki-resolver] No fingerprint match for ${pkiDid} against ${caCertDerHexes.length} CA cert(s)`)
  return { matched: false, matchedCertIndex: -1, matchedKey: null, resolution }
}

/**
 * Clear the resolver cache. Exposed for testing.
 * @internal
 */
export function _resetResolverCache(): void {
  resolverCache.clear()
}

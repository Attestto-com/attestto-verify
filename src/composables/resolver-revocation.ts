/**
 * CR Firma Digital revocation via the Attestto resolver CRL endpoint.
 *
 * Direct OCSP from the browser is blocked twice for CR: the responder is plain
 * HTTP (mixed content) and sends no CORS headers. So for CR SINPE certificates
 * we ask our own resolver, which fetches + verifies the CRL server-side and
 * serves it over HTTPS with CORS. We download the whole revoked-serial list and
 * check the signer serial locally, so the resolver never learns which cert is
 * being checked (better privacy than OCSP, which sends the serial).
 *
 * Because the list is public (not per-cert) and comes from our own host, this
 * path is safe to run automatically when a card is shown. Two layers keep it
 * cheap:
 *   1. In-flight dedup + a per-session parsed cache here, so N signature cards
 *      that share a CA trigger ONE fetch and reuse the parsed revoked-set.
 *   2. The resolver sends `Cache-Control: max-age=<until nextUpdate>`, so the
 *      browser HTTP cache serves the list across page loads until the CRL's own
 *      next update. Coming back within that window resolves with no network.
 */

const RESOLVER_BASE = 'https://resolver.attestto.com'

export type CrSinpeCa = 'sinpe-persona-fisica' | 'sinpe-persona-juridica'

export interface ResolverRevocationResult {
  status: 'good' | 'revoked' | 'unknown' | 'unreachable'
  message: string
  checkedAt: string
}

interface CrlResponse {
  revokedSerials?: string[]
  signatureVerified?: boolean
  stale?: boolean
  nextUpdate?: string | null
}

/** Parsed, ready-to-query CRL data with a per-session freshness bound. */
interface CrlData {
  revoked: Set<string>
  signatureVerified: boolean
  stale: boolean
  /** Date.now() ms after which this session-cached parse is considered stale. */
  expiresAt: number
}

/** Normalize a hex serial for comparison: lowercase, strip non-hex, drop leading zeros. */
function normSerial(s: string): string {
  return s.toLowerCase().replace(/[^0-9a-f]/g, '').replace(/^0+/, '')
}

// Per-session parsed cache + in-flight dedup. The browser HTTP cache handles the
// network layer across sessions; these avoid re-parsing and stop N cards from
// each issuing their own request within one page.
const crlCache = new Map<CrSinpeCa, CrlData>()
const inFlight = new Map<CrSinpeCa, Promise<CrlData | null>>()

/** One-hour floor when a CRL is stale or omits nextUpdate. */
const FALLBACK_TTL_MS = 60 * 60 * 1000

async function fetchCrlData(ca: CrSinpeCa, fetchFn: typeof fetch): Promise<CrlData | null> {
  try {
    const resp = await fetchFn(`${RESOLVER_BASE}/revocation/cr/${ca}`, {
      method: 'GET',
      headers: { accept: 'application/json' },
    })
    if (!resp.ok) return null
    const data = (await resp.json()) as CrlResponse
    const revoked = new Set((data.revokedSerials ?? []).map(normSerial))
    const nextMs = data.nextUpdate ? Date.parse(data.nextUpdate) : NaN
    const expiresAt =
      Number.isFinite(nextMs) && !data.stale ? nextMs : Date.now() + FALLBACK_TTL_MS
    return {
      revoked,
      signatureVerified: data.signatureVerified !== false,
      stale: data.stale === true,
      expiresAt,
    }
  } catch {
    return null
  }
}

/**
 * Get the parsed CRL data for a CA, deduped and session-cached. Returns null on
 * any network/parse failure. Concurrent callers share a single in-flight fetch.
 */
async function getCrlData(ca: CrSinpeCa, fetchFn: typeof fetch): Promise<CrlData | null> {
  const cached = crlCache.get(ca)
  if (cached && Date.now() < cached.expiresAt) return cached

  const pending = inFlight.get(ca)
  if (pending) return pending

  const p = fetchCrlData(ca, fetchFn)
    .then((d) => {
      if (d) crlCache.set(ca, d)
      inFlight.delete(ca)
      return d
    })
    .catch(() => {
      inFlight.delete(ca)
      return null
    })
  inFlight.set(ca, p)
  return p
}

/**
 * Check whether `signerSerialHex` is revoked, via the resolver's CRL endpoint.
 * Never throws. Returns `unreachable` on any network/CORS/parse failure. If the
 * serial is not revoked but the CRL could not be signature-verified or is stale,
 * returns `unknown` rather than falsely asserting `good`. Deduped + cached, so
 * calling it for many cards costs at most one network fetch per CA.
 */
export async function checkRevocationViaResolver(
  ca: CrSinpeCa,
  signerSerialHex: string,
  lang: 'en' | 'es',
  fetchFn: typeof fetch = fetch,
): Promise<ResolverRevocationResult> {
  const es = lang === 'es'
  const checkedAt = new Date().toISOString()
  const target = normSerial(signerSerialHex)

  const data = await getCrlData(ca, fetchFn)
  if (!data) {
    return {
      status: 'unreachable',
      message: es
        ? 'No se pudo contactar el resolver de Attestto desde el navegador.'
        : 'Could not reach the Attestto resolver from the browser.',
      checkedAt,
    }
  }

  if (target && data.revoked.has(target)) {
    return {
      status: 'revoked',
      message: es
        ? 'Revocado: el certificado del firmante figura en la lista de revocación.'
        : 'Revoked: the signer certificate is on the revocation list.',
      checkedAt,
    }
  }

  if (!data.signatureVerified) {
    return {
      status: 'unknown',
      message: es
        ? 'No revocado en la lista, pero no se pudo verificar la firma de la lista.'
        : 'Not on the list, but the list signature could not be verified.',
      checkedAt,
    }
  }
  if (data.stale) {
    return {
      status: 'unknown',
      message: es
        ? 'No revocado, pero la lista de revocación está vencida.'
        : 'Not revoked, but the revocation list is expired.',
      checkedAt,
    }
  }

  return {
    status: 'good',
    message: es
      ? 'No revocado (lista de revocación verificada).'
      : 'Not revoked (verified revocation list).',
    checkedAt,
  }
}

/**
 * Map a signer's issuer common name to the CR SINPE CA slug, or null if the
 * cert is not a CR Firma Digital SINPE certificate (so we fall back to OCSP).
 */
export function crSinpeCaFromIssuer(issuerCommonName: string | null | undefined): CrSinpeCa | null {
  if (!issuerCommonName) return null
  const cn = issuerCommonName.toUpperCase()
  if (!cn.includes('SINPE')) return null
  if (cn.includes('PERSONA FISICA') || cn.includes('PERSONA FÍSICA')) return 'sinpe-persona-fisica'
  if (cn.includes('PERSONA JURIDICA') || cn.includes('PERSONA JURÍDICA')) return 'sinpe-persona-juridica'
  return null
}

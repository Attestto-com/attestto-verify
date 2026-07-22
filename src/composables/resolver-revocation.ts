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
 * This still leaves the device only to reach our resolver — it is opt-in, run
 * only on explicit user action, exactly like the OCSP path.
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

/** Normalize a hex serial for comparison: lowercase, strip non-hex, drop leading zeros. */
function normSerial(s: string): string {
  return s.toLowerCase().replace(/[^0-9a-f]/g, '').replace(/^0+/, '')
}

/**
 * Check whether `signerSerialHex` is revoked, via the resolver's CRL endpoint.
 * Never throws. Returns `unreachable` on any network/CORS/parse failure.
 * If the serial is not revoked but the CRL could not be signature-verified or
 * is stale, returns `unknown` rather than falsely asserting `good`.
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

  try {
    const resp = await fetchFn(`${RESOLVER_BASE}/revocation/cr/${ca}`, {
      method: 'GET',
      headers: { accept: 'application/json' },
    })
    if (!resp.ok) {
      return {
        status: 'unreachable',
        message: es
          ? 'No se pudo obtener la lista de revocación del resolver de Attestto.'
          : 'Could not fetch the revocation list from the Attestto resolver.',
        checkedAt,
      }
    }
    const data = (await resp.json()) as CrlResponse
    const revoked = new Set((data.revokedSerials ?? []).map(normSerial))

    if (target && revoked.has(target)) {
      return {
        status: 'revoked',
        message: es
          ? 'Revocado: el certificado del firmante figura en la lista de revocación.'
          : 'Revoked: the signer certificate is on the revocation list.',
        checkedAt,
      }
    }

    if (data.signatureVerified === false) {
      return {
        status: 'unknown',
        message: es
          ? 'No revocado en la lista, pero no se pudo verificar la firma de la lista.'
          : 'Not on the list, but the list signature could not be verified.',
        checkedAt,
      }
    }
    if (data.stale === true) {
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
  } catch {
    return {
      status: 'unreachable',
      message: es
        ? 'No se pudo contactar el resolver de Attestto desde el navegador.'
        : 'Could not reach the Attestto resolver from the browser.',
      checkedAt,
    }
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

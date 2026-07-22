/**
 * Online OCSP Check — OPT-IN live revocation lookup
 *
 * The default product promise of attestto-verify is that nothing leaves the
 * device: revocation is evaluated ONLY from OCSP/CRL responses embedded in the
 * PDF's /DSS (see `revocation-checker.ts`). This module is the strictly opt-in
 * exception: it fires a LIVE OCSP request over the network, and ONLY when the
 * user explicitly asks for it. Nothing here runs automatically.
 *
 * It builds a proper RFC 6960 OCSPRequest with pkijs (SHA-256 CertID computed
 * from the real issuer cert), POSTs it as `application/ocsp-request`, and parses
 * the OCSPResponse. pkijs is lazy-loaded (~250KB) so the network path costs
 * nothing until the user clicks.
 *
 * CORS reality: many national OCSP responders do NOT send CORS headers, so the
 * browser `fetch` will reject before we ever see a response. We CATCH that and
 * return `status: 'unreachable'` with a plain-language message. We NEVER claim
 * success on failure and NEVER crash the card.
 */

const OCSP_REQUEST_MIME = 'application/ocsp-request'
const OCSP_RESPONSE_MIME = 'application/ocsp-response'
const DEFAULT_TIMEOUT_MS = 8000

export type OnlineOcspStatus = 'good' | 'revoked' | 'unknown' | 'unreachable'

export interface OnlineOcspResult {
  status: OnlineOcspStatus
  /** Plain-language, bilingual-ready message for the card. */
  message: string
  /** ISO timestamp of when the check ran (device clock). */
  checkedAt: string
  /** OCSP responder URL that was contacted (for the advanced/trust view). */
  responderUrl: string
  /** Revocation time, if the responder reported the cert as revoked. */
  revokedAt: string | null
}

// Messages are keyed by locale so the caller can pick without re-deriving
// status semantics. NO em-dashes (commas / parentheses only).
type Lang = 'en' | 'es'

const MSG: Record<OnlineOcspStatus, Record<Lang, string>> = {
  good: {
    en: 'Not revoked. The issuer’s revocation responder confirmed this certificate is currently valid.',
    es: 'No revocado. El servicio de revocación del emisor confirmó que este certificado está vigente.',
  },
  revoked: {
    en: 'Revoked. The issuer’s revocation responder reports this certificate as revoked.',
    es: 'Revocado. El servicio de revocación del emisor reporta este certificado como revocado.',
  },
  unknown: {
    en: 'Unknown. The responder answered but does not have status for this certificate.',
    es: 'Desconocido. El servicio respondió pero no tiene el estado de este certificado.',
  },
  unreachable: {
    en: 'The issuer’s revocation responder could not be reached from the browser (it may block cross-origin requests).',
    es: 'No se pudo contactar el servicio de revocación del emisor desde el navegador (puede bloquear solicitudes de otro origen).',
  },
}

/** Convert a hex string to a fresh ArrayBuffer (for pkijs `fromBER`). */
function hexToArrayBuffer(hex: string): ArrayBuffer {
  const clean = hex.replace(/\s+/g, '')
  const bytes = new Uint8Array(clean.length / 2)
  for (let i = 0; i < clean.length; i += 2) {
    bytes[i / 2] = parseInt(clean.substring(i, i + 2), 16)
  }
  return bytes.buffer
}

/**
 * Perform a LIVE OCSP check for a signer certificate against a responder.
 *
 * @param signerCertDerHex  Hex DER of the signer (end-entity) certificate.
 * @param issuerCertDerHex  Hex DER of the issuing CA certificate (needed to
 *                          compute the CertID issuerNameHash / issuerKeyHash).
 * @param responderUrl      OCSP responder URL (from the cert AIA or the resolver).
 * @param lang              Locale for the human message.
 * @param timeoutMs         Abort after this many ms (default 8000).
 * @returns                 An OnlineOcspResult. NEVER throws.
 */
export async function checkOcspOnline(
  signerCertDerHex: string,
  issuerCertDerHex: string,
  responderUrl: string,
  lang: Lang = 'en',
  timeoutMs = DEFAULT_TIMEOUT_MS,
): Promise<OnlineOcspResult> {
  const checkedAt = new Date().toISOString()
  const unreachable = (extra?: string): OnlineOcspResult => ({
    status: 'unreachable',
    message: MSG.unreachable[lang] + (extra ? ` (${extra})` : ''),
    checkedAt,
    responderUrl,
    revokedAt: null,
  })

  if (!responderUrl || !/^https?:\/\//i.test(responderUrl)) {
    return unreachable(lang === 'es' ? 'sin URL de responder' : 'no responder URL')
  }

  let pkijs: typeof import('pkijs')
  let asn1js: typeof import('asn1js')
  try {
    ;[pkijs, asn1js] = await Promise.all([import('pkijs'), import('asn1js')])
  } catch {
    // Should not happen (both are bundled deps), but never crash the card.
    return unreachable(lang === 'es' ? 'no se pudo cargar el motor cripto' : 'crypto engine unavailable')
  }

  // Build the OCSP request with a real SHA-256 CertID derived from the issuer.
  let requestBytes: Uint8Array
  try {
    const signerCert = pkijs.Certificate.fromBER(hexToArrayBuffer(signerCertDerHex))
    const issuerCert = pkijs.Certificate.fromBER(hexToArrayBuffer(issuerCertDerHex))

    const ocspReq = new pkijs.OCSPRequest()
    await ocspReq.createForCertificate(signerCert, {
      hashAlgorithm: 'SHA-256',
      issuerCertificate: issuerCert,
    })

    requestBytes = new Uint8Array(ocspReq.toSchema(true).toBER())
    // Keep a reference so the unused-import guard is happy and future nonce
    // support has asn1js at hand.
    void asn1js
  } catch (err) {
    const detail = err instanceof Error ? err.message : String(err)
    return {
      status: 'unknown',
      message:
        (lang === 'es'
          ? 'No se pudo construir la solicitud OCSP para este certificado.'
          : 'Could not build the OCSP request for this certificate.') + ` (${detail})`,
      checkedAt,
      responderUrl,
      revokedAt: null,
    }
  }

  // Fire the network request. This is the ONLY place the device talks out.
  let responseBytes: Uint8Array
  try {
    const controller = new AbortController()
    const timer = setTimeout(() => controller.abort(), timeoutMs)
    let resp: Response
    try {
      resp = await fetch(responderUrl, {
        method: 'POST',
        headers: {
          'Content-Type': OCSP_REQUEST_MIME,
          Accept: OCSP_RESPONSE_MIME,
        },
        body: requestBytes as unknown as BodyInit,
        signal: controller.signal,
      })
    } finally {
      clearTimeout(timer)
    }

    if (!resp.ok) {
      return unreachable(
        (lang === 'es' ? 'HTTP ' : 'HTTP ') + resp.status,
      )
    }

    const contentType = resp.headers.get('Content-Type') || ''
    if (contentType && !contentType.toLowerCase().includes('ocsp-response')) {
      // Some CORS proxies / captive portals return HTML with a 200. Treat as
      // unreachable rather than trying to parse garbage as an OCSP response.
      return unreachable(
        lang === 'es' ? 'respuesta no OCSP' : 'non-OCSP response',
      )
    }

    responseBytes = new Uint8Array(await resp.arrayBuffer())
  } catch (err) {
    // Fetch rejections are almost always CORS or network. This is the expected,
    // documented failure mode, NOT a crash.
    const detail = err instanceof Error && err.name === 'AbortError'
      ? lang === 'es' ? 'tiempo agotado' : 'timed out'
      : undefined
    return unreachable(detail)
  }

  // Parse and evaluate the response. pkijs derives status for our exact cert.
  try {
    const respBuffer = responseBytes.buffer.slice(
      responseBytes.byteOffset,
      responseBytes.byteOffset + responseBytes.byteLength,
    ) as ArrayBuffer
    const ocspResp = pkijs.OCSPResponse.fromBER(respBuffer)
    const responseStatus = ocspResp.responseStatus.valueBlock.valueDec
    if (responseStatus !== 0 || !ocspResp.responseBytes) {
      return {
        status: 'unknown',
        message:
          (lang === 'es'
            ? 'El servicio de revocación no devolvió una respuesta exitosa.'
            : 'The revocation responder did not return a successful response.') +
          ` (status ${responseStatus})`,
        checkedAt,
        responderUrl,
        revokedAt: null,
      }
    }

    const signerCert = pkijs.Certificate.fromBER(hexToArrayBuffer(signerCertDerHex))
    const issuerCert = pkijs.Certificate.fromBER(hexToArrayBuffer(issuerCertDerHex))

    const { status } = await ocspResp.getCertificateStatus(signerCert, issuerCert)
    // pkijs status: 0 = good, 1 = revoked, 2 = unknown
    const mapped: OnlineOcspStatus = status === 0 ? 'good' : status === 1 ? 'revoked' : 'unknown'

    return {
      status: mapped,
      message: MSG[mapped][lang],
      checkedAt,
      responderUrl,
      revokedAt: null,
    }
  } catch (err) {
    const detail = err instanceof Error ? err.message : String(err)
    return {
      status: 'unknown',
      message:
        (lang === 'es'
          ? 'El servicio respondió pero la respuesta no se pudo interpretar.'
          : 'The responder answered but the response could not be interpreted.') + ` (${detail})`,
      checkedAt,
      responderUrl,
      revokedAt: null,
    }
  }
}

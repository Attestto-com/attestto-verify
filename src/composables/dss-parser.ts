/**
 * DSS Parser — Document Security Store extraction
 *
 * PAdES B-LT and B-LTA PDFs embed revocation data inside a /DSS dictionary
 * in the document catalog. This module extracts the raw OCSP response and
 * CRL blobs from the /DSS without any network calls.
 *
 * PDF structure:
 *   /DSS <<
 *     /OCSPs [ 10 0 R 11 0 R ]    ← indirect refs to OCSP response streams
 *     /CRLs  [ 12 0 R ]           ← indirect refs to CRL streams
 *     /Certs [ 13 0 R 14 0 R ]    ← indirect refs to cert streams (ignored here)
 *   >>
 *
 * Each indirect object is:
 *   10 0 obj
 *   << /Length NNN >>
 *   stream
 *   ...raw DER bytes...
 *   endstream
 *   endobj
 */

import { logger } from '../logger.js'

const log = logger.verify

export interface DssData {
  /** Raw DER-encoded OCSP responses */
  ocspResponses: Uint8Array[]
  /** Raw DER-encoded CRLs */
  crls: Uint8Array[]
  /** Whether a /DSS dictionary was found at all */
  found: boolean
}

/**
 * Extract DSS (Document Security Store) data from raw PDF bytes.
 * Returns OCSP responses and CRLs as raw DER blobs.
 */
export function extractDss(pdfBytes: Uint8Array): DssData {
  const text = new TextDecoder('latin1').decode(pdfBytes)

  // Find /DSS dictionary
  const dssMatch = /\/DSS\s*<</.exec(text)
  if (!dssMatch) {
    return { ocspResponses: [], crls: [], found: false }
  }

  // Find the closing >> of the DSS dictionary (handle nesting)
  const dssStart = dssMatch.index + dssMatch[0].length - 2 // include <<
  const dssDict = extractDict(text, dssStart)
  if (!dssDict) {
    log.warn('[dss] Found /DSS marker but could not parse dictionary')
    return { ocspResponses: [], crls: [], found: true }
  }

  // Extract indirect object references from /OCSPs array
  const ocspRefs = extractRefArray(dssDict, 'OCSPs')
  const crlRefs = extractRefArray(dssDict, 'CRLs')

  log.info(`[dss] Found DSS: ${ocspRefs.length} OCSP ref(s), ${crlRefs.length} CRL ref(s)`)

  // Resolve each indirect reference to its stream bytes
  const ocspResponses = ocspRefs
    .map((ref) => resolveStreamObject(text, pdfBytes, ref))
    .filter((b): b is Uint8Array => b !== null)

  const crls = crlRefs
    .map((ref) => resolveStreamObject(text, pdfBytes, ref))
    .filter((b): b is Uint8Array => b !== null)

  log.info(`[dss] Resolved: ${ocspResponses.length} OCSP response(s), ${crls.length} CRL(s)`)

  return { ocspResponses, crls, found: true }
}

/**
 * Extract a balanced << ... >> dictionary from text starting at position.
 */
function extractDict(text: string, start: number): string | null {
  if (text[start] !== '<' || text[start + 1] !== '<') return null

  let depth = 0
  for (let i = start; i < text.length - 1; i++) {
    if (text[i] === '<' && text[i + 1] === '<') {
      depth++
      i++
    } else if (text[i] === '>' && text[i + 1] === '>') {
      depth--
      if (depth === 0) {
        return text.substring(start, i + 2)
      }
      i++
    }
  }
  return null
}

/**
 * Extract indirect object references from a named array in a dictionary.
 * e.g. /OCSPs [ 10 0 R 11 0 R ] → [{objNum: 10, genNum: 0}, ...]
 */
function extractRefArray(
  dict: string,
  key: string,
): Array<{ objNum: number; genNum: number }> {
  // Match /Key [ ... ]
  const pattern = new RegExp(`\\/${key}\\s*\\[([^\\]]*)\\]`)
  const match = pattern.exec(dict)
  if (!match) return []

  const refs: Array<{ objNum: number; genNum: number }> = []
  const refPattern = /(\d+)\s+(\d+)\s+R/g
  let refMatch: RegExpExecArray | null
  while ((refMatch = refPattern.exec(match[1])) !== null) {
    refs.push({
      objNum: parseInt(refMatch[1], 10),
      genNum: parseInt(refMatch[2], 10),
    })
  }
  return refs
}

/**
 * Resolve an indirect object reference to its stream bytes.
 * Finds "N G obj ... stream\r?\n...bytes...\r?\nendstream" in the PDF.
 */
function resolveStreamObject(
  text: string,
  bytes: Uint8Array,
  ref: { objNum: number; genNum: number },
): Uint8Array | null {
  // Find the object definition: "N G obj"
  const objPattern = new RegExp(`(?:^|\\n|\\r)${ref.objNum}\\s+${ref.genNum}\\s+obj\\b`)
  const objMatch = objPattern.exec(text)
  if (!objMatch) {
    log.warn(`[dss] Could not find object ${ref.objNum} ${ref.genNum} R`)
    return null
  }

  const objStart = objMatch.index

  // Find /Length in the object's dictionary
  const lengthPattern = /\/Length\s+(\d+)/
  const afterObj = text.substring(objStart, objStart + 500) // look ahead
  const lengthMatch = lengthPattern.exec(afterObj)

  // Find "stream" keyword — content starts after stream\r?\n or stream\n
  const streamKeyword = 'stream'
  const streamIdx = text.indexOf(streamKeyword, objStart)
  if (streamIdx === -1 || streamIdx > objStart + 1000) {
    // No stream — might be a direct object with hex content
    return resolveDirectObject(text, bytes, objStart)
  }

  // Skip past "stream" + EOL (either \r\n or \n)
  let contentStart = streamIdx + streamKeyword.length
  if (bytes[contentStart] === 0x0d && bytes[contentStart + 1] === 0x0a) {
    contentStart += 2
  } else if (bytes[contentStart] === 0x0a) {
    contentStart += 1
  } else if (bytes[contentStart] === 0x0d) {
    contentStart += 1
  }

  // Determine length
  let streamLength: number
  if (lengthMatch) {
    streamLength = parseInt(lengthMatch[1], 10)
  } else {
    // Fallback: find "endstream" and measure
    const endIdx = text.indexOf('endstream', contentStart)
    if (endIdx === -1) return null
    // Trim trailing \r\n before endstream
    let end = endIdx
    if (bytes[end - 1] === 0x0a) end--
    if (bytes[end - 1] === 0x0d) end--
    streamLength = end - contentStart
  }

  if (streamLength <= 0 || contentStart + streamLength > bytes.length) {
    log.warn(`[dss] Invalid stream length for object ${ref.objNum}: ${streamLength}`)
    return null
  }

  return bytes.slice(contentStart, contentStart + streamLength)
}

/**
 * Fallback: resolve a direct object (non-stream) that contains hex data.
 * Some PDFs embed OCSP/CRL as hex strings rather than streams.
 */
function resolveDirectObject(
  text: string,
  _bytes: Uint8Array,
  objStart: number,
): Uint8Array | null {
  // Look for hex string: <hex...>
  const afterObj = text.substring(objStart, objStart + 10000)
  const hexMatch = /<([0-9a-fA-F\s]+)>/.exec(afterObj)
  if (!hexMatch) return null

  const hex = hexMatch[1].replace(/\s/g, '')
  if (hex.length < 10) return null // too short to be meaningful

  const result = new Uint8Array(hex.length / 2)
  for (let i = 0; i < result.length; i++) {
    result[i] = parseInt(hex.substring(i * 2, i * 2 + 2), 16)
  }
  return result
}

/**
 * Minimal ASN.1 DER Parser
 *
 * Parses just enough DER to navigate PKCS#7 SignedData structures
 * and extract X.509 certificate fields. No external dependencies.
 *
 * Supports: SEQUENCE, SET, OID, INTEGER, BIT STRING, OCTET STRING,
 * UTF8String, PrintableString, IA5String, UTCTime, GeneralizedTime,
 * context-specific tags ([0], [1], [3]).
 */

// ── Tag constants ─────────────────────────────────────────────────

export const ASN1_TAG = {
  INTEGER: 0x02,
  BIT_STRING: 0x03,
  OCTET_STRING: 0x04,
  NULL: 0x05,
  OID: 0x06,
  UTF8_STRING: 0x0c,
  PRINTABLE_STRING: 0x13,
  IA5_STRING: 0x16,
  UTC_TIME: 0x17,
  GENERALIZED_TIME: 0x18,
  SEQUENCE: 0x30,
  SET: 0x31,
} as const

// ── ASN.1 Node ────────────────────────────────────────────────────

export interface Asn1Node {
  /** Raw tag byte */
  tag: number
  /** Whether the tag is constructed (contains children) */
  constructed: boolean
  /** Tag class: 0=universal, 1=application, 2=context-specific, 3=private */
  tagClass: number
  /** Tag number (for context-specific: 0, 1, 2, 3...) */
  tagNumber: number
  /** Byte offset where content starts */
  contentOffset: number
  /** Length of content in bytes */
  contentLength: number
  /** Raw content bytes */
  content: Uint8Array
  /** Child nodes (only for constructed types) */
  children: Asn1Node[]
}

// ── Parser ────────────────────────────────────────────────────────

/**
 * Parse a DER-encoded ASN.1 structure.
 * Returns the root node with all children recursively parsed.
 */
export function parseAsn1(data: Uint8Array, offset = 0): Asn1Node {
  if (offset >= data.length) {
    throw new Error(`ASN.1: offset ${offset} beyond data length ${data.length}`)
  }

  const tag = data[offset]
  const constructed = (tag & 0x20) !== 0
  const tagClass = (tag >> 6) & 0x03
  const tagNumber = tag & 0x1f

  // Parse length
  const { length, bytesRead } = parseLength(data, offset + 1)
  const contentOffset = offset + 1 + bytesRead
  const content = data.subarray(contentOffset, contentOffset + length)

  // Parse children for constructed types
  const children: Asn1Node[] = []
  if (constructed && length > 0) {
    let pos = contentOffset
    const endPos = contentOffset + length
    while (pos < endPos) {
      const child = parseAsn1(data, pos)
      children.push(child)
      const childTotalSize = (child.contentOffset - pos) + child.contentLength
      if (childTotalSize <= 0) break // safety: prevent infinite loop
      pos += childTotalSize
    }
  }

  return {
    tag,
    constructed,
    tagClass,
    tagNumber,
    contentOffset,
    contentLength: length,
    content,
    children,
  }
}

/**
 * Parse all top-level nodes from a byte range (for parsing certificate sets).
 */
export function parseAsn1All(data: Uint8Array): Asn1Node[] {
  const nodes: Asn1Node[] = []
  let offset = 0
  while (offset < data.length) {
    const node = parseAsn1(data, offset)
    nodes.push(node)
    const headerSize = node.contentOffset - offset
    offset += headerSize + node.contentLength
    // Fix: parseAsn1 returns contentOffset relative to the passed data's start in memory
    // We need to recalculate based on the subarray
    break // For top-level, parse one at a time
  }
  return nodes
}

/**
 * Parse DER length encoding.
 * Short form: single byte < 0x80
 * Long form: first byte = 0x80 + N, next N bytes = length
 */
function parseLength(data: Uint8Array, offset: number): { length: number; bytesRead: number } {
  const first = data[offset]
  if (first < 0x80) {
    return { length: first, bytesRead: 1 }
  }

  const numBytes = first & 0x7f
  if (numBytes === 0) {
    // Indefinite length — not valid in DER, but handle gracefully
    return { length: 0, bytesRead: 1 }
  }

  let length = 0
  for (let i = 0; i < numBytes; i++) {
    length = (length << 8) | data[offset + 1 + i]
  }
  return { length, bytesRead: 1 + numBytes }
}

// ── Value extractors ──────────────────────────────────────────────

/** Decode an OID from DER bytes to dotted string (e.g. "1.2.840.113549.1.7.2") */
export function decodeOid(content: Uint8Array): string {
  if (content.length === 0) return ''

  // First byte encodes first two components: value = 40 * first + second
  const first = Math.floor(content[0] / 40)
  const second = content[0] % 40
  const parts: number[] = [first, second]

  let value = 0
  for (let i = 1; i < content.length; i++) {
    value = (value << 7) | (content[i] & 0x7f)
    if ((content[i] & 0x80) === 0) {
      parts.push(value)
      value = 0
    }
  }

  return parts.join('.')
}

/** Decode a string value (UTF8String, PrintableString, IA5String) */
export function decodeString(node: Asn1Node): string {
  const tag = node.tag & 0x1f
  if (
    tag === ASN1_TAG.UTF8_STRING ||
    tag === ASN1_TAG.PRINTABLE_STRING ||
    tag === ASN1_TAG.IA5_STRING ||
    node.tag === ASN1_TAG.UTF8_STRING ||
    node.tag === ASN1_TAG.PRINTABLE_STRING ||
    node.tag === ASN1_TAG.IA5_STRING
  ) {
    return new TextDecoder('utf-8').decode(node.content)
  }
  // BMPString (0x1E) — UTF-16BE
  if (node.tag === 0x1e) {
    const u16 = new Uint16Array(node.contentLength / 2)
    for (let i = 0; i < u16.length; i++) {
      u16[i] = (node.content[i * 2] << 8) | node.content[i * 2 + 1]
    }
    return String.fromCharCode(...u16)
  }
  return new TextDecoder('latin1').decode(node.content)
}

/** Decode UTCTime or GeneralizedTime to ISO string */
export function decodeTime(node: Asn1Node): string {
  const raw = new TextDecoder('ascii').decode(node.content)
  if (node.tag === ASN1_TAG.UTC_TIME) {
    // YYMMDDHHmmSSZ — 2-digit year
    const yy = parseInt(raw.substring(0, 2))
    const year = yy >= 50 ? 1900 + yy : 2000 + yy
    return `${year}-${raw.substring(2, 4)}-${raw.substring(4, 6)}T${raw.substring(6, 8)}:${raw.substring(8, 10)}:${raw.substring(10, 12)}Z`
  }
  // GeneralizedTime: YYYYMMDDHHmmSSZ
  return `${raw.substring(0, 4)}-${raw.substring(4, 6)}-${raw.substring(6, 8)}T${raw.substring(8, 10)}:${raw.substring(10, 12)}:${raw.substring(12, 14)}Z`
}

/** Decode INTEGER to hex string (for serial numbers) */
export function decodeInteger(node: Asn1Node): string {
  return Array.from(node.content)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('')
}

/** Find a child node by tag */
export function findChild(node: Asn1Node, tag: number): Asn1Node | undefined {
  return node.children.find((c) => c.tag === tag)
}

/** Find a child by context-specific tag number (e.g. [0], [3]) */
export function findContext(node: Asn1Node, tagNumber: number): Asn1Node | undefined {
  return node.children.find((c) => c.tagClass === 2 && c.tagNumber === tagNumber)
}

/**
 * PDF Verification — Client-Side
 *
 * Extracts SHA-256 hash, metadata, and PAdES/PKCS#7 digital signatures
 * from a PDF file. Runs entirely in the browser — the file never leaves
 * the device.
 */

export interface PdfMetadata {
  title: string | null
  author: string | null
  subject: string | null
  creator: string | null
  producer: string | null
  creationDate: string | null
  modDate: string | null
}

export interface PdfSignatureInfo {
  name: string
  reason: string | null
  location: string | null
  contactInfo: string | null
  signDate: string | null
}

export interface PdfVerificationResult {
  fileName: string
  fileSize: number
  hash: string
  isPdf: boolean
  metadata: PdfMetadata | null
  signatures: PdfSignatureInfo[]
}

/** Compute SHA-256 hash of raw bytes */
export async function computeHash(buffer: ArrayBuffer): Promise<string> {
  const hashBuffer = await crypto.subtle.digest('SHA-256', buffer)
  const hashArray = Array.from(new Uint8Array(hashBuffer))
  return hashArray.map((b) => b.toString(16).padStart(2, '0')).join('')
}

/** Parse PDF date string (D:YYYYMMDDHHmmSS) to ISO string */
function formatPdfDate(raw: string): string | null {
  if (!raw) return null
  try {
    const cleaned = raw.replace(/^D:/, '')
    const year = cleaned.substring(0, 4)
    const month = cleaned.substring(4, 6) || '01'
    const day = cleaned.substring(6, 8) || '01'
    const hour = cleaned.substring(8, 10) || '00'
    const min = cleaned.substring(10, 12) || '00'
    const sec = cleaned.substring(12, 14) || '00'
    return new Date(`${year}-${month}-${day}T${hour}:${min}:${sec}Z`).toISOString()
  } catch {
    return raw
  }
}

/**
 * Extract digital signature fields by scanning PDF bytes for /Type /Sig dictionaries.
 *
 * The /Contents field contains a massive hex blob (the PKCS#7 signature),
 * so we strip it before extracting fields. We also need to find the full
 * dictionary boundary (matching << ... >>) rather than using fixed offsets.
 */
function extractSignaturesFromBytes(bytes: Uint8Array): PdfSignatureInfo[] {
  const sigs: PdfSignatureInfo[] = []
  const text = new TextDecoder('latin1').decode(bytes)

  // Find all /Type /Sig dictionaries
  const sigPattern = /\/Type\s*\/Sig\b/g
  let match: RegExpExecArray | null

  while ((match = sigPattern.exec(text)) !== null) {
    // Walk backwards to find the opening << of this dictionary
    let dictStart = match.index
    let depth = 0
    for (let i = match.index; i >= 0; i--) {
      if (text[i] === '>' && text[i - 1] === '>') { depth++; i-- }
      if (text[i] === '<' && text[i - 1] === '<') {
        if (depth === 0) { dictStart = i - 1; break }
        depth--
        i--
      }
    }

    // Walk forwards to find the closing >> of this dictionary
    let dictEnd = text.length
    depth = 0
    for (let i = dictStart; i < text.length - 1; i++) {
      if (text[i] === '<' && text[i + 1] === '<') { depth++; i++ }
      if (text[i] === '>' && text[i + 1] === '>') {
        depth--
        if (depth === 0) { dictEnd = i + 2; break }
        i++
      }
    }

    // Get the full dictionary, then strip /Contents hex blob to make regex work
    const rawDict = text.substring(dictStart, dictEnd)
    const dict = rawDict.replace(/\/Contents\s*<[0-9a-fA-F\s]*>/g, '')

    // Extract parenthesized string values — handles nested parens via balanced match
    const getField = (key: string): string | null => {
      // Match /Key followed by a parenthesized string (not /Key /Name which is a name object)
      const re = new RegExp(`\\/${key}\\s*\\(`)
      const m = re.exec(dict)
      if (!m) return null

      // Extract balanced parentheses content
      let start = m.index + m[0].length
      let depth = 1
      let end = start
      while (end < dict.length && depth > 0) {
        if (dict[end] === '(' && dict[end - 1] !== '\\') depth++
        if (dict[end] === ')' && dict[end - 1] !== '\\') depth--
        if (depth > 0) end++
      }
      return dict.substring(start, end)
    }

    const name = getField('Name') || 'Unknown Signer'
    sigs.push({
      name,
      reason: getField('Reason'),
      location: getField('Location'),
      contactInfo: getField('ContactInfo'),
      signDate: getField('M') ? formatPdfDate(getField('M')!) : null,
    })
  }

  return sigs
}

/** Full client-side PDF verification */
export async function verifyPdf(file: File): Promise<PdfVerificationResult> {
  const buffer = await file.arrayBuffer()
  const hash = await computeHash(buffer)
  const isPdf = file.name.toLowerCase().endsWith('.pdf')

  let metadata: PdfMetadata | null = null
  let signatures: PdfSignatureInfo[] = []

  if (isPdf) {
    // Extract signatures from raw bytes (no external dependency)
    signatures = extractSignaturesFromBytes(new Uint8Array(buffer))

    // Try pdfjs-dist for metadata (lazy-loaded)
    try {
      const { getDocument, GlobalWorkerOptions } = await import('pdfjs-dist')
      GlobalWorkerOptions.workerSrc = new URL(
        'pdfjs-dist/build/pdf.worker.min.mjs',
        import.meta.url
      ).toString()

      const pdf = await getDocument({ data: buffer }).promise
      const meta = await pdf.getMetadata()
      const info = meta?.info as Record<string, unknown> | undefined

      if (info) {
        metadata = {
          title: (info.Title as string) || null,
          author: (info.Author as string) || null,
          subject: (info.Subject as string) || null,
          creator: (info.Creator as string) || null,
          producer: (info.Producer as string) || null,
          creationDate: info.CreationDate ? formatPdfDate(info.CreationDate as string) : null,
          modDate: info.ModDate ? formatPdfDate(info.ModDate as string) : null,
        }
      }
    } catch {
      // pdfjs-dist not available — signatures still extracted from raw bytes
    }
  }

  return {
    fileName: file.name,
    fileSize: file.size,
    hash,
    isPdf,
    metadata,
    signatures,
  }
}

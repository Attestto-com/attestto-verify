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
  /** Verification level achieved — v1 = 'detected', v2 will upgrade */
  level: 'detected' | 'parsed' | 'signed' | 'trusted' | 'qualified'
  /** DID URI extracted from cert SubjectAltName (v2) */
  did: string | null
  /** LEI code from cert serialNumber (v2) */
  lei: string | null
  /** Organization from cert O field (v2) */
  organization: string | null
  /** SubFilter from PDF signature dictionary */
  subFilter: string | null
}

/** Forensic audit data extracted from raw PDF bytes — zero network calls */
export interface PdfAuditInfo {
  /** PDF version from header (e.g. "1.7", "2.0") */
  pdfVersion: string | null
  /** Number of pages */
  pageCount: number | null
  /** Encryption detected */
  encrypted: boolean
  /** Encryption algorithm if detected */
  encryptionAlgorithm: string | null
  /** JavaScript objects found (/JS or /JavaScript) */
  hasJavaScript: boolean
  /** Count of JS objects */
  javaScriptCount: number
  /** Auto-open actions (/OpenAction) */
  hasOpenAction: boolean
  /** Embedded files (/EmbeddedFile) */
  embeddedFileCount: number
  /** External links (URI actions) */
  externalLinkCount: number
  /** ByteRange arrays from signature dictionaries */
  byteRanges: number[][]
  /** Has LTV data (/DSS dictionary) for offline revocation */
  hasLtvData: boolean
  /** Linearized (web-optimized) */
  linearized: boolean
}

export interface PdfVerificationResult {
  fileName: string
  fileSize: number
  hash: string
  isPdf: boolean
  metadata: PdfMetadata | null
  signatures: PdfSignatureInfo[]
  /** Forensic audit — security scan results */
  audit: PdfAuditInfo | null
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

    // Extract /SubFilter as a name object (e.g. /SubFilter /adbe.pkcs7.detached)
    const getNameField = (key: string): string | null => {
      const re = new RegExp(`\\/${key}\\s*\\/([\\w.]+)`)
      const m = re.exec(dict)
      return m ? m[1] : null
    }

    const name = getField('Name') || 'Unknown Signer'
    sigs.push({
      name,
      reason: getField('Reason'),
      location: getField('Location'),
      contactInfo: getField('ContactInfo'),
      signDate: getField('M') ? formatPdfDate(getField('M')!) : null,
      level: 'detected', // v1 = byte scan only; v2 (ATT-209) will upgrade to 'signed'/'trusted'
      did: null,          // v2: extracted from cert SubjectAltName
      lei: null,          // v2: extracted from cert serialNumber
      organization: null, // v2: extracted from cert O field
      subFilter: getNameField('SubFilter'),
    })
  }

  return sigs
}

/**
 * Forensic security scan — extracts audit-relevant properties from raw PDF bytes.
 * Zero dependencies, zero network calls. Runs in < 1ms for typical documents.
 */
function scanPdfAudit(bytes: Uint8Array, text: string): PdfAuditInfo {
  // PDF version from header (%PDF-X.Y)
  const versionMatch = text.match(/%PDF-(\d+\.\d+)/)
  const pdfVersion = versionMatch ? versionMatch[1] : null

  // Page count from /Type /Page (not /Pages)
  const pageMatches = text.match(/\/Type\s*\/Page\b(?!s)/g)
  const pageCount = pageMatches ? pageMatches.length : null

  // Encryption detection (/Encrypt dictionary reference)
  const encrypted = /\/Encrypt\s/.test(text)
  let encryptionAlgorithm: string | null = null
  if (encrypted) {
    if (/\/AESV3\b/.test(text)) encryptionAlgorithm = 'AES-256'
    else if (/\/AESV2\b/.test(text)) encryptionAlgorithm = 'AES-128'
    else if (/\/V\s+4\b/.test(text)) encryptionAlgorithm = 'AES-128'
    else if (/\/V\s+[12]\b/.test(text)) encryptionAlgorithm = 'RC4'
    else encryptionAlgorithm = 'Unknown'
  }

  // JavaScript detection (/JS or /JavaScript)
  const jsMatches = text.match(/\/JS\s|\/JavaScript\s/g)
  const hasJavaScript = (jsMatches?.length ?? 0) > 0
  const javaScriptCount = jsMatches?.length ?? 0

  // OpenAction detection
  const hasOpenAction = /\/OpenAction\s/.test(text)

  // Embedded files
  const embeddedMatches = text.match(/\/EmbeddedFile\b/g)
  const embeddedFileCount = embeddedMatches?.length ?? 0

  // External links (URI actions)
  const uriMatches = text.match(/\/URI\s*\(/g)
  const externalLinkCount = uriMatches?.length ?? 0

  // ByteRange arrays from signatures
  const byteRanges: number[][] = []
  const brPattern = /\/ByteRange\s*\[\s*(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s*\]/g
  let brMatch: RegExpExecArray | null
  while ((brMatch = brPattern.exec(text)) !== null) {
    byteRanges.push([
      parseInt(brMatch[1]),
      parseInt(brMatch[2]),
      parseInt(brMatch[3]),
      parseInt(brMatch[4]),
    ])
  }

  // LTV data (/DSS dictionary)
  const hasLtvData = /\/DSS\s*<</.test(text)

  // Linearized (web-optimized)
  const linearized = /\/Linearized\s/.test(text)

  return {
    pdfVersion,
    pageCount,
    encrypted,
    encryptionAlgorithm,
    hasJavaScript,
    javaScriptCount,
    hasOpenAction,
    embeddedFileCount,
    externalLinkCount,
    byteRanges,
    hasLtvData,
    linearized,
  }
}

/** Full client-side PDF verification */
export async function verifyPdf(file: File): Promise<PdfVerificationResult> {
  const buffer = await file.arrayBuffer()
  const hash = await computeHash(buffer)
  const isPdf = file.name.toLowerCase().endsWith('.pdf')

  let metadata: PdfMetadata | null = null
  let signatures: PdfSignatureInfo[] = []
  let audit: PdfAuditInfo | null = null

  if (isPdf) {
    const pdfBytes = new Uint8Array(buffer)
    const pdfText = new TextDecoder('latin1').decode(pdfBytes)

    // Extract signatures from raw bytes (no external dependency)
    signatures = extractSignaturesFromBytes(pdfBytes)

    // Forensic security scan
    audit = scanPdfAudit(pdfBytes, pdfText)

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
    audit,
  }
}

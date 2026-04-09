/**
 * PDF Verification — Client-Side
 *
 * Extracts SHA-256 hash, metadata, and PAdES/PKCS#7 digital signatures
 * from a PDF file. Runs entirely in the browser — the file never leaves
 * the device.
 */

import { logger } from '../logger.js'
import {
  extractPkcs7Hex,
  parseCertificateChain,
  cleanSignerName,
  type CertificateChainResult,
} from './certificate-parser.js'
import { verifyDocumentIntegrity, reconstructSignedBytes } from './chain-validator.js'

const log = logger.verify

// ── CDN Lazy Loader for pdfjs-dist ────────────────────────────────

const PDFJS_VERSION = '4.9.155'
const PDFJS_CDN = `https://cdnjs.cloudflare.com/ajax/libs/pdf.js/${PDFJS_VERSION}`

// eslint-disable-next-line @typescript-eslint/no-explicit-any
let pdfjsCache: any = null
let pdfjsLoading: Promise<unknown> | null = null

/**
 * Load pdfjs-dist from CDN. Cached after first load.
 * Returns the pdfjsLib global, or null if loading fails.
 */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
export async function loadPdfJs(onProgress?: VerifyProgressCallback): Promise<any> {
  // Already loaded
  if (pdfjsCache) return pdfjsCache

  // Check if running in Node (tests) — skip CDN loading
  if (typeof window === 'undefined') return null

  // Already loading (concurrent calls)
  if (pdfjsLoading) {
    await pdfjsLoading
    return pdfjsCache
  }

  onProgress?.('loading-pdfjs', 'Loading PDF engine from CDN...')
  log.info('[cdn] Loading pdfjs-dist from CDN (first time only)')

  pdfjsLoading = new Promise<void>((resolve, reject) => {
    const script = document.createElement('script')
    script.src = `${PDFJS_CDN}/pdf.min.mjs`
    script.type = 'module'

    // For module scripts, we need a different approach — use dynamic import
    script.remove()

    // Use dynamic import from CDN
    const moduleScript = document.createElement('script')
    moduleScript.type = 'module'
    moduleScript.textContent = `
      import * as pdfjsLib from '${PDFJS_CDN}/pdf.min.mjs';
      pdfjsLib.GlobalWorkerOptions.workerSrc = '${PDFJS_CDN}/pdf.worker.min.mjs';
      window.__pdfjsLib = pdfjsLib;
      window.dispatchEvent(new Event('pdfjs-loaded'));
    `

    const onLoad = () => {
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      pdfjsCache = (window as any).__pdfjsLib
      window.removeEventListener('pdfjs-loaded', onLoad)
      if (pdfjsCache) {
        log.event('[cdn] pdfjs-dist loaded and cached')
        onProgress?.('pdfjs-ready', 'PDF engine ready')
        resolve()
      } else {
        reject(new Error('pdfjs-dist module did not expose __pdfjsLib'))
      }
    }

    window.addEventListener('pdfjs-loaded', onLoad)
    // Timeout after 15s
    setTimeout(() => {
      window.removeEventListener('pdfjs-loaded', onLoad)
      if (!pdfjsCache) {
        log.warn('[cdn] pdfjs-dist load timed out after 15s')
        resolve() // Don't reject — graceful degradation
      }
    }, 15_000)

    document.head.appendChild(moduleScript)
  })

  try {
    await pdfjsLoading
  } catch (e) {
    log.warn(`[cdn] Failed to load pdfjs-dist: ${e}`)
  } finally {
    pdfjsLoading = null
  }

  return pdfjsCache
}

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
  /**
   * Verification level achieved.
   *   - 'detected'  → signature dictionary present, no certs parsed
   *   - 'parsed'    → certs parsed, chain NOT cryptographically verified
   *   - 'verified'  → chain cryptographically verified AND document content matches signature (post-ATT-309)
   *   - 'tampered'  → chain may be valid but document content was modified after signing — DO NOT TRUST
   *   - 'signed'    → legacy alias, retained for backward compatibility
   *   - 'trusted'   → plugin-elevated (e.g. did-verifier matched)
   *   - 'qualified' → plugin-elevated (e.g. vLEI / GLEIF tier)
   */
  level: 'detected' | 'parsed' | 'verified' | 'tampered' | 'signed' | 'trusted' | 'qualified'
  /**
   * True iff the bytes covered by the signature's ByteRange hash to the
   * exact value the signer signed (Phase A — document integrity check).
   * `null` when no signature was checked.
   */
  documentIntegrityVerified: boolean | null
  /** Reason integrity verification failed, if any */
  integrityError: string | null
  /** DID URI extracted from cert SubjectAltName (v2) */
  did: string | null
  /** LEI code from cert serialNumber (v2) */
  lei: string | null
  /** Organization from cert O field (v2) */
  organization: string | null
  /** SubFilter from PDF signature dictionary */
  subFilter: string | null
  /** Certificate chain extracted from PKCS#7 (v1.5) */
  certChain: CertificateChainResult | null
  /**
   * Raw PKCS#7 (CMS SignedData) hex blob from the signature dictionary's
   * /Contents field. Exposed so downstream consumers (e.g. the desktop's
   * BCCR trust validator) can re-run validation against their own trust
   * stores without re-parsing the PDF. `null` when no PKCS#7 was extracted.
   */
  pkcs7Hex: string | null
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
export function formatPdfDate(raw: string): string | null {
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
async function extractSignaturesFromBytes(bytes: Uint8Array): Promise<PdfSignatureInfo[]> {
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
      if (text[i] === '>' && text[i - 1] === '>') {
        depth++
        i--
      }
      if (text[i] === '<' && text[i - 1] === '<') {
        if (depth === 0) {
          dictStart = i - 1
          break
        }
        depth--
        i--
      }
    }

    // Walk forwards to find the closing >> of this dictionary
    let dictEnd = text.length
    depth = 0
    for (let i = dictStart; i < text.length - 1; i++) {
      if (text[i] === '<' && text[i + 1] === '<') {
        depth++
        i++
      }
      if (text[i] === '>' && text[i + 1] === '>') {
        depth--
        if (depth === 0) {
          dictEnd = i + 2
          break
        }
        i++
      }
    }

    // Get the full dictionary — capture /Contents hex blob before stripping
    const rawDict = text.substring(dictStart, dictEnd)
    const pkcs7Hex = extractPkcs7Hex(text, dictStart, dictEnd)
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

    // Parse certificate chain from PKCS#7 blob (now async — runs real
    // cryptographic chain validation against bundled BCCR trust anchors)
    let certChain: CertificateChainResult | null = null
    if (pkcs7Hex) {
      certChain = await parseCertificateChain(pkcs7Hex)
    }

    // Phase A (ATT-309) — Document integrity check.
    // Even if the certificate chain is valid, if a single byte of the document
    // was modified after signing, the signature must NOT be trusted.
    // We extract the ByteRange from THIS signature dictionary (each signature
    // has its own ByteRange), reconstruct the bytes that were actually signed,
    // and run pkijs.SignedData.verify() against them.
    let documentIntegrityVerified: boolean | null = null
    let integrityError: string | null = null
    if (pkcs7Hex) {
      const brMatch = /\/ByteRange\s*\[\s*(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s*\]/.exec(rawDict)
      if (brMatch) {
        const byteRange: [number, number, number, number] = [
          parseInt(brMatch[1], 10),
          parseInt(brMatch[2], 10),
          parseInt(brMatch[3], 10),
          parseInt(brMatch[4], 10),
        ]
        try {
          const signedBytes = reconstructSignedBytes(bytes, byteRange)
          // Copy into a fresh ArrayBuffer so pkijs gets a contiguous view
          // and the type system gets a plain ArrayBuffer (not SharedArrayBuffer).
          const signedBuffer = new ArrayBuffer(signedBytes.byteLength)
          new Uint8Array(signedBuffer).set(signedBytes)
          const integrity = await verifyDocumentIntegrity(pkcs7Hex, signedBuffer)
          documentIntegrityVerified = integrity.integrityValid
          integrityError = integrity.error
        } catch (err) {
          documentIntegrityVerified = false
          integrityError = err instanceof Error ? err.message : String(err)
        }
      } else {
        // No ByteRange found — cannot verify integrity. Mark as failed
        // because we cannot prove the document is the original.
        documentIntegrityVerified = false
        integrityError = 'No ByteRange found in signature dictionary'
      }
    }

    // Use cert data to enrich signature info
    const rawName = getField('Name') || 'Unknown Signer'
    const displayName = certChain?.signerDisplayName || cleanSignerName(rawName)
    // Level escalation rules (post-ATT-309):
    //   - 'detected'  → no certs found
    //   - 'parsed'    → certs found but chain NOT cryptographically verified
    //   - 'tampered'  → chain may be parsed/verified, but document was modified after signing
    //   - 'verified'  → chain cryptographically verified AND document integrity intact
    // Plugins may further escalate (e.g. did-verifier → 'trusted', vLEI → 'qualified').
    let level: 'detected' | 'parsed' | 'verified' | 'tampered' = 'detected'
    if (certChain && certChain.certificates.length > 0) {
      if (documentIntegrityVerified === false) {
        level = 'tampered'
      } else if (certChain.cryptographicallyVerified && documentIntegrityVerified === true) {
        level = 'verified'
      } else {
        level = 'parsed'
      }
    }

    sigs.push({
      name: displayName,
      reason: getField('Reason'),
      location: getField('Location'),
      contactInfo: getField('ContactInfo'),
      signDate: getField('M') ? formatPdfDate(getField('M')!) : null,
      level,
      did: certChain?.signer?.subjectAltNames.find((s) => s.startsWith('did:')) || null,
      lei: null, // v2: extracted from cert or vLEI
      organization: certChain?.signer?.organization || null,
      subFilter: getNameField('SubFilter'),
      certChain,
      pkcs7Hex: pkcs7Hex ?? null,
      documentIntegrityVerified,
      integrityError,
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

/** Progress callback for lazy-loading status */
export type VerifyProgressCallback = (step: string, detail?: string) => void

/** Full client-side PDF verification */
export async function verifyPdf(
  file: File,
  onProgress?: VerifyProgressCallback,
): Promise<PdfVerificationResult> {
  log.info(`[1/4] Reading "${file.name}" (${file.size} bytes)`)
  const buffer = await file.arrayBuffer()
  const hash = await computeHash(buffer)
  log.info(`[2/4] SHA-256: ${hash}`)
  const isPdf = file.name.toLowerCase().endsWith('.pdf')

  let metadata: PdfMetadata | null = null
  let signatures: PdfSignatureInfo[] = []
  let audit: PdfAuditInfo | null = null

  if (isPdf) {
    const pdfBytes = new Uint8Array(buffer)
    const pdfText = new TextDecoder('latin1').decode(pdfBytes)

    // Extract signatures from raw bytes (no external dependency)
    signatures = await extractSignaturesFromBytes(pdfBytes)
    log.info(
      `[3/4] PAdES scan: ${signatures.length} signature${signatures.length !== 1 ? 's' : ''} found${signatures.length > 0 ? ' — ' + signatures.map((s) => s.name).join(', ') : ''}`,
    )

    // Forensic security scan
    audit = scanPdfAudit(pdfBytes, pdfText)
    log.info(
      `[3/4] Forensic audit: PDF ${audit.pdfVersion || '?'}, JS=${audit.hasJavaScript ? 'YES' : 'no'}, OpenAction=${audit.hasOpenAction ? 'YES' : 'no'}, Encrypted=${audit.encrypted ? 'YES' : 'no'}`,
    )

    // Load pdfjs-dist from CDN (lazy, cached) for metadata extraction
    try {
      const pdfjsLib = await loadPdfJs(onProgress)
      if (pdfjsLib) {
        const pdf = await pdfjsLib.getDocument({ data: buffer }).promise
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
      }
    } catch {
      // pdfjs-dist not available — signatures still extracted from raw bytes
    }
  }

  log.event(
    `[4/4] Verification complete — ${signatures.length} signature(s), ${audit?.hasJavaScript ? 'JS detected' : 'clean'}`,
  )

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

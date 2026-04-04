/**
 * PDF Attestation Page — Injects a signature attestation page into a PDF.
 *
 * Uses pdf-lib (client-side, zero backend). The attestation page contains:
 * - Attestto branding
 * - Signer DID
 * - Document hash (SHA-256)
 * - Signature timestamp
 * - Verification URL
 * - Original document metadata
 *
 * The page is appended as the last page of the PDF.
 */

import { PDFDocument, rgb, StandardFonts } from 'pdf-lib'
import type { DocumentSignatureCredential } from './document-signer.js'

interface AttestationOptions {
  credential: DocumentSignatureCredential
  originalFileName: string
  signerName?: string
}

/**
 * Inject an attestation page into a PDF and return the modified bytes.
 */
export async function injectAttestationPage(
  pdfBytes: ArrayBuffer,
  options: AttestationOptions,
): Promise<Uint8Array> {
  const pdfDoc = await PDFDocument.load(pdfBytes)
  const page = pdfDoc.addPage()
  const { width, height } = page.getSize()

  const helvetica = await pdfDoc.embedFont(StandardFonts.Helvetica)
  const helveticaBold = await pdfDoc.embedFont(StandardFonts.HelveticaBold)

  const { credential, originalFileName, signerName } = options
  const subject = credential.credentialSubject
  const proof = credential.proof

  const margin = 50
  let y = height - margin

  // ── Header ──
  const brandColor = rgb(0.349, 0.31, 0.827) // #594FD3

  page.drawRectangle({
    x: 0,
    y: height - 80,
    width,
    height: 80,
    color: rgb(0.059, 0.059, 0.102), // #0f0f1a
  })

  page.drawText('ATTESTTO', {
    x: margin,
    y: height - 35,
    size: 20,
    font: helveticaBold,
    color: rgb(1, 1, 1),
  })

  page.drawText('Document Signature Attestation', {
    x: margin,
    y: height - 55,
    size: 11,
    font: helvetica,
    color: rgb(0.58, 0.64, 0.72), // #94a3b8
  })

  y = height - 110

  // ── Status Badge ──
  page.drawRectangle({
    x: margin,
    y: y - 5,
    width: 180,
    height: 28,
    color: rgb(0.02, 0.18, 0.09), // dark green bg
    borderColor: rgb(0.086, 0.639, 0.247),
    borderWidth: 1,
  })

  page.drawText('DIGITALLY SIGNED', {
    x: margin + 12,
    y: y + 2,
    size: 12,
    font: helveticaBold,
    color: rgb(0.29, 0.85, 0.5), // #4ade80
  })

  y -= 50

  // ── Document Info Section ──
  const drawSection = (title: string) => {
    page.drawText(title, {
      x: margin,
      y,
      size: 9,
      font: helveticaBold,
      color: rgb(0.58, 0.64, 0.72),
    })
    y -= 18
  }

  const drawRow = (label: string, value: string, mono = false) => {
    page.drawText(label, {
      x: margin,
      y,
      size: 10,
      font: helveticaBold,
      color: rgb(0.39, 0.45, 0.53), // #64748b
    })

    // Truncate long values
    const maxChars = mono ? 60 : 70
    const displayValue = value.length > maxChars ? value.slice(0, maxChars) + '...' : value

    page.drawText(displayValue, {
      x: margin + 120,
      y,
      size: mono ? 9 : 10,
      font: helvetica,
      color: rgb(0.886, 0.91, 0.94), // #e2e8f0
    })
    y -= 18
  }

  // Background for content area
  page.drawRectangle({
    x: margin - 10,
    y: 40,
    width: width - 2 * margin + 20,
    height: y - 20,
    color: rgb(0.082, 0.098, 0.153), // #151825
  })

  drawSection('DOCUMENT')
  drawRow('Filename', originalFileName)
  drawRow('File Size', `${(subject.document.size / 1024).toFixed(1)} KB`)
  drawRow('SHA-256', subject.document.hash, true)
  y -= 8

  drawSection('SIGNER')
  if (signerName) drawRow('Name', signerName)
  drawRow('DID', credential.issuer, true)
  drawRow('Method', proof.type)
  y -= 8

  drawSection('SIGNATURE')
  drawRow('Created', proof.created)
  drawRow('Proof', proof.proofValue.slice(0, 44) + '...', true)
  y -= 8

  drawSection('VERIFICATION')
  drawRow('Verify URL', subject.verifyUrl)
  drawRow('Standard', 'W3C Verifiable Credential v1')
  y -= 20

  // ── Separator ──
  page.drawLine({
    start: { x: margin, y },
    end: { x: width - margin, y },
    thickness: 0.5,
    color: rgb(0.118, 0.161, 0.212), // #1e293b
  })
  y -= 20

  // ── Privacy notice ──
  page.drawText('This attestation was generated 100% client-side. No document data was transmitted.', {
    x: margin,
    y,
    size: 8,
    font: helvetica,
    color: rgb(0.39, 0.45, 0.53),
  })
  y -= 14

  page.drawText(`verify.attestto.com — Open source under Apache 2.0`, {
    x: margin,
    y,
    size: 8,
    font: helvetica,
    color: brandColor,
  })

  return pdfDoc.save()
}

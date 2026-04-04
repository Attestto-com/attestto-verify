/**
 * PDF Attestation Page — Injects a signature attestation page into a PDF.
 *
 * Uses pdf-lib (client-side, zero backend). The attestation page contains:
 * - Attestto branding header (purple)
 * - Signer DID, document hash, timestamp, verification URL
 * - White background for print/standard viewing
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

  // Colors — white background, dark text, purple brand
  const brand = rgb(0.349, 0.31, 0.827)    // #594FD3
  const textDark = rgb(0.06, 0.09, 0.16)   // #0f172a
  const textMuted = rgb(0.39, 0.45, 0.53)  // #64748b
  const borderLight = rgb(0.88, 0.91, 0.94) // #e2e8f0
  const greenDark = rgb(0.086, 0.639, 0.247) // #16a34a
  const greenBg = rgb(0.86, 0.99, 0.91)    // #dcfce7

  // ── Header bar (purple) ──
  page.drawRectangle({
    x: 0,
    y: height - 70,
    width,
    height: 70,
    color: brand,
  })

  page.drawText('ATTESTTO', {
    x: margin,
    y: height - 32,
    size: 18,
    font: helveticaBold,
    color: rgb(1, 1, 1),
  })

  page.drawText('Document Signature Attestation', {
    x: margin,
    y: height - 50,
    size: 10,
    font: helvetica,
    color: rgb(0.85, 0.82, 1), // light purple
  })

  y = height - 100

  // ── Status badge ──
  page.drawRectangle({
    x: margin,
    y: y - 4,
    width: 160,
    height: 24,
    color: greenBg,
    borderColor: greenDark,
    borderWidth: 1,
  })

  page.drawText('DIGITALLY SIGNED', {
    x: margin + 10,
    y: y + 2,
    size: 11,
    font: helveticaBold,
    color: greenDark,
  })

  y -= 45

  // ── Section helpers ──
  const drawSection = (title: string) => {
    page.drawLine({
      start: { x: margin, y: y + 8 },
      end: { x: width - margin, y: y + 8 },
      thickness: 0.5,
      color: borderLight,
    })
    page.drawText(title, {
      x: margin,
      y: y - 6,
      size: 8,
      font: helveticaBold,
      color: textMuted,
    })
    y -= 22
  }

  const drawRow = (label: string, value: string, mono = false) => {
    page.drawText(label, {
      x: margin,
      y,
      size: 10,
      font: helveticaBold,
      color: textMuted,
    })

    const maxChars = mono ? 60 : 70
    const displayValue = value.length > maxChars ? value.slice(0, maxChars) + '...' : value

    page.drawText(displayValue, {
      x: margin + 120,
      y,
      size: mono ? 8.5 : 10,
      font: helvetica,
      color: textDark,
    })
    y -= 17
  }

  // ── Content ──
  drawSection('DOCUMENT')
  drawRow('Filename', originalFileName)
  drawRow('File Size', `${(subject.document.size / 1024).toFixed(1)} KB`)
  drawRow('SHA-256', subject.document.hash, true)
  y -= 6

  drawSection('SIGNER')
  if (signerName) drawRow('Name', signerName)
  drawRow('DID', credential.issuer, true)
  drawRow('Method', proof.type)
  y -= 6

  drawSection('SIGNATURE')
  drawRow('Created', proof.created)
  drawRow('Proof', proof.proofValue.slice(0, 44) + '...', true)
  y -= 6

  drawSection('VERIFICATION')
  drawRow('Verify URL', subject.verifyUrl)
  drawRow('Standard', 'W3C Verifiable Credential v1')
  y -= 30

  // ── Footer separator ──
  page.drawLine({
    start: { x: margin, y },
    end: { x: width - margin, y },
    thickness: 0.5,
    color: borderLight,
  })
  y -= 16

  page.drawText('This attestation was generated 100% client-side. No document data was transmitted.', {
    x: margin,
    y,
    size: 7.5,
    font: helvetica,
    color: textMuted,
  })
  y -= 12

  page.drawText('verify.attestto.com — Open source under Apache 2.0', {
    x: margin,
    y,
    size: 7.5,
    font: helvetica,
    color: brand,
  })

  return pdfDoc.save()
}

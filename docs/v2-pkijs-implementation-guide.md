# V2 Cryptographic Verification — PKI.js Implementation Guide

> **Source:** Architecture session 2026-04-03 (Gemini corroboration)
> **Ticket:** ATT-209

## The Mental Shift: Text → Binary ASN.1

v1 scans for text patterns (`/Type /Sig`). v2 operates on **binary ASN.1 structures**.
The PDF signature is not text — it's a DER-encoded CMS (Cryptographic Message Syntax) container.

---

## Step 1: ByteRange Reconstruction

The PDF is signed "hollow" — the signature occupies a hole in the file.

```
ByteRange: [0, 500, 1000, 300]
           ↓
Bytes 0-499  +  Bytes 1000-1299  =  "What was signed"
(skip 500-999 — that's where /Contents lives)
```

```typescript
function reconstructSignedData(
  pdfBytes: Uint8Array,
  byteRange: [number, number, number, number]
): Uint8Array {
  const [offset1, length1, offset2, length2] = byteRange
  const part1 = pdfBytes.slice(offset1, offset1 + length1)
  const part2 = pdfBytes.slice(offset2, offset2 + length2)

  const result = new Uint8Array(length1 + length2)
  result.set(part1, 0)
  result.set(part2, length1)
  return result
}
```

---

## Step 2: Extract PKCS#7 from /Contents

The `/Contents` hex string is a CMS `ContentInfo` containing `SignedData`.

```typescript
import * as asn1js from 'asn1js'
import * as pkijs from 'pkijs'

function parseSignature(contentsHex: string): pkijs.SignedData {
  // Convert hex to ArrayBuffer
  const bytes = new Uint8Array(
    contentsHex.match(/.{1,2}/g)!.map(b => parseInt(b, 16))
  )

  // Parse ASN.1
  const asn1 = asn1js.fromBER(bytes.buffer)
  if (asn1.offset === -1) throw new Error('Invalid ASN.1 in /Contents')

  // Unwrap CMS ContentInfo → SignedData
  const contentInfo = new pkijs.ContentInfo({ schema: asn1.result })
  return new pkijs.SignedData({ schema: contentInfo.content })
}
```

Inside `SignedData`:
- `signedData.certificates` — signer cert + intermediate certs
- `signedData.signerInfos[0]` — signature algorithm, signed attributes, signature value
- `signedData.encapContentInfo` — encapsulated content (for detached: empty, hash is external)

---

## Step 3: Two-Phase Validation ("Sandwich")

### Phase A: Mathematical Integrity (Hash Match)

"Was the document modified after signing?"

```typescript
async function verifyIntegrity(
  signedData: pkijs.SignedData,
  reconstructedPdfData: ArrayBuffer
): Promise<boolean> {
  const result = await signedData.verify({
    signer: 0,                      // First signer
    data: reconstructedPdfData,     // ByteRange-reconstructed buffer
    checkChain: false,              // Just the math, not the chain
  })
  return result.signatureVerified
}
```

If `false` → document was tampered after signing (e.g., page added).

### Phase B: Identity Trust (Certificate Chain)

"Who signed, and do we trust them?"

```typescript
async function verifyTrust(
  signedData: pkijs.SignedData,
  attesttoRootCert: pkijs.Certificate
): Promise<{ trusted: boolean; signer: pkijs.Certificate }> {
  // Extract signer cert (leaf)
  const signerCert = signedData.certificates?.[0] as pkijs.Certificate

  // Build chain validation engine
  const chainEngine = new pkijs.CertificateChainValidationEngine({
    trustedCerts: [attesttoRootCert],     // Attestto Root CA (pinned)
    certs: signedData.certificates || [], // Intermediates from PDF
  })

  const chainResult = await chainEngine.verify()
  return {
    trusted: chainResult.result,
    signer: signerCert,
  }
}
```

### Combined Verification

```typescript
async function fullVerify(
  pdfBytes: Uint8Array,
  byteRange: [number, number, number, number],
  contentsHex: string,
  rootCaPem: string
): Promise<{
  integrityValid: boolean
  chainTrusted: boolean
  signerName: string
}> {
  const signedData = parseSignature(contentsHex)
  const reconstructed = reconstructSignedData(pdfBytes, byteRange)

  // Phase A: Math
  const integrityValid = await verifyIntegrity(signedData, reconstructed.buffer)

  // Phase B: Trust
  const rootCert = pkijs.Certificate.fromBER(pemToDer(rootCaPem))
  const { trusted, signer } = await verifyTrust(signedData, rootCert)

  // Extract signer CN
  const cnAttr = signer.subject.typesAndValues.find(
    t => t.type === '2.5.4.3' // OID for commonName
  )
  const signerName = cnAttr?.value?.valueBlock?.value || 'Unknown'

  return { integrityValid, chainTrusted: trusted, signerName }
}
```

---

## Step 4: SubFilter Handling

All three SubFilters produce CMS/PKCS#7 — PKI.js handles them the same way.
The difference is what **extra validation** to perform:

| SubFilter | Extra Validation |
|---|---|
| `adbe.pkcs7.detached` | None — standard PKCS#7 |
| `ETSI.CAdES.detached` | Check signed attributes: signing-time, cert hash (ESS signing-certificate-v2) |
| `adbe.pkcs7.sha1` | Use SHA-1 instead of SHA-256 for hash comparison |

```typescript
function getHashAlgorithm(subFilter: string): string {
  if (subFilter === 'adbe.pkcs7.sha1') return 'SHA-1'
  return 'SHA-256' // default for both pkcs7.detached and CAdES
}
```

---

## Step 5: Revocation — The "Phone Home" Problem

### Why This Is Hard

Checking revocation means asking the CA "is this cert still valid?" But:

1. **Privacy leak:** The OCSP responder learns WHO is verifying WHOM and from which IP. This breaks "No Phone Home."
2. **CORS block:** Most government OCSP/CRL servers (TSE, etc.) don't set `Access-Control-Allow-Origin: *`. The browser silently blocks the request.

### Strategy: LTV First, Proxy Second

#### Priority 1: LTV (Offline — Zero Network Calls)

Well-signed PDFs (PAdES B-LT / B-LTA) include revocation data INSIDE the PDF:

```
PDF → /DSS (Document Security Store)
       ├── /OCSPs — OCSP responses captured at signing time
       ├── /CRLs  — CRL snapshots captured at signing time
       └── /Certs — Intermediate certificates
```

The signing software already called OCSP at sign-time and embedded the signed response. Our component just extracts and verifies it — **zero external calls, maximum privacy.**

```typescript
function extractLtvData(pdfBytes: Uint8Array): {
  ocspResponses: Uint8Array[]
  crls: Uint8Array[]
  certs: Uint8Array[]
} | null {
  const text = new TextDecoder('latin1').decode(pdfBytes)

  // Find /DSS dictionary
  const dssMatch = text.match(/\/DSS\s*<</)
  if (!dssMatch) return null // No LTV data embedded

  // Extract /OCSPs, /CRLs, /Certs arrays from DSS
  // (implementation: parse indirect object references)
  // ...
}
```

If LTV data exists → verify the OCSP response signature → confirm cert was valid at signing time → **even if the cert has since expired, the signature was valid when made.**

#### Priority 2: Attestto Validation Proxy (Hybrid)

When no LTV data in the PDF, the component needs help:

```
<attestto-verify> → extracts cert → finds OCSP URL (Authority Information Access)
  → CORS blocked → sends cert HASH (not cert) to Attestto proxy
  → POST /api/verify/ocsp { certHash, issuerHash, serialNumber }
  → Attestto backend calls CA's OCSP responder
  → Returns signed OCSP response to component
  → Component verifies OCSP response signature locally
```

**Privacy rules for the proxy:**
- Send only the cert hash + serial, NOT the full certificate
- Backend MUST NOT log who asked or what cert was checked
- The OCSP response is signed by the CA — the proxy cannot forge it
- Response is verified client-side — the proxy is a dumb pipe

```typescript
// pkijs OCSP request creation
const ocspReq = new pkijs.OCSPRequest()
await ocspReq.createForCertificate(signerCert, {
  issuerCertificate: issuerCert,
  hashAlgorithm: 'SHA-256',
})
const ocspBody = ocspReq.toSchema(true).toBER()

// Send to proxy (not directly to CA — CORS blocked)
const resp = await fetch('https://api.attestto.com/verify/ocsp', {
  method: 'POST',
  body: ocspBody,
  headers: { 'Content-Type': 'application/ocsp-request' },
})
const ocspRespBuffer = await resp.arrayBuffer()

// Verify OCSP response locally
const ocspResp = new pkijs.OCSPResponse({
  schema: asn1js.fromBER(ocspRespBuffer).result,
})
const status = await ocspResp.getCertificateStatus(signerCert, issuerCert)

if (status.status === 0) {
  // Certificate is valid and NOT revoked
}
```

### Implementation Order

| Version | What | Network calls |
|---------|------|---------------|
| v2.0 | Chain validation only. Display "revocation not checked" | Zero |
| v2.1 | Extract /DSS from PDF. Verify embedded OCSP/CRL | Zero |
| v2.2 | Attestto proxy for non-LTV PDFs | One call to proxy (privacy-preserving) |

### Verification Display

| Revocation Status | Badge | Color |
|---|---|---|
| Not checked (v2.0) | "Chain valid, revocation not verified" | Blue |
| Valid via LTV (v2.1) | "Certificate valid at signing time" | Green |
| Valid via proxy (v2.2) | "Certificate currently valid" | Green |
| Revoked | "Certificate has been revoked" | Red |
| Check failed | "Revocation check failed (network error)" | Yellow |

---

## Dependencies

```json
{
  "pkijs": "^3.2.0",
  "asn1js": "^3.0.0",
  "pvutils": "^1.1.0"
}
```

All three run in the browser via WebCrypto. No Node.js required.

---

## Web Worker Architecture

Heavy crypto ops should run off the main thread:

```typescript
// verify-worker.ts
self.onmessage = async (e) => {
  const { pdfBytes, byteRange, contentsHex, rootCaPem } = e.data
  const result = await fullVerify(pdfBytes, byteRange, contentsHex, rootCaPem)
  self.postMessage(result)
}

// In Lit component:
const worker = new Worker(new URL('./verify-worker.ts', import.meta.url))
worker.postMessage({ pdfBytes, byteRange, contentsHex, rootCaPem })
worker.onmessage = (e) => {
  this.verificationResult = e.data
}
```

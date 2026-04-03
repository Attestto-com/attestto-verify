# @attestto/verify

Web Components for document verification and signing. Drop a PDF, verify its integrity and digital signatures — entirely in your browser.

**No login. No backend. No data transmitted. Apache 2.0.**

## Quick Start

### CDN (zero config)

```html
<script type="module" src="https://unpkg.com/@attestto/verify"></script>

<attestto-verify></attestto-verify>
```

### npm

```bash
npm install @attestto/verify
```

```typescript
import '@attestto/verify'

// Use in HTML
// <attestto-verify></attestto-verify>
// <attestto-sign></attestto-sign>
```

## Components

### `<attestto-verify>`

Drop a document to verify its integrity, digital signatures, and security properties.

**What it does (v1):**
- SHA-256 hash computation
- PAdES/PKCS#7 signature detection and metadata extraction
- Forensic security scan (JavaScript, OpenAction, embedded files, encryption)
- ByteRange array extraction for signature integrity audit
- SubFilter detection (`adbe.pkcs7.detached`, `ETSI.CAdES.detached`, `adbe.pkcs7.sha1`)

**Coming in v2 (ATT-209):**
- Cryptographic verification via pkijs (ByteRange + CA chain validation)
- LTV offline revocation checking (/DSS extraction)
- DID and vLEI identity extraction from X.509 certificates

```html
<attestto-verify></attestto-verify>
```

**Attributes:**
- `hash` — Pre-filled hash for deep-link mode (`/d/{hash}`)

**Events (composed, cross shadow DOM):**
- `verification-started` — `{ fileName, fileSize }`
- `verification-complete` — `{ hash, signatures, plugins }`

### `<attestto-sign>`

Sign documents with your DID via the Attestto ID browser extension.

```html
<attestto-sign></attestto-sign>
```

## CSS Parts

Style any element from outside the shadow DOM:

```css
attestto-verify::part(drop-zone) {
  border-color: #your-brand;
}

attestto-verify::part(status-badge) {
  font-size: 0.8rem;
}

attestto-verify::part(vlei-badge) {
  background: gold;
}
```

| Part | Element |
|------|---------|
| `drop-zone` | File drop area |
| `result-card` | Results container |
| `hash-display` | SHA-256 hash |
| `sig-card` | Signature card |
| `status-badge` | Verification level badge |
| `signer-name` | Signer display name |
| `did-link` | DID URI |
| `vlei-badge` | GLEIF vLEI corporate identity |
| `corporate-info` | Organization row |
| `trust-level` | Level hint text |
| `audit-section` | Collapsible forensic audit |
| `audit-grid` | Audit data grid |
| `button` | Action buttons |

## Verification Levels

| Level | Badge | Meaning |
|-------|-------|---------|
| Detected | Amber | Signature structure found (v1 byte scan) |
| Verified | Green | Cryptographic math verified (v2) |
| Trusted | Blue | Chain reaches a recognized CA |
| Qualified | Gold | GLEIF vLEI — verified legal entity |

## Plugin System

Extend verification with custom trust sources. Plugins can only ADD trust signals — they cannot bypass the core integrity check (sandwich security rule).

```typescript
import { attesttoPlugins } from '@attestto/verify'

attesttoPlugins.register({
  name: 'my-custom-verifier',
  label: 'My Custom Trust Source',
  type: 'verifier',
  verify: async (hash, context) => {
    // Your verification logic
    return { valid: true }
  }
})
```

**Plugin types:** Parser, Crypto, Trust, Verifier

**Built-in plugins:**
- DID Verifier (`did:web`, `did:jwk` resolvers)

**CDN registration:**
```html
<script>
  window.Attestto.registerPlugin({ ... })
</script>
```

## Forensic Security Scan

The collapsible audit section scans for:

| Check | Safe | Warning |
|-------|------|---------|
| JavaScript | None found | Scripts detected |
| Auto Actions | None | OpenAction present |
| Embedded Files | None | Files attached |
| External Links | Count | URI actions |
| ByteRange | Offsets displayed | — |
| LTV Data | /DSS present | Requires online check |
| Encryption | None or AES-256 | RC4 (weak) |

All scanning runs on local bytes. No data is sent to any external service.

## Privacy

> The issuer knows who received the credential, but not where the user presents it. The verifier knows the credential is authentic, but trusts the math — not Attestto.

- Your file never leaves your device
- No login or account required
- No telemetry, analytics, or tracking
- Forensic scanner is 100% local
- See [PRIVACY.md](./PRIVACY.md) for the full manifesto

## Development

```bash
pnpm install
pnpm dev          # Dev server
pnpm test         # Run tests (19 passing)
pnpm build        # Production build
```

## Architecture

- **Lit Web Components** — W3C standard, framework-agnostic
- **Shadow DOM** — Encapsulated styles, CSS Parts for external customization
- **Composed Events** — Cross shadow DOM communication
- **Zero backend** — All verification is client-side
- **pdfjs-dist** — Lazy-loaded for metadata extraction only

## Roadmap

- [x] ATT-208: v1 signature detection + forensic scanner (19 tests)
- [ ] ATT-209: v2 cryptographic verification (pkijs + ByteRange + CA chain)
- [ ] ATT-210: Solana anchor verifier plugin
- [ ] ATT-211: Secure proxy & auth (DID session tokens)
- [ ] ATT-212: vLEI Trust Plugin (GLEIF)

## License

Apache 2.0 — see [LICENSE](./LICENSE)

---

**verify.attestto.com** | **sign.attestto.com**

No data is transmitted. All verification happens in your browser.

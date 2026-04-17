# Security Changelog

Security-relevant changes to `@attestto/verify`. Each entry describes the vulnerability, its impact, the fix, and which commit closes it.

---

## 2026-04-17 — ATT-313: Offline revocation checking via embedded DSS

**Vector:** `attestto-verify` verified certificate chain integrity and trust but never checked whether the signer's certificate had been revoked. A fired employee's cert, or a compromised key that was revoked by the CA, would still show a green badge.

**Impact:** High — revoked certificates treated as trusted.

**Fix:** Added offline revocation checking by parsing the PDF's `/DSS` (Document Security Store) dictionary. PAdES B-LT and B-LTA documents embed OCSP responses and CRLs at signing time. The new `dss-parser.ts` extracts these blobs, and `revocation-checker.ts` parses the ASN.1 structures to check if the signer cert serial appears as revoked. Zero network calls — all data from the document itself.

`PdfSignatureInfo` now includes:
- `revocationStatus`: `'good'` | `'revoked'` | `'unknown'` | `'no-data'` | `'parse-error'`
- `revocationMessage`: human-readable explanation

Non-LTV documents get `'no-data'` — the UI should render this as a yellow "Revocation not verified" hint, not green.

**Test:** `revocation-checker.spec.ts` — 18 tests covering OCSP parsing (good/revoked/unknown), CRL parsing, serial normalization, DSS extraction, and no-data fallback.

---

## 2026-04-17 — ATT-312: Plugin security hardening (3 flaws)

### Flaw 1: Plugin level escalation — no crypto floor

**Vector:** A plugin (trust or verifier) could set `sig.level` to `'trusted'` or `'qualified'` even when the certificate chain was never cryptographically verified against a bundled trust anchor. A malicious plugin could make a forged PDF appear trusted.

**Impact:** High — undermines the entire verification guarantee for end users.

**Fix:** Added `gatePluginLevel()` in `pdf-verifier.ts`. Runs AFTER all plugins. If `certChain.cryptographicallyVerified !== true` and level is `'trusted'` or `'qualified'`, level is downgraded to `'parsed'` and a warning is logged.

**Test:** `registry.security.spec.ts` — 6 tests covering downgrade + passthrough paths.

### Flaw 2: `checkTrust()` accepted elevated trust without crypto verification

**Vector:** The trust plugin runner (`checkTrust()`) returned the highest `trustLevel` from any registered trust plugin without checking whether the underlying chain was cryptographically verified. A buggy or malicious trust plugin returning `{ trusted: true, trustLevel: 'qualified' }` would be accepted unconditionally.

**Impact:** High — same as Flaw 1, but at the registry layer.

**Fix:** `checkTrust()` now takes a `cryptographicallyVerified` boolean parameter. When `false`, plugins claiming `'qualified'` or `'recognized'` are capped to `'unknown'` and a console warning is emitted. `'self-signed'` is allowed regardless (it's a factual observation, not a trust claim).

**Test:** `registry.security.spec.ts` — 4 tests covering cap + passthrough paths.

### Flaw 3: Plugin overwrite without protection

**Vector:** `register()` silently overwrote plugins by name. A malicious script loaded after `@attestto/verify` on the same page could replace any plugin (e.g., `did-verifier`) with one that always returns `{ valid: true }`.

**Impact:** Medium — requires attacker-controlled script on the same origin (XSS or supply chain), but once achieved, completely bypasses plugin verification.

**Fix:** Plugins are now "frozen" after first registration. Subsequent `register()` calls with the same name are rejected with a console warning. Two escape hatches for legitimate use:
- `unregister(name)` then `register(...)` — explicit removal first.
- `register(plugin, { allowOverwrite: true })` — opt-in override (for tests or hot-reload).

**Test:** `registry.security.spec.ts` — 3 tests covering reject, allowOverwrite, and unregister-then-register.

---

## 2026-04-07 — ATT-309: Document integrity verification (Phase A)

**Vector:** `attestto-verify` v1.5 verified certificate chain structure (ASN.1 parsing, CA name matching) but never verified that the PDF content matched the signature. Anyone could modify the PDF after signing and the widget would show a green badge.

**Impact:** Critical — complete bypass of document integrity.

**Fix:** Added `verifyDocumentIntegrity()` using pkijs `SignedData.verify()` against the `ByteRange`-reconstructed signed bytes. Introduced `documentIntegrityVerified` (true/false/null) and the `'tampered'` level. Badge rendering now keys off `cryptographicallyVerified` instead of structure parsing.

**Test:** `chain-validator.spec.ts` — 8 tests for integrity verification paths.

---

## 2026-04-07 — ATT-357: Integrity check error handling

**Vector:** When `verifyDocumentIntegrity()` threw an exception (e.g., unsupported algorithm, malformed PKCS#7), the error was caught but `integrityValid` was set to `false` — rendering as "TAMPERED". This was a false positive: a document whose integrity *couldn't be checked* is not the same as one that *was tampered with*.

**Impact:** Medium — false tamper accusations on valid documents with unsupported signature algorithms.

**Fix:** Exceptions during integrity verification now set `integrityValid = null` (unknown), not `false` (tampered). Only `pkijs.SignedData.verify()` returning `{ signatureVerified: false }` triggers `false`. UI renders null as "INTEGRITY UNKNOWN" with a neutral badge.

**Test:** `chain-validator.spec.ts` — 4 tests distinguishing null (unknown) from false (tampered).

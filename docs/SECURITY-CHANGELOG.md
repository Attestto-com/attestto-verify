# Security Changelog

Security-relevant changes to `@attestto/verify`. Each entry describes the vulnerability, its impact, the fix, and which commit closes it.

---

## 2026-08-12 — ATT-1285: Self-attested signatures forgeable with a small-order Ed25519 key

**Vector:** An all-zero Ed25519 public key is a small-order curve point, and Web Crypto implements the RFC 8032 *cofactored* verification equation, which accepts such a key for a large fraction of messages. `verifyEd25519` handed the embedded public key straight to `crypto.subtle.verify` with no validation of the key itself. An attacker sets `proof.publicKey` to 32 zero bytes and `proof.proofValue` to 64 zero bytes, then nudges any signed field (`signedAt` suffices) and retries. Measured on Node 25: 10 of 40 arbitrary messages verify, so roughly 4 attempts land a forgery.

**Impact:** Critical — signature forgery with **no private key and no interaction with the signer**. A forged credential reached `level: 'verified'` and rendered as `self-attested`, whose copy asserts the signer proved ownership of their vault. Unlike the chain-validation defect fixed the same day, this failed **open**.

**Why it survived:** the existing test was blessing it. `attestto-self-attested.spec.ts` asserted `expect(['tampered','parsed','verified']).toContain(level)` over exactly the all-zero payload, with a comment reading "Accept any crypto-aware outcome". The vulnerability was therefore a *passing* CI outcome on every run since that test was written.

**Fix:** `verifyEd25519` now rejects libsodium's `ge25519_has_small_order` blocklist (orders 1, 2, 4 and 8, plus the non-canonical `p-1`, `p`, `p+1` encodings) before the key reaches `crypto.subtle.verify`. The comparison clears bit 255 so sign-flipped encodings of the same point cannot slip through. A small-order key returns `false`, a hard verification failure, and never `null`: a forgery attempt is not a missing browser capability and must not degrade to the softer `parsed` level. Exported as `isSmallOrderEd25519Key` so the producer side can reuse it.

**Test:** `attestto-self-attested.spec.ts` — the blessing assertion is now a single exact level (`tampered`); every blocklisted point is pinned with both sign bits; a real generate/sign/verify round trip acts as the positive control (which also makes `level: 'verified'` reachable in a test for the first time) with a tamper case alongside it.

**Commit:** `75e74c0`

**Residual risk:** `attestto-self-sign.ts`, the producer for this format, is at 0% coverage and is never round-tripped against the verifier, so no test proves which fields are actually inside the canonical signed bytes.

---

## 2026-08-12 — Chain validation: trusted verdict without validating the end entity

**Vector:** `validateChainWithDynamicAnchor` built its pkijs candidate pool as `[signerCert, ...intermediates, anchorCert]`. pkijs concatenates `[...trustedCerts, ...certs]`, dedupes, and treats the **last** element as the end entity to validate, so the signer was never the leaf. The immediate symptom was a false negative (every CR Firma Digital signature stuck at `parsed`), but the tempting fix for that symptom, anchoring at the topmost embedded CA, is an authentication bypass: pkijs validates the intermediate-to-anchor link and returns `trusted: true` while never examining the end entity. Measured: it returns true for a forged signer certificate, and true for a candidate pool containing **no signer at all**.

**Impact:** As shipped, a false negative only, fail-closed. The bypass was never shipped; it is recorded because it is the natural fix and would have set `cryptographicallyVerified = true`, which is the input every downstream trust floor keys off, including `gatePluginLevel` and the ATT-312 cap.

**Fix:** the pool is now `[...intermediates, signerCert]`, with the anchor not repeated (pkijs already prepends `trustedCerts`). Because pkijs selects the leaf **positionally** and that behaviour is undocumented and could shift on a dependency bump, the function additionally asserts by raw DER that `result.certificatePath[0]` is our signer before returning `trusted: true`. Chain errors also stopped claiming "no matching key fingerprint from resolver.attestto.com" in cases where the fingerprint had matched, or where the resolver was simply unreachable.

**Test:** `chain-validator.cr-anchor.spec.ts` — pins the working orderings, the old broken ordering, a forged signer, a forged anchor, and the bypass itself (asserting pkijs returns `true` while the validated path excludes the signer, which is exactly what the runtime guard catches).

**Commit:** `a92f2c8`

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

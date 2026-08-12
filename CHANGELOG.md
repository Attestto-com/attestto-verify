# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Security
- **A self attested signature could be forged by anyone, with no private key, and it was reported as `verified` (ATT-1284).** An all zero Ed25519 public key is a small order curve point, and Web Crypto implements the RFC 8032 *cofactored* verification equation, which accepts such a key for a large fraction of messages. Measured on Node 25: importing an all zero public key succeeds, and an all zero signature then verifies for 10 of 40 arbitrary messages. An attacker sets `publicKey` and `proofValue` to zeros, nudges any field (`signedAt` will do) until one lands, roughly 4 attempts, and reaches `level: 'verified'`, which renders as `self-attested`, whose Spanish copy asserts the signer proved ownership of their vault. `verifyEd25519` now rejects libsodium's `ge25519_has_small_order` blocklist before the key reaches `verify`, comparing with bit 255 cleared so the sign flipped encodings cannot slip through. A small order key returns `false` (a hard verification failure) and never `null`, because a forgery attempt is not a missing browser capability and must not degrade to the softer `parsed`.
- The existing test had been blessing the forgery. It asserted `expect(['tampered','parsed','verified']).toContain(level)` over exactly this payload, so the vulnerability was a passing outcome in CI rather than a failing one. That assertion is now a single exact level, and a real generate, sign and verify round trip was added as the positive control, which also makes `level: 'verified'` reachable in a test for the first time.

### Fixed
- **Every Costa Rican (BCCR Firma Digital) PAdES signature was stuck at `parsed` and could never reach `verified`.** Everything upstream was working: `did:pki:cr:sinpe:persona-fisica` derived correctly, the resolver returned `#key-2023`, and its SHA-256 fingerprint matched the PDF embedded CA SINPE certificate byte for byte. The verdict was lost one step later. pkijs builds its working pool as `[...trustedCerts, ...certs]`, dedupes it, and treats the **last** element as the end entity to validate. The pool was built as `[signerCert, ...intermediates, anchorCert]`, putting the signer first, so pkijs treated whichever CA landed last as the leaf and tried to build a path upward from an intermediate, returning "Incorrect name chaining". The pool is now `[...intermediates, signerCert]`, and the anchor is not repeated in `certs` because pkijs already prepends `trustedCerts`. Verified end to end against the live resolver: a real chain returns `trusted: true` anchored at "CA SINPE - PERSONA FISICA v2", and a forged signer is rejected.
- **A chain is no longer reported as trusted unless the validated path actually begins at the signer.** The obvious alternative fix for the above, anchoring at the topmost embedded CA, is an authentication bypass: it makes pkijs validate the intermediate to anchor link and return `trusted: true` while never examining the end entity, which returns true for a forged signer certificate and even for a candidate pool containing no signer at all. Because pkijs selects the leaf positionally and that behaviour is undocumented, it can shift on a dependency bump, so `validateChainWithDynamicAnchor` now asserts by raw DER that `certificatePath[0]` is our signer before returning success. Both the bypass and the guard are pinned by tests.
- **Chain validation errors no longer claim something false about the resolver.** The terminal error read "no matching key fingerprint from resolver.attestto.com" even when the fingerprint had matched perfectly, and the identical string was returned when the resolver was simply unreachable. Resolver unreachable, no fingerprint match, and matched but path could not be built are now reported distinctly.
- **Installing this package from its git repository produced a package with no build output, and the install still succeeded.** `dist/` is gitignored and the only build hook was `prepublishOnly`, which npm runs for a registry publish and **not** for a git dependency. A consumer writing `"@attestto/verify": "github:Attestto-com/attestto-verify#main"` got `exit 0`, `added 20 packages`, and a directory containing `LICENSE`, `package.json` and `README.md` only. `main` points at `dist/attestto-verify.js`, so it failed at import rather than at install. Adding `prepare` makes npm build after cloning: verified by installing the branch as a git dependency and confirming `dist/attestto-verify.js` is present.
- The script is `npm run build` rather than `pnpm build`, even though this repo is pnpm-managed. `prepare` runs in the **consumer's** environment with the consumer's package manager, and npm ships with Node while pnpm may not be present.

### Added
- **A coverage ratchet, enforced before every push and in CI.** `pnpm coverage:check` regenerates coverage and holds it against a tracked `coverage-baseline.json` under three rules: FLOOR (no metric may fall below the baseline), NO-DROP (the committed baseline must itself be at least the baseline at the merge base, so a pull request cannot lower the bar in the same commit that drops coverage), and DRIFT (a rise of more than 2pp means the baseline is stale, otherwise the bar sticks at today's value forever). Delivered as a tracked `.githooks/pre-push` wired up by `prepare` through `core.hooksPath`, rather than husky, to keep install time dependencies at zero. The hook can be skipped with `git push --no-verify`, so CI runs the same gate, and `actions/checkout` gains `fetch-depth: 0` because at the default depth of 1 there is no merge base and NO-DROP would silently never run. Starting baseline: 37.76% statements, 67.02% branches, 84.44% functions.
- Vitest's own `coverage.thresholds.autoUpdate` was rejected for this: it rewrites `vite.config.ts` as a side effect of a *passing* run, so in a pre-push hook the raised bar lands after the commit being pushed and never ships, and four bare numbers inline in a config file cannot be diffed against the base branch, which is the entire threat model.
- The new gate is registered in `gateSelfTest` and proven able to fail. That registration immediately earned itself: the first CI run reported `coverage:check` PASSED with a deliberate violation seeded in it. The baseline had been generated on Node 25 while CI runs the Node 22 pinned in `.nvmrc`, and the script was downgrading a FLOOR failure to a warning whenever those majors differed. That guard was meant to avoid an unreproducible local red and instead made the gate unfailable, which is precisely the decorative control `scripts/gate-self-test.mjs` exists to catch. The downgrade is removed (a mismatch now warns and still enforces) and the baseline is generated on the `.nvmrc` version. The measured numbers turn out to be identical on both majors.

### Notes
- Coverage exclusions cover only files with no executable logic (a type only module, a re-export barrel, a CSS template literal). `src/components/` stays in scope despite being roughly 4,838 lines at 0% coverage and about 73% of the current deficit, because excluding it would manufacture a headline number rather than remove noise. The consequence is real and deliberate: the first person to touch a component will need a DOM test environment stood up before they can push, since `environment: 'node'` is set globally.
- `tests/fixtures/cr-persona-fisica-certs.ts`, committed earlier for exactly this purpose, was imported by nothing. That is why no existing test caught the chain validation defect above. It is now used.

### Notes
- This makes a git dependency a working way to consume the package before it is published, which unblocks `attestto-desktop` (it currently uses `link:../attestto-verify`, a local filesystem path). Pin a tag or commit rather than `#main`, since a branch ref silently follows whatever lands next.
- `prepare` also runs on every local install in this repo, so `pnpm install` now builds. That is intentional (a package that cannot build should not install cleanly), but it is a behaviour change for anyone working here.

## [0.1.2] - 2026-08-12

Packaging fix. `0.1.1` was published with `"@attestto/trust": "link:../attestto-trust"` in its dependencies. `link:` is a local-filesystem protocol that resolves only against a sibling `../attestto-trust` checkout, so the published `0.1.1` was uninstallable for every external consumer. The Pages workflow hid it by checking out `attestto-trust` and symlinking it as a sibling, which is why CI stayed green while the registry artifact was broken.

### Security
- **A tampered document was reported as "could not check" rather than "failed" (ATT-1270).** `pkijs` signals a content mismatch by throwing, not by returning `signatureVerified: false`, so every genuinely tampered PDF landed in the catch-all and produced `integrityValid: null`. The `false` branch that exists to report tampering was unreachable for the one case it was written for. A modified document therefore rendered as an unknown state rather than a failed one. `verifyDocumentIntegrity` now maps a digest mismatch to `false` and keeps `null` for genuine inability to run the check (dynamic import failure, parser error), which is the distinction ATT-357 introduced.

### Fixed
- **The `link:` dependency is removed from the published package (ATT-1231).** `npm install @attestto/verify` now resolves for a consumer with no sibling checkout.

### Notes
- Removed rather than repointed at `^1.3.0`, even though that version is published and a semver range would have installed. Nothing in this package imports `@attestto/trust`, and `src/composables/no-bundled-trust.regression.spec.ts` exists specifically to keep it out of the trust path: bundling it shipped roughly 1 MB gzipped of PEM certificates to every visitor in the 2026 regression. Trust anchors are resolved on demand through `did:pki`. Pinning a version would have reintroduced into every consumer's install exactly the weight that a dedicated regression guard exists to keep out.
- Republishing also refreshes the `repository` URL in the registry metadata. The one published with `0.1.1` points at `github.com/attestto/verify` and returns 404. `main` already carries the correct URL, so no source change was needed.
- `0.1.1` should be deprecated on npm once `0.1.2` is published, since it cannot be installed.
- **PAdES signature extraction is covered by automated tests for the first time (ATT-1270).** The 17 cases covering signature extraction, forensic audit and the self attested credential path previously read fixtures from outside the repository: one from a gitignored directory inside a separate private repo, the other from a hardcoded absolute path containing a developer username. They ran on a single workstation and were skipped everywhere else, so this package's core capability was never exercised in CI. Both fixtures are now generated with synthetic signers and committed, and both carry real signatures rather than mocks, so the tests exercise `pkijs.SignedData.verify()` and Ed25519 verification rather than only the parsing.

## [0.1.1] - 2026-04-17

### Added
- Tooltips for trust permissions, cert chain, and signature format badges
- Stub-guard CI step to catch incomplete code on push/PR (ATT-504)

### Fixed
- UX improvements for badge visibility and interaction

## [0.1.0] - 2026-04-10

### Added
- Initial release
- Web Components for document verification (`<attestto-verify>`) and signing (`<attestto-sign>`)
- Plugin system with DID verifier plugin
- PDF signature verification (PAdES, CMS)
- Certificate chain validation against trust store
- BCCR/CR trust anchor bundling
- CSS Parts API for custom styling
- Zero-backend, zero-login architecture
- Apache 2.0 license

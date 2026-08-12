# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed
- **Installing this package from its git repository produced a package with no build output, and the install still succeeded.** `dist/` is gitignored and the only build hook was `prepublishOnly`, which npm runs for a registry publish and **not** for a git dependency. A consumer writing `"@attestto/verify": "github:Attestto-com/attestto-verify#main"` got `exit 0`, `added 20 packages`, and a directory containing `LICENSE`, `package.json` and `README.md` only. `main` points at `dist/attestto-verify.js`, so it failed at import rather than at install. Adding `prepare` makes npm build after cloning: verified by installing the branch as a git dependency and confirming `dist/attestto-verify.js` is present.
- The script is `npm run build` rather than `pnpm build`, even though this repo is pnpm-managed. `prepare` runs in the **consumer's** environment with the consumer's package manager, and npm ships with Node while pnpm may not be present.

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

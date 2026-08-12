# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.2] - 2026-08-12

Packaging fix. `0.1.1` was published with `"@attestto/trust": "link:../attestto-trust"` in its dependencies. `link:` is a local-filesystem protocol that resolves only against a sibling `../attestto-trust` checkout, so the published `0.1.1` was uninstallable for every external consumer. The Pages workflow hid it by checking out `attestto-trust` and symlinking it as a sibling, which is why CI stayed green while the registry artifact was broken.

### Fixed
- **The `link:` dependency is removed from the published package (ATT-1231).** `npm install @attestto/verify` now resolves for a consumer with no sibling checkout.

### Notes
- Removed rather than repointed at `^1.3.0`, even though that version is published and a semver range would have installed. Nothing in this package imports `@attestto/trust`, and `src/composables/no-bundled-trust.regression.spec.ts` exists specifically to keep it out of the trust path: bundling it shipped roughly 1 MB gzipped of PEM certificates to every visitor in the 2026 regression. Trust anchors are resolved on demand through `did:pki`. Pinning a version would have reintroduced into every consumer's install exactly the weight that a dedicated regression guard exists to keep out.
- Republishing also refreshes the `repository` URL in the registry metadata. The one published with `0.1.1` points at `github.com/attestto/verify` and returns 404. `main` already carries the correct URL, so no source change was needed.
- `0.1.1` should be deprecated on npm once `0.1.2` is published, since it cannot be installed.

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

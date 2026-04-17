# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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

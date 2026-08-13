# attestto-verify — Operating Rules

> Web Components for document verification and signing. Zero-trust, client-side PDF verification built on W3C Web Components (Lit). No framework, no backend — drop a PDF to verify.

The stack, the runnable scripts and the `src/` layout are deliberately NOT copied here.
Read them from `package.json`, `vite.config.ts` and the tree — an agent derives them more
accurately first-hand, and a copy drifts silently the moment a script is renamed. This file
carries only what the code cannot say.

## Architecture

### did:pki integration (key architectural decision)

Verify uses **did:pki resolution** for multi-country trust anchor lookup instead of manually bundling PEM files per country.

**Flow:**
1. PDF dropped → cert chain extracted (pkijs)
2. `pki-did-derivation.ts` derives `did:pki:cr:sinpe:persona-fisica` from X.509 Subject DN
3. `pki-resolver.ts` resolves via `resolver.attestto.com/1.0/identifiers/{did}`
4. DID Document returns: public keys, OCSP endpoints, endEntityHints, trust metadata
5. `chain-validator.ts` matches cert fingerprints against resolved keys

**Key files:**
- `src/composables/pki-did-derivation.ts` — X.509 → did:pki (deterministic)
- `src/composables/pki-resolver.ts` — resolver client (5min cache, 10s timeout)
- `src/composables/certificate-parser.ts` — cert chain extraction
- `src/composables/chain-validator.ts` — chain validation against resolved keys
- `src/plugins/did-verifier.ts` — plugin system: did:pki, did:web, did:jwk, did:sns

**No bundled fallback — resolver-only, and this is non-negotiable.** There is no
`src/trust-store/`, and the FE trust path must never `import ... from '@attestto/trust'`:
doing so bundles every promoted country's `ALL_CERTS` into the worker, which is the
regression that shipped ~1 MB gz of PEM to every visitor. `src/composables/no-bundled-trust.regression.spec.ts`
pins this at the source level and will fail the build if the import returns.

If the resolver is unreachable, the chain simply does not reach a trust anchor and the
signature stays at `parsed` with an honest error. Failing closed IS the design — there is
nothing to fall back to.

**Candidate anchors come only from the PDF's own embedded CA certs.** The resolver returns
key *fingerprints*; `chain-validator.ts` matches the embedded intermediate/CA certs against
those fingerprints and uses the matched cert as the pkijs trust anchor. A consequence worth
knowing: a PDF that embeds only the signer leaf has no candidate anchor at all, so no
`did:pki` is derivable and the resolver is never contacted.

### Related repos
- `@attestto/trust` — multi-country PKI cert store (source of truth)
- `did-pki-resolver/` — standalone npm resolver package
- `attestto-did-resolver/` — unified HTTP resolver (did:pki + did:sns), LIVE at resolver.attestto.com
- `did-pki-spec/` — W3C DID method specification

## Rules

- This is a public repo (Apache 2.0) — no PII, no private keys, no internal references
- Web Component must work standalone in any HTML page — no framework dependency leaks
- All crypto runs client-side — never send document content to any server
- Trust anchors come from did:pki resolution ONLY — never bundle national PKI certs in the FE
- Coverage may go up, never down: `pnpm coverage:check` runs pre-push and in CI against
  `coverage-baseline.json`. Raise the baseline with `pnpm coverage:update`; never hand-edit it
- **A fix is not done when the suite is green. It is done when you have watched the test
  FAIL without the fix and pass with it.** Break it on purpose, require red, restore,
  require green — then say so plainly ("reverting X turns Y red"), or state that the fix
  is unverified. A green check is not evidence. See `docs/HANDOFF-2026-08-12.md` for the
  six controls in this repo that were green and did nothing
- **Coverage measures execution, not checking.** Removing all 25 assertions from
  `asn1-parser.spec.ts` leaves coverage byte-identical with every test still passing.
  Use it as a lower bound, never as evidence of correctness
- Run CI locally before pushing, in CI's order, under the Node version in `.nvmrc` (22):
  changelog gate, `pnpm install --frozen-lockfile`, `pnpm gate-self-test`, `pnpm run lint`,
  `pnpm test`, `COVERAGE_BASE_REF=origin/main pnpm run coverage:check`, `pnpm run build`,
  `pnpm run check:bundle-size`, the `pnpm pack` tarball check, and `git merge-tree` against
  `origin/main`. `ci.yml` and `pages.yml` honour `.nvmrc`, but `changelog.yml` pins Node 20
  in the workflow — that one step does not run on 22
- Any new quality gate must be registered in `package.json` under `gateSelfTest` with a
  seed that violates it. An unregistered gate is the decorative control that file exists
  to prevent. Two gates currently CANNOT be registered, and the reason is the seed model,
  not neglect: `check:bundle-size` reads build output while seeds write source (a seeded
  run exits 0), and the changelog gate diffs against a base ref, which an untracked seed
  never appears in. Do not "fix" this by inventing a seed that does not really violate
  them — extending the model means changing `gate-self-test.mjs`, which is byte-identical
  across every Attestto repo and must not drift locally
- Do not run `pnpm dev` — user owns the dev server
- CSS uses `::part()` for external styling — don't break part names

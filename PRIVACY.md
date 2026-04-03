# Privacy Manifesto

> **The issuer knows who received the credential, but not where the user presents it. The verifier knows the credential is authentic, but trusts the math — not Attestto.**

## Three Pillars

### 1. Local Verification (No Phone Home)
All cryptographic verification happens inside the user's browser. The truth lives in the digital signature, not in a server query. When you drop a PDF into `<attestto-verify>`, it never leaves your device.

### 2. Selective Disclosure
DID-based signatures and SD-JWTs allow proving attributes without revealing full identity. You can prove "valid driver's license" or "over 18" by sending only the cryptographic proof of that fact — no name, address, or ID number required.

### 3. No Single Point of Failure
If Attestto's servers go offline, every signed PDF and every Solana-anchored document remains independently verifiable. The proof is self-contained — anyone with the Lit component and the public key can verify.

## What We Never Do

- **Never transmit your document** to any server for verification
- **Never expose API keys** in frontend components
- **Never log** which documents are verified, by whom, or from where
- **Never require** a login or account to verify a document
- **Never phone home** to check if a credential is "still valid" — trust the math

## Proxy Privacy Rules

When backend services are needed (OCSP, RPC, anchoring):

| Service | What we receive | What we NEVER log |
|---------|----------------|-------------------|
| OCSP Proxy | Certificate hash | User IP, identity, which document |
| RPC Proxy | Transaction hash | User IP, identity, which document |
| Anchor Proxy | Document hash | Document content (only the hash) |

## Future: Zero-Knowledge Proofs

ZKP plugins will allow proving properties without revealing values:
- "This contract is worth more than $10K" (without the exact amount)
- "This document was signed before 2026-04-01" (without the exact date)
- "The signer holds a valid professional license" (without revealing which one)

## Open Source Guarantee

This entire verification stack is Apache 2.0 licensed. Anyone can audit the code, run their own instance, or build plugins. Privacy is not a promise — it's verifiable in the source.

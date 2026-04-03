/**
 * Attestto Plugin Registry — Micro-Platform Architecture
 *
 * Three plugin types with distinct responsibilities:
 *
 *   Parser  — Extracts signatures from file formats (PDF, XML, JSON)
 *   Crypto  — Handles verification math (RSA, ECDSA, hardware tokens)
 *   Trust   — Decides if a Root CA is trusted (gov lists, corporate CAs)
 *
 * Security: Plugins can only ADD trust or provide metadata.
 * They can NEVER bypass the core integrity check (the "sandwich" rule).
 *
 * Registration:
 *   // Via ES module import
 *   import { attesttoPlugins } from '@attestto/verify'
 *   attesttoPlugins.register(myPlugin)
 *
 *   // Via global (for CDN/script-tag users)
 *   window.Attestto.registerPlugin(myPlugin)
 */

// ── Verification Result ──────────────────────────────────────────────

export interface VerificationResult {
  valid: boolean
  /** Human-readable summary */
  message?: string
  /** Structured details for display */
  details?: Record<string, unknown>
  /** Error message if verification failed */
  error?: string
}

// ── Plugin Types ─────────────────────────────────────────────────────

export type PluginType = 'parser' | 'crypto' | 'trust' | 'verifier'

export interface PluginBase {
  /** Unique identifier (e.g., 'solana-anchor', 'eu-tsl', 'xml-sig') */
  name: string
  /** Human-readable label for UI display */
  label: string
  /** Plugin type determines where it runs in the pipeline */
  type: PluginType
  /** Semver version string */
  version?: string
}

/**
 * Parser Plugin — Extracts raw signature data from file formats.
 * Example: XML/XAdES parser, JSON Web Signature parser
 */
export interface ParserPlugin extends PluginBase {
  type: 'parser'
  /** File extensions this parser handles (e.g., ['.xml', '.json']) */
  supportedExtensions: string[]
  /** Extract signature data from a file buffer */
  extract: (buffer: ArrayBuffer, fileName: string) => Promise<ExtractedSignature[]>
}

export interface ExtractedSignature {
  /** Raw signature bytes (DER-encoded PKCS#7, or format-specific) */
  signatureBytes: Uint8Array
  /** SubFilter or equivalent format identifier */
  format: string
  /** Signer display name (if extractable without crypto) */
  signerName?: string
  /** Additional metadata from the container */
  metadata?: Record<string, unknown>
}

/**
 * Crypto Plugin — Handles the heavy math or hardware token interaction.
 * Example: HSM-backed verification, custom algorithm support
 */
export interface CryptoPlugin extends PluginBase {
  type: 'crypto'
  /** Algorithms this plugin handles (e.g., ['RSA-PSS', 'Ed25519']) */
  supportedAlgorithms: string[]
  /** Verify a signature against a public key */
  verify: (
    signatureBytes: Uint8Array,
    dataHash: Uint8Array,
    publicKey: CryptoKey | Uint8Array,
    algorithm: string,
  ) => Promise<VerificationResult>
}

/**
 * Trust Plugin — Decides if a certificate authority is trusted.
 * Example: EU Trusted List (TSL), government CA registries
 */
export interface TrustPlugin extends PluginBase {
  type: 'trust'
  /** Check if a certificate (DER bytes) chains to a trusted root */
  isTrusted: (certChain: Uint8Array[]) => Promise<TrustResult>
}

export interface TrustResult {
  trusted: boolean
  /** Name of the trust source (e.g., 'EU TSL', 'Attestto Root CA') */
  trustSource?: string
  /** Trust level: 'qualified' (eIDAS), 'recognized', 'self-signed' */
  trustLevel?: 'qualified' | 'recognized' | 'self-signed' | 'unknown'
  /** Additional info */
  details?: Record<string, unknown>
}

/**
 * Verifier Plugin — Generic verification logic (backward-compatible).
 * Example: Solana anchor check, IPFS pinning verification
 */
export interface VerifierPlugin extends PluginBase {
  type: 'verifier'
  /** Run verification against a document hash + metadata */
  check: (hash: string, metadata?: Record<string, unknown>) => Promise<VerificationResult>
}

export type Plugin = ParserPlugin | CryptoPlugin | TrustPlugin | VerifierPlugin

// ── Registry ─────────────────────────────────────────────────────────

class PluginRegistry {
  private plugins = new Map<string, Plugin>()

  /**
   * Register a plugin. Overwrites if same name exists.
   * Dispatches 'attestto-plugin-registered' event for components to react.
   */
  register(plugin: Plugin): void {
    if (this.plugins.has(plugin.name)) {
      console.warn(`[attestto] Plugin "${plugin.name}" already registered, overwriting.`)
    }
    this.plugins.set(plugin.name, plugin)

    // Notify components via composed event (crosses shadow DOM)
    if (typeof window !== 'undefined') {
      window.dispatchEvent(
        new CustomEvent('attestto-plugin-registered', {
          detail: { name: plugin.name, type: plugin.type },
          composed: true,
          bubbles: true,
        }),
      )
    }
  }

  unregister(name: string): void {
    this.plugins.delete(name)
  }

  get(name: string): Plugin | undefined {
    return this.plugins.get(name)
  }

  getAll(): Plugin[] {
    return Array.from(this.plugins.values())
  }

  /** Get all plugins of a specific type */
  getByType<T extends Plugin>(type: PluginType): T[] {
    return Array.from(this.plugins.values()).filter((p) => p.type === type) as T[]
  }

  /** Get parsers that handle a specific file extension */
  getParsersForExtension(ext: string): ParserPlugin[] {
    return this.getByType<ParserPlugin>('parser').filter((p) =>
      p.supportedExtensions.includes(ext.toLowerCase()),
    )
  }

  /**
   * Run all verifier plugins against a document hash.
   * Security: These run AFTER the core integrity check — they can
   * only ADD trust signals, never bypass the core hash verification.
   */
  async runVerifiers(
    hash: string,
    metadata?: Record<string, unknown>,
  ): Promise<Map<string, VerificationResult>> {
    const results = new Map<string, VerificationResult>()
    const verifiers = this.getByType<VerifierPlugin>('verifier')

    const settled = await Promise.allSettled(
      verifiers.map(async (v) => {
        const result = await v.check(hash, metadata)
        return { name: v.name, result }
      }),
    )

    for (const outcome of settled) {
      if (outcome.status === 'fulfilled') {
        results.set(outcome.value.name, outcome.value.result)
      } else {
        const idx = settled.indexOf(outcome)
        const name = verifiers[idx]?.name ?? 'unknown'
        results.set(name, { valid: false, error: String(outcome.reason) })
      }
    }

    return results
  }

  /**
   * Run all trust plugins against a certificate chain.
   * Returns the highest trust level found.
   */
  async checkTrust(certChain: Uint8Array[]): Promise<TrustResult> {
    const trustPlugins = this.getByType<TrustPlugin>('trust')

    if (trustPlugins.length === 0) {
      return { trusted: false, trustLevel: 'unknown' }
    }

    const results = await Promise.allSettled(trustPlugins.map((p) => p.isTrusted(certChain)))

    // Return the highest trust level found
    const trustOrder: TrustResult['trustLevel'][] = [
      'qualified',
      'recognized',
      'self-signed',
      'unknown',
    ]

    let best: TrustResult = { trusted: false, trustLevel: 'unknown' }

    for (const outcome of results) {
      if (outcome.status === 'fulfilled' && outcome.value.trusted) {
        const current = trustOrder.indexOf(outcome.value.trustLevel ?? 'unknown')
        const bestIdx = trustOrder.indexOf(best.trustLevel ?? 'unknown')
        if (current < bestIdx || !best.trusted) {
          best = outcome.value
        }
      }
    }

    return best
  }
}

/** Global plugin registry — shared across all Attestto component instances */
export const attesttoPlugins = new PluginRegistry()

// ── Global API (for CDN/script-tag users) ────────────────────────────

if (typeof window !== 'undefined') {
  const global = window as unknown as {
    Attestto?: { registerPlugin: (p: Plugin) => void; plugins: PluginRegistry }
  }
  if (!global.Attestto) {
    global.Attestto = {
      registerPlugin: (plugin: Plugin) => attesttoPlugins.register(plugin),
      plugins: attesttoPlugins,
    }
  }
}

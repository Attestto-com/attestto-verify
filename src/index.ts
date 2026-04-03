/**
 * @attestto/verify — Web Components for document verification and signing
 *
 * Embed anywhere:
 *   <script type="module" src="https://cdn.attestto.com/v1/attestto-verify.js"></script>
 *   <attestto-verify></attestto-verify>
 *   <attestto-sign></attestto-sign>
 *
 * Install via npm:
 *   import '@attestto/verify'
 *
 * Individual components:
 *   import '@attestto/verify/verify'
 *   import '@attestto/verify/sign'
 *
 * Plugin system:
 *   import { attesttoPlugins } from '@attestto/verify'
 *   attesttoPlugins.register(myPlugin)
 *
 *   // Or via global (CDN users):
 *   window.Attestto.registerPlugin(myPlugin)
 */

// Initialize global Attestto namespace (debug toggle, plugin registration)
import { initGlobal } from './logger.js'
initGlobal()

export { AttesttoVerify } from './components/attestto-verify.js'
export { AttesttoSign } from './components/attestto-sign.js'

// Plugin system
export { attesttoPlugins } from './plugins/registry.js'
export type {
  Plugin,
  PluginType,
  PluginBase,
  ParserPlugin,
  CryptoPlugin,
  TrustPlugin,
  VerifierPlugin,
  VerificationResult,
  TrustResult,
  ExtractedSignature,
} from './plugins/registry.js'

// Signing composable
export {
  hashFile,
  signWithWallet,
  signWithBrowserKey,
  getBrowserKeyPair,
  buildCredential,
  exportCredentialAsJson,
} from './composables/document-signer.js'
export type { DocumentSignatureCredential, SignResult } from './composables/document-signer.js'

// Built-in plugins
export { didVerifierPlugin, createDidVerifier } from './plugins/did-verifier.js'
export type { DidDocument, DidResolver, VerificationMethod } from './plugins/did-verifier.js'

// Result schema — the universal contract
export type {
  AttesttoVerificationResult,
  DocumentInfo,
  IntegrityResult,
  SignatureResult,
  SignerIdentity,
  TrustInfo,
  TrustSource,
  TrustLevel,
  CertTrustDetails,
  DidTrustDetails,
  ExtensionResult,
  VerificationLevel,
  SignatureType,
} from './plugins/types.js'

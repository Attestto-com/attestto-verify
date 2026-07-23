import { defineConfig } from 'vite'
import { resolve } from 'node:path'
import { readFileSync, readdirSync } from 'node:fs'

const pkg = JSON.parse(readFileSync(resolve(__dirname, 'package.json'), 'utf-8'))

// Read per-country authority metadata from the sibling attestto-trust repo.
// meta.json is not included in the npm package's `files` allowlist, so we
// read directly from the sibling path (safe because package.json uses
// `link:../attestto-trust`, so this always resolves to the local directory).
function loadTrustDirectory() {
  const trustRoot = resolve(__dirname, '../attestto-trust/countries')
  try {
    const countries = readdirSync(trustRoot, { withFileTypes: true })
      .filter((d) => d.isDirectory())
      .map((d) => {
        try {
          const meta = JSON.parse(readFileSync(resolve(trustRoot, d.name, 'meta.json'), 'utf-8'))
          return {
            code: meta.code ?? d.name,
            name: meta.name ?? d.name,
            flag: meta.flag ?? '',
            authorityName: meta.authority?.name ?? '',
            authorityUrl: meta.authority?.url ?? '',
            relatedLinks: (meta.relatedLinks ?? []).filter(
              (l: { url?: string }) => l.url && !l.url.includes('attestto'),
            ),
          }
        } catch {
          return null
        }
      })
      .filter(Boolean)
    return countries
  } catch {
    return []
  }
}

const trustDirectory = loadTrustDirectory()

/**
 * Vite config for GitHub Pages site build.
 * Builds index.html as a standard web app (not library mode).
 * Usage: vite build --config vite.config.pages.ts
 */
export default defineConfig({
  define: {
    __APP_VERSION__: JSON.stringify(pkg.version),
    __TRUST_DIRECTORY__: JSON.stringify(trustDirectory),
  },
  resolve: {
    alias: {
      '@': resolve(__dirname, 'src'),
    },
  },
  build: {
    outDir: 'dist-pages',
    sourcemap: false,
    rollupOptions: {
      input: {
        main: resolve(__dirname, 'index.html'),
        // The public "Sign" demo is intentionally not built/published. Source
        // is kept in the repo (sign/index.html + composables) so it can be
        // re-enabled, but it is unreachable from the public site.
        dev: resolve(__dirname, 'dev/index.html'),
        // Open Credential Handoff landing page — canonical at /offer/,
        // legacy alias /c/ kept for backwards compat with existing
        // desktop and issuer URLs.
        offer: resolve(__dirname, 'offer/index.html'),
        c: resolve(__dirname, 'c/index.html'),
      },
    },
  },
})

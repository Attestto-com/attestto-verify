import { defineConfig } from 'vite'
import { resolve } from 'node:path'
import { readFileSync } from 'node:fs'

const pkg = JSON.parse(readFileSync(resolve(__dirname, 'package.json'), 'utf-8'))

/**
 * Vite config for GitHub Pages site build.
 * Builds index.html as a standard web app (not library mode).
 * Usage: vite build --config vite.config.pages.ts
 */
export default defineConfig({
  define: {
    __APP_VERSION__: JSON.stringify(pkg.version),
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

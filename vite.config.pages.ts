import { defineConfig } from 'vite'
import { resolve } from 'node:path'

/**
 * Vite config for GitHub Pages site build.
 * Builds index.html as a standard web app (not library mode).
 * Usage: vite build --config vite.config.pages.ts
 */
export default defineConfig({
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
        sign: resolve(__dirname, 'sign/index.html'),
        dev: resolve(__dirname, 'dev/index.html'),
        c: resolve(__dirname, 'c/index.html'),
      },
    },
  },
})

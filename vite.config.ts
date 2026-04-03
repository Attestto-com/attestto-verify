import { defineConfig } from 'vite'
import { resolve } from 'node:path'

export default defineConfig({
  resolve: {
    alias: {
      '@': resolve(__dirname, 'src'),
    },
  },
  build: {
    lib: {
      entry: resolve(__dirname, 'src/index.ts'),
      name: 'AttesttoVerify',
      fileName: 'attestto-verify',
      formats: ['es'],
    },
    outDir: 'dist',
    sourcemap: true,
    rollupOptions: {
      // pdfjs-dist is lazy-loaded at runtime — keep it external to reduce bundle
      external: ['pdfjs-dist'],
      output: {
        globals: {
          'pdfjs-dist': 'pdfjsLib',
        },
      },
    },
  },
})

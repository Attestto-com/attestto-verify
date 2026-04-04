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
      output: {},
    },
  },
  test: {
    testTimeout: 30000,
    fileParallelism: false,
    pool: 'forks',
    poolOptions: {
      forks: {
        singleFork: true,
        execArgv: ['--max-old-space-size=8192'],
      },
    },
    environment: 'node',
    server: {
      deps: {
        external: ['lit', '@lit/reactive-element', 'lit-element', 'lit-html'],
      },
    },
  },
})

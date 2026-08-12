import { defineConfig } from 'vite'
import { resolve } from 'node:path'
import { readFileSync } from 'node:fs'

const pkg = JSON.parse(readFileSync(resolve(__dirname, 'package.json'), 'utf-8'))

export default defineConfig({
  appType: 'mpa',
  define: {
    __APP_VERSION__: JSON.stringify(pkg.version),
  },
  // Pinned dev port so the demo has a stable URL:
  //   http://localhost:5174/demo/signature-card.html
  // strictPort fails loudly if 5174 is taken (rather than drifting to 5175).
  server: {
    port: 5174,
    strictPort: true,
  },
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
    coverage: {
      provider: 'v8',
      // `json-summary` feeds scripts/coverage-ratchet.mjs; `html` is the
      // report a human actually reads (coverage/index.html); `lcov` is what
      // external tooling consumes.
      reporter: ['text', 'html', 'json-summary', 'lcov'],
      reportsDirectory: 'coverage',
      // Without `all`, a source file with no test importing it is simply
      // absent from the report — so adding an untested module would RAISE the
      // percentage. That is the exact opposite of a ratchet.
      all: true,
      include: ['src/**/*.ts'],
      // NOTE: this REPLACES vitest's defaults, so everything must be spelled
      // out. Kept deliberately short: the only things excluded are files with
      // no executable logic to test. Nothing is excluded to flatter the
      // number — in particular src/components/**, which is ~4,800 untested
      // lines and most of the current deficit, stays IN.
      exclude: [
        '**/*.spec.ts',
        '**/*.test.ts',
        '**/*.d.ts',
        // Type-only declarations — no runtime code to cover.
        'src/plugins/types.ts',
        // A re-export barrel and a bare CSS template literal.
        'src/index.ts',
        'src/styles/shared.ts',
      ],
    },
  },
})

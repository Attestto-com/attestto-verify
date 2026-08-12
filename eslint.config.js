// ESLint 9 flat config.
//
// This repo declared a `lint` script since its first commit and never had a
// config file or the TypeScript plugin installed, so `eslint src --ext .ts`
// exited 2 with "couldn't find an eslint.config.js" on every invocation. That
// also disabled the publish gate: `prepublishOnly` is
// `lint && test && build`, so it could never reach `test`, yet 0.1.1 and 0.1.2
// both reached the registry. A gate that cannot pass is not a gate.
//
// Copied from vc-sdk, where the same gap was closed first, so the rule set is
// identical across the published estate and a fix in one place is portable.
//
// Deliberately narrow. This restores a lint step that runs and can fail; it is
// not the place to introduce a rule set nobody has reviewed, which would either
// bury the build in pre-existing violations or get switched off.
import js from '@eslint/js'
import tseslint from 'typescript-eslint'

export default tseslint.config(
  {
    ignores: [
      'dist/**',
      'coverage/**',
      'node_modules/**',
      '*.config.js',
      '*.config.ts',
      'scripts/**',
    ],
  },
  js.configs.recommended,
  ...tseslint.configs.recommended,
  {
    rules: {
      // Tests assert on loosely-typed JSON fixtures; `any` there is honest.
      '@typescript-eslint/no-explicit-any': 'warn',
      '@typescript-eslint/no-unused-vars': [
        'error',
        { argsIgnorePattern: '^_', varsIgnorePattern: '^_' },
      ],
    },
  },
)

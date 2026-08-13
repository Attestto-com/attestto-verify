/**
 * i18n was at 0% — the module had never been imported by a test.
 *
 * These assertions are chosen for what they would CATCH, not for what they
 * execute. Coverage measures execution, not checking, so a spec that imports
 * this module and asserts it is defined would move the number without telling
 * anyone anything.
 *
 * The failure modes that actually reach a user:
 *
 *   1. A key goes missing from `es`. `t()` silently falls back to English, so
 *      the page still renders and nothing throws — a Spanish user just gets an
 *      English string. That is invisible to every other check in this repo.
 *   2. `t()` returns undefined for an unknown key, rendering "undefined" into
 *      the UI instead of something a human can read.
 *   3. `setLang` stops dispatching its event. Components listen for
 *      `attestto-lang-change` to re-render, so switching language would update
 *      the stored value and change nothing on screen.
 */
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'
import { t, setLang, currentLang } from './i18n'

/**
 * `environment: 'node'`, so there is no window. `setLang` dispatches on it
 * unguarded (unlike its localStorage access, which IS guarded), so a stub is
 * required rather than optional.
 */
let dispatched: CustomEvent[]

beforeEach(() => {
  dispatched = []
  vi.stubGlobal('window', {
    dispatchEvent: (event: CustomEvent) => {
      dispatched.push(event)
      return true
    },
  })
  // Closure-backed rather than `this.store`: the object literal has no declared
  // type, so `this` widens to `{}` and `tsc -p tsconfig.build.json` rejects it.
  const store = new Map<string, string>()
  vi.stubGlobal('localStorage', {
    getItem: (key: string) => store.get(key) ?? null,
    setItem: (key: string, value: string) => void store.set(key, value),
  })
})

afterEach(() => {
  // Module-level `_lang` persists between tests; leaving it as 'es' would make
  // every later test read a language it did not set.
  setLang('en')
  vi.unstubAllGlobals()
})

describe('t', () => {
  it('returns the key itself for an unknown key, never undefined', () => {
    // Rendering the key is ugly; rendering "undefined" is a bug report.
    expect(t('no.such.key.exists')).toBe('no.such.key.exists')
  })

  it('translates a known key in the default language', () => {
    expect(t('nav.verify')).toBe('Verify')
  })

  it('translates through the selected language', () => {
    setLang('es')
    expect(t('nav.verify')).toBe('Verificar')
  })
})

describe('translation parity', () => {
  /**
   * Keys whose Spanish differs from their English. If one of these ever returns
   * the English string while the language is 'es', the key was removed from the
   * `es` table and `t()`'s fallback is hiding it.
   *
   * This is the check that catches translation drift, and nothing else in the
   * repo does: a missing key throws nothing, logs nothing, and renders fine.
   */
  const DIVERGENT = ['nav.verify', 'nav.sign', 'nav.developers', 'verify.title', 'verify.subtitle']

  it('does not fall back to English for keys that have a Spanish translation', () => {
    const english = Object.fromEntries(DIVERGENT.map((key) => [key, t(key)]))

    setLang('es')

    for (const key of DIVERGENT) {
      expect(t(key), `${key} rendered English while the language was Spanish`).not.toBe(
        english[key],
      )
      expect(t(key), `${key} is missing from both tables`).not.toBe(key)
    }
  })
})

describe('setLang', () => {
  it('changes what currentLang reports', () => {
    expect(currentLang()).toBe('en')
    setLang('es')
    expect(currentLang()).toBe('es')
  })

  it('persists the choice so a reload keeps the language', () => {
    setLang('es')
    expect(localStorage.getItem('attestto-lang')).toBe('es')
  })

  it('dispatches attestto-lang-change so components re-render', () => {
    setLang('es')

    // Not just "something was dispatched" — the name and payload are the
    // contract the components read.
    expect(dispatched, 'no event dispatched, so the UI would not re-render').toHaveLength(1)
    expect(dispatched[0].type).toBe('attestto-lang-change')
    expect(dispatched[0].detail).toEqual({ lang: 'es' })
  })
})

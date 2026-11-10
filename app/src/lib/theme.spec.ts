import { afterEach, describe, expect, it, vi } from 'vitest'
import { DEFAULT_THEME, THEME_KEY, applyTheme, isTheme, readTheme, saveTheme } from '@/lib/theme'

const failing = {
  getItem: () => {
    throw new Error('stockage refusé')
  },
  setItem: () => {
    throw new Error('stockage refusé')
  },
}

afterEach(() => {
  localStorage.clear()
  document.documentElement.removeAttribute('data-theme')
  vi.restoreAllMocks()
})

describe('thème', () => {
  it('sombre par défaut', () => {
    expect(DEFAULT_THEME).toBe('dark')
    expect(readTheme({ getItem: () => null })).toBe('dark')
  })

  it('relit un choix valide', () => {
    expect(readTheme({ getItem: () => 'light' })).toBe('light')
    expect(readTheme({ getItem: () => 'dark' })).toBe('dark')
  })

  it('ignore une valeur inconnue ou altérée', () => {
    for (const value of ['', 'Light', 'sepia', '{"a":1}', 'null']) {
      expect(readTheme({ getItem: () => value })).toBe('dark')
    }
    expect(isTheme(undefined)).toBe(false)
    expect(isTheme(1)).toBe(false)
  })

  it('reste en sombre si le stockage manque ou refuse', () => {
    expect(readTheme(null)).toBe('dark')
    expect(readTheme(failing)).toBe('dark')
    expect(() => saveTheme('light', null)).not.toThrow()
    expect(() => saveTheme('light', failing)).not.toThrow()
  })

  it('enregistre et relit le choix', () => {
    saveTheme('light')
    expect(localStorage.getItem(THEME_KEY)).toBe('light')
    expect(readTheme()).toBe('light')
  })

  it('applique le thème aux jetons et aux contrôles natifs', () => {
    document.head.insertAdjacentHTML('beforeend', '<meta name="color-scheme" content="dark">')
    applyTheme('light')
    expect(document.documentElement.dataset.theme).toBe('light')
    expect(document.querySelector('meta[name="color-scheme"]')?.getAttribute('content')).toBe('light')
    applyTheme('dark')
    expect(document.documentElement.dataset.theme).toBe('dark')
    document.querySelector('meta[name="color-scheme"]')?.remove()
  })

  it('applyTheme ne plante pas sans balise color-scheme', () => {
    expect(() => applyTheme('light')).not.toThrow()
  })
})

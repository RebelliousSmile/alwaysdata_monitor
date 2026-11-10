import { describe, expect, it } from 'vitest'
import tokens from './styles/tokens.css?raw'
import reference from '../../../aidd_docs/design/vigie-design/tokens.css?raw'
import light from './styles/tokens-light.css?raw'

// Les couleurs viennent des jetons de la maquette, jamais d'une vue.
const sources = import.meta.glob<string>(['./**/*.vue', './lib/*.ts'], {
  query: '?raw',
  import: 'default',
  eager: true,
})

describe('système visuel', () => {
  it('tokens.css est la copie exacte de la maquette', () => {
    expect(tokens.replace(/\r\n/g, '\n')).toBe(reference.replace(/\r\n/g, '\n'))
  })

  it.each(Object.entries(sources))('%s ne code aucune couleur en dur', (_path, source) => {
    expect(source).not.toMatch(/#[0-9a-fA-F]{3,8}\b/)
    expect(source).not.toMatch(/\b(rgb|rgba|hsl|hsla)\(/)
  })
})

// --- Thème clair ----------------------------------------------------------

const declared = (css: string): Record<string, string> =>
  Object.fromEntries([...css.matchAll(/(--vg-[a-z0-9-]+):\s*([^;]+);/g)].map((m) => [m[1] ?? '', (m[2] ?? '').trim()]))

const lightTokens = declared(light)
const darkTokens = declared(tokens)

const isColor = (value: string) => /^#[0-9A-Fa-f]{6}$/.test(value)
const darkColors = Object.entries(darkTokens).filter(([, value]) => isColor(value))

function luminance(hex: string): number {
  const channel = (i: number) => {
    const c = parseInt(hex.slice(1 + i * 2, 3 + i * 2), 16) / 255
    return c <= 0.03928 ? c / 12.92 : ((c + 0.055) / 1.055) ** 2.4
  }
  return 0.2126 * channel(0) + 0.7152 * channel(1) + 0.0722 * channel(2)
}

function contrast(a: string, b: string): number {
  const hi = Math.max(luminance(a), luminance(b))
  const lo = Math.min(luminance(a), luminance(b))
  return (hi + 0.05) / (lo + 0.05)
}

describe('thème clair', () => {
  it('ne s’applique que sous data-theme="light"', () => {
    expect(light).toMatch(/:root\[data-theme='light'\]\s*\{/)
    expect(light.match(/\{/g)).toHaveLength(1)
  })

  it('redéfinit chaque couleur du thème sombre, sous le même nom, et rien d’autre', () => {
    const darkNames = darkColors.map(([name]) => name).sort()
    const lightNames = Object.keys(lightTokens).filter((name) => isColor(lightTokens[name] ?? '')).sort()
    expect(lightNames).toEqual(darkNames)
    expect(Object.keys(lightTokens).filter((name) => !(name in darkTokens))).toEqual([])
  })

  it('tous les jetons clairs sont des couleurs #RRGGBB différentes de leur équivalent sombre', () => {
    for (const [name, value] of Object.entries(lightTokens)) {
      if (isColor(value)) expect(value, name).not.toBe(darkTokens[name])
    }
  })

  const t = (name: string): string => lightTokens[`--vg-${name}`] ?? ''
  const TEXT_ON = ['bg', 'surface', 'surface-2', 'surface-3', 'header', 'code']

  it.each(['text', 'text-2', 'text-3'].flatMap((fg) => TEXT_ON.map((bg) => [fg, bg] as const)))(
    'texte %s sur %s : au moins 4,5:1',
    (fg, bg) => {
      expect(contrast(t(fg), t(bg))).toBeGreaterThanOrEqual(4.5)
    },
  )

  it.each([
    ['link', 'bg'],
    ['link', 'surface'],
    ['link', 'surface-2'],
    ['on-primary', 'primary'],
    ['ok', 'ok-bg'],
    ['danger', 'danger-bg'],
    ['danger-text', 'danger-bg'],
    ['warn', 'warn-bg'],
    ['info', 'info-bg'],
    ['ia', 'ia-bg'],
    ['neutral', 'neutral-bg'],
    ['ok', 'surface'],
    ['danger', 'surface'],
    ['warn', 'surface'],
    ['info', 'surface'],
    ['ia', 'surface'],
    ['neutral', 'surface'],
  ])('%s sur %s : au moins 4,5:1', (fg, bg) => {
    expect(contrast(t(fg), t(bg))).toBeGreaterThanOrEqual(4.5)
  })

  it.each([
    ['control', 'surface'],
    ['control', 'bg'],
    ['switch-off', 'surface'],
    ['switch-off', 'bg'],
    ['primary', 'surface'],
  ])('contour ou interrupteur %s sur %s : au moins 3:1', (fg, bg) => {
    expect(contrast(t(fg), t(bg))).toBeGreaterThanOrEqual(3)
  })

  it('le calcul de contraste est exact (noir sur blanc = 21)', () => {
    expect(contrast('#000000', '#FFFFFF')).toBeCloseTo(21, 5)
    expect(contrast('#777777', '#FFFFFF')).toBeCloseTo(4.48, 2)
  })
})

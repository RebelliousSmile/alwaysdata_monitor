import { describe, expect, it } from 'vitest'
import tokens from './styles/tokens.css?raw'
import reference from '../../../aidd_docs/design/vigie-design/tokens.css?raw'

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

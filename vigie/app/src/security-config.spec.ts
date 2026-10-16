import { describe, expect, it } from 'vitest'
import tauriConfig from '../src-tauri/tauri.conf.json'
import indexHtml from '../index.html?raw'

// Sources admises par la CSP de l'app empaquetée : la page elle-même, l'IPC
// de Tauri et les images en ligne. Aucune origine externe.
const ALLOWED = new Set(["'self'", 'ipc:', 'http://ipc.localhost', 'data:'])

const directives = (csp: string): Map<string, string[]> =>
  new Map(
    csp
      .split(';')
      .map((part) => part.trim().split(/\s+/))
      .filter((words) => words[0])
      .map(([name, ...sources]) => [name ?? '', sources]),
  )

describe('configuration de sécurité de l’app empaquetée', () => {
  const csp = tauriConfig.app.security.csp
  const parsed = directives(csp)

  it('n’autorise ni unsafe-eval ni unsafe-inline', () => {
    expect(csp).not.toContain("'unsafe-eval'")
    expect(csp).not.toContain("'unsafe-inline'")
  })

  it('n’autorise aucune origine externe', () => {
    for (const sources of parsed.values()) {
      for (const source of sources) expect(ALLOWED, source).toContain(source)
    }
  })

  it('limite connect-src à la page et à l’IPC de Tauri', () => {
    expect(parsed.get('default-src')).toEqual(["'self'"])
    expect(parsed.get('connect-src')).toEqual(["'self'", 'ipc:', 'http://ipc.localhost'])
  })

  it('ne charge rien d’externe au démarrage', () => {
    expect(indexHtml).not.toMatch(/https?:\/\//)
  })
})

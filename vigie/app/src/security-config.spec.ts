import { describe, expect, it } from 'vitest'
import tauriConfig from '../src-tauri/tauri.conf.json'
import indexHtml from '../index.html?raw'
import eslintConfig from '../eslint.config.js?raw'
import cargoLock from '../src-tauri/Cargo.lock?raw'
import pnpmLock from '../pnpm-lock.yaml?raw'

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

interface Capability {
  identifier: string
  windows: string[]
  platforms?: string[]
  permissions: string[]
}

const capabilities = import.meta.glob<Capability>('../src-tauri/capabilities/*.json', {
  eager: true,
  import: 'default',
})

describe('capacités du webview', () => {
  // Toute capacité nouvelle passe par ce test : le webview n'a que le noyau
  // de Tauri et, sur mobile, le scanner du QR code d'appairage.
  it('se limitent à core:default et, sur mobile, au scanner', () => {
    const byFile = Object.fromEntries(
      Object.entries(capabilities).map(([path, capability]) => [path.split('/').pop(), capability]),
    )
    expect(Object.keys(byFile).sort()).toEqual(['default.json', 'mobile.json'])
    expect(byFile['default.json']).toMatchObject({ windows: ['main'], permissions: ['core:default'] })
    expect(byFile['default.json']?.platforms).toBeUndefined()
    expect(byFile['mobile.json']).toMatchObject({ windows: ['main'], platforms: ['android', 'iOS'] })
    expect(byFile['mobile.json']?.permissions).toEqual([
      'barcode-scanner:allow-check-permissions',
      'barcode-scanner:allow-request-permissions',
      'barcode-scanner:allow-scan',
      'barcode-scanner:allow-cancel',
    ])
  })
})

describe('webview sans pont global ni page distante', () => {
  const app: { withGlobalTauri?: boolean; windows: Array<Record<string, unknown>> } = tauriConfig.app

  it('n’expose pas window.__TAURI__', () => {
    expect(app.withGlobalTauri ?? false).toBe(false)
  })

  it('ne charge que la page empaquetée', () => {
    for (const window of app.windows) {
      const url = window.url
      if (url !== undefined) expect(String(url)).not.toMatch(/^[a-z][a-z0-9+.-]*:/i)
    }
    expect(tauriConfig.build.frontendDist).not.toMatch(/^[a-z][a-z0-9+.-]*:/i)
    expect(new URL(tauriConfig.build.devUrl).hostname).toBe('localhost')
  })
})

// Sources de l'interface hors tests : Vue et TypeScript.
const sources = import.meta.glob<string>(['./**/*.vue', './**/*.ts', '!./**/*.spec.ts'], {
  eager: true,
  query: '?raw',
  import: 'default',
})

describe('échappement', () => {
  it('vue/no-v-html est une erreur du lint', () => {
    expect(eslintConfig).toMatch(/'vue\/no-v-html':\s*'error'/)
  })

  it('aucun HTML brut dans src, hors tests', () => {
    expect(Object.keys(sources).length).toBeGreaterThan(10)
    for (const [path, source] of Object.entries(sources)) {
      expect(source, path).not.toMatch(/v-html|innerHTML|outerHTML|insertAdjacentHTML/)
    }
  })
})

describe('plugins interdits', () => {
  // fs, shell et http ouvriraient au webview le disque, les processus ou le
  // réseau : refusés, même tirés par une autre dépendance.
  it('aucun dans Cargo.lock', () => {
    const names = [...cargoLock.matchAll(/^name = "([^"]+)"$/gm)].map((m) => m[1])
    expect(names).toContain('tauri')
    expect(names.filter((name) => /^tauri-plugin-(fs|shell|http)$/.test(name ?? ''))).toEqual([])
  })

  it('aucun dans pnpm-lock.yaml', () => {
    expect(pnpmLock).toContain('@tauri-apps/api')
    expect(pnpmLock).not.toMatch(/@tauri-apps\/plugin-(fs|shell|http)\b/)
  })
})

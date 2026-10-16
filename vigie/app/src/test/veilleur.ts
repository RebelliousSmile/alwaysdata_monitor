import { mockIPC } from '@tauri-apps/api/mocks'
import type {
  ApiError,
  Check,
  Incident,
  Overview,
  Settings,
  SiteDetail,
  SiteIncidents,
  Status,
} from '@/lib/api'

// Faux veilleur derrière les commandes Tauri, sur des données fictives : le
// dépôt est public. Site A non conforme (incidents critique, avertissement et
// information, un agent), site B sans rien à signaler.

/** Vendredi 16 octobre 2026, 10:00 à Paris. */
export const NOW = 1792137600
export const MIN = 60
export const HOUR = 3600
export const DAY = 86400

/** Jeton fictif : il ne doit jamais atteindre le webview. */
export const TOKEN = 'jeton-fictif-0123456789abcdef'
export const CODE = 'AAAAAAAAAAAAAAAAAAAAAA'
export const PAIR_LINK = `vigie://pair?u=https://vigie.example.org&c=${CODE}`

export const STATUS: Status = { device_id: 3, name: 'poste de test', url: 'https://vigie.example.org' }

function incident(fields: Partial<Incident> & Pick<Incident, 'id' | 'check' | 'severity' | 'detail' | 'opened_at'>): Incident {
  return {
    site: 'site-a',
    closed_at: null,
    acked_at: null,
    open_notified_at: null,
    close_notified_at: null,
    last_reminder_at: null,
    state: 'open',
    ...fields,
  }
}

function check(fields: Partial<Check> & Pick<Check, 'name'>): Check {
  return {
    interval: 900,
    last_run: NOW - 5 * MIN,
    result: 'ok',
    severity: null,
    detail: null,
    duration_ms: 120,
    observed: null,
    ...fields,
  }
}

const CRITICAL = incident({
  id: 12,
  check: 'agent:core',
  severity: 'critical',
  detail: 'Fichier du cœur modifié : wp-includes/version.php',
  opened_at: NOW - HOUR,
  open_notified_at: NOW - HOUR + MIN,
})

const WARNING = incident({
  id: 13,
  check: 'headers',
  severity: 'warning',
  detail: 'En-tête Content-Security-Policy absent',
  opened_at: NOW - 2 * HOUR,
  open_notified_at: NOW - 2 * HOUR + MIN,
  last_reminder_at: NOW - 30 * MIN,
})

const INFO = incident({
  id: 14,
  check: 'tls',
  severity: 'info',
  detail: 'Certificat valable encore 25 jours',
  opened_at: NOW - 10 * MIN,
})

const CLOSED = incident({
  id: 9,
  check: 'content',
  severity: 'critical',
  detail: 'Texte attendu absent de la page',
  opened_at: NOW - 2 * DAY,
  open_notified_at: NOW - 2 * DAY + MIN,
  closed_at: NOW - 2 * DAY + 30 * MIN,
  close_notified_at: NOW - 2 * DAY + 31 * MIN,
  state: 'closed',
})

const SITE_A: SiteDetail = {
  id: 'site-a',
  url: 'https://site-a.example.org',
  kind: 'wordpress',
  interval: 900,
  agent_silence: 2 * HOUR,
  state: 'non_compliant',
  last_read: NOW - 2 * MIN,
  agent: {
    declared_at: NOW - 30 * DAY,
    last_report_at: NOW - 20 * MIN,
    agent: 'vigie-agent 0.1.0',
    facts: { php: '8.3.12', core: 'wp-includes/version.php' },
  },
  open_incidents: [INFO, WARNING, CRITICAL],
  checks: [
    check({ name: 'content' }),
    check({ name: 'installer' }),
    check({ name: 'exposed' }),
    check({
      name: 'tls',
      result: 'finding',
      severity: 'info',
      detail: 'Certificat valable encore 25 jours',
      observed: { tls_not_after: NOW + 25 * DAY },
    }),
    check({ name: 'headers', result: 'finding', severity: 'warning', detail: WARNING.detail }),
    check({ name: 'heartbeat', interval: 2 * HOUR, last_run: NOW - 20 * MIN }),
    check({
      name: 'agent:core',
      interval: null,
      last_run: NOW - 20 * MIN,
      result: 'finding',
      severity: 'critical',
      detail: CRITICAL.detail,
    }),
  ],
}

const SITE_B: SiteDetail = {
  id: 'site-b',
  url: 'https://site-b.example.org',
  kind: 'generic',
  interval: 900,
  agent_silence: 2 * HOUR,
  state: 'ok',
  last_read: NOW - MIN,
  agent: null,
  open_incidents: [],
  checks: [check({ name: 'content' }), check({ name: 'tls', observed: { tls_not_after: NOW + 80 * DAY } })],
}

type Fixed<T> = { 'site-a': T; 'site-b': T } & Record<string, T>

export interface Fixture {
  overview: Overview
  sites: Fixed<SiteDetail>
  history: Fixed<SiteIncidents>
  settings: Settings
}

/** Copie neuve à chaque appel : un test peut la modifier. */
export function fixture(): Fixture {
  const data: Fixture = {
    overview: {
      server_time: NOW,
      last_tick: NOW - MIN,
      sites: [
        {
          id: 'site-a',
          url: SITE_A.url,
          kind: SITE_A.kind,
          state: SITE_A.state,
          open_count: 2,
          worst: CRITICAL,
          last_read: SITE_A.last_read,
        },
        {
          id: 'site-b',
          url: SITE_B.url,
          kind: SITE_B.kind,
          state: SITE_B.state,
          open_count: 0,
          worst: null,
          last_read: SITE_B.last_read,
        },
      ],
    },
    sites: { 'site-a': SITE_A, 'site-b': SITE_B },
    history: {
      'site-a': { site: 'site-a', since: NOW - 30 * DAY, incidents: [CLOSED] },
      'site-b': { site: 'site-b', since: NOW - 30 * DAY, incidents: [] },
    },
    settings: {
      sites: [
        { id: 'site-a', url: SITE_A.url, kind: 'wordpress', interval: 900, agent_silence: 2 * HOUR, agent: true, checks: { content: 900, tls: DAY } },
        { id: 'site-b', url: SITE_B.url, kind: 'generic', interval: 900, agent_silence: 2 * HOUR, agent: false, checks: { content: 900 } },
      ],
      alerts: { to: 'a…@example.org' },
      reminder_period: 6 * HOUR,
      public_url: 'https://vigie.example.org',
      devices: [
        { id: 3, name: 'poste de test', created_at: NOW - DAY, seen_at: NOW - MIN, revoked_at: null, current: true },
      ],
    },
  }
  return structuredClone(data)
}

/** État du faux veilleur, modifiable pendant un test. */
export interface Veilleur {
  data: Fixture
  paired: boolean
  /** Le veilleur ne répond plus. */
  offline: boolean
  /** Le jeton de l'appareil a été révoqué côté veilleur. */
  revoked: boolean
  /** Commandes reçues, dans l'ordre. */
  calls: string[]
}

const fail = (kind: ApiError['kind'], message: string): ApiError => ({ kind, message })

/** Installe le faux veilleur ; `clearMocks()` le retire. */
export function mockVeilleur(paired = true): Veilleur {
  const state: Veilleur = { data: fixture(), paired, offline: false, revoked: false, calls: [] }

  const reach = (): void => {
    if (!state.paired) throw fail('not_paired', 'cet appareil n’est pas appairé')
    if (state.offline) throw fail('offline', 'le veilleur ne répond pas')
    if (state.revoked) {
      state.paired = false
      throw fail('unauthorized', 'jeton refusé')
    }
  }

  const findIncident = (id: number): Incident | undefined =>
    [
      ...Object.values(state.data.sites).flatMap((s) => s.open_incidents),
      ...Object.values(state.data.history).flatMap((h) => h.incidents),
    ].find((i) => i.id === id)

  function answer(cmd: string, payload: unknown): unknown {
    state.calls.push(cmd)
    const args = (payload ?? {}) as Record<string, unknown>
    switch (cmd) {
      case 'plugin:app|version':
        return '0.1.0'
      case 'status':
        return state.paired ? STATUS : null
      case 'pair':
        state.paired = true
        state.revoked = false
        return STATUS
      case 'unpair': {
        const revoked = !state.offline
        state.paired = false
        return { revoked, device_id: STATUS.device_id }
      }
      case 'overview':
        reach()
        return state.data.overview
      case 'site': {
        reach()
        const site = state.data.sites[String(args.id)]
        if (!site) throw fail('not_found', 'site inconnu')
        return site
      }
      case 'incidents': {
        reach()
        const history = state.data.history[String(args.site)]
        if (!history) throw fail('not_found', 'site inconnu')
        return history
      }
      case 'incident': {
        reach()
        const found = findIncident(Number(args.id))
        if (!found) throw fail('not_found', 'incident inconnu')
        return found
      }
      case 'ack': {
        reach()
        const found = findIncident(Number(args.id))
        if (!found) throw fail('not_found', 'incident inconnu')
        if (found.state === 'closed') throw fail('conflict', 'incident fermé')
        found.state = 'acked'
        found.acked_at = Math.floor(Date.now() / 1000)
        return found
      }
      case 'settings':
        reach()
        return state.data.settings
      default:
        throw new Error(`commande inattendue : ${cmd}`)
    }
  }

  // Copie, comme une réponse sérialisée : le store ne partage rien avec la base.
  mockIPC((cmd, payload) => structuredClone(answer(cmd, payload)))
  return state
}

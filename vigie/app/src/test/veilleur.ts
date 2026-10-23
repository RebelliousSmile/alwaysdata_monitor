import { mockIPC } from '@tauri-apps/api/mocks'
import type {
  ApiError,
  Check,
  Incident,
  LogIps,
  Mail,
  Overview,
  Settings,
  SiteComponents,
  SiteDetail,
  SiteIncidents,
  SiteLogs,
  SiteVulns,
  Status,
  Vuln,
  VulnSources,
} from '@/lib/api'

// Faux veilleur derrière les commandes Tauri, sur des données fictives : le
// dépôt est public. Site A non conforme (incidents critique, avertissement et
// information, un agent, une analyse des logs, des failles fictives
// `CVE-2099-…` aux attributions d'un titulaire inventé et aux liens
// `example.org`), site B sans rien à signaler, sans source de logs ni
// inventaire. IP des plages de documentation (RFC 5737, 3849).

/** Vendredi 16 octobre 2026, 10:00 à Paris. */
export const NOW = 1792137600
export const MIN = 60
export const HOUR = 3600
export const DAY = 86400

/** Jeton fictif : il ne doit jamais atteindre le webview. */
export const TOKEN = 'jeton-fictif-0123456789abcdef'
export const CODE = 'AAAAAAAAAAAAAAAAAAAAAA'
export const PAIR_LINK = `vigie://pair?u=https://vigie.example.org&c=${CODE}`

export const STATUS: Status = {
  device_id: 3,
  name: 'poste de test',
  url: 'https://vigie.example.org',
  token_storage: 'keyring',
}

function incident(fields: Partial<Incident> & Pick<Incident, 'id' | 'check' | 'severity' | 'detail' | 'opened_at'>): Incident {
  return {
    site: 'site-a',
    closed_at: null,
    acked_at: null,
    open_notified_at: null,
    close_notified_at: null,
    last_reminder_at: null,
    snoozed_until: null,
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
  /** Première page des incidents clos. */
  history: Fixed<SiteIncidents>
  /** Pages suivantes, par curseur. */
  moreHistory: Record<string, SiteIncidents>
  /** Analyse des logs ; un site absent répond 404 (sans source). */
  logs: Record<string, SiteLogs>
  /** Première page des verdicts d'IP ; absent : 404. */
  ips: Record<string, LogIps>
  /** Pages suivantes des verdicts, par curseur. */
  moreIps: Record<string, LogIps>
  /** Première page des composants rapprochés ; absent : 404 (sans inventaire). */
  components: Record<string, SiteComponents>
  moreComponents: Record<string, SiteComponents>
  /** Première page des failles ; absent : 404 (sans inventaire). */
  vulns: Record<string, SiteVulns>
  moreVulns: Record<string, SiteVulns>
  vulnSources: VulnSources
  settings: Settings
}

/** Attribution fictive d'une source « usage interne ». */
export const ATTRIBUTION = 'Copyright 2099 Exemple Intelligence SARL, données fictives (https://example.org/licence)'

function vuln(fields: Partial<Vuln> & Pick<Vuln, 'group' | 'component' | 'severity'>): Vuln {
  return {
    ids: [fields.group],
    versions: [{ source: 'agent', version: '1.2.3' }],
    verdict: 'affected',
    corrected: false,
    fixed: ['1.2.4'],
    rule: 'cvss_high',
    kev: null,
    epss: null,
    score: 75,
    redistribution: 'free',
    waiver: null,
    links: [{ source: 'osv-packagist', url: `https://example.org/avis/${fields.group}` }],
    attributions: ['Données fictives de démonstration (https://example.org/)'],
    ...fields,
  }
}

const PLUGIN = 'pkg:wordpress/plugin/exemple-plugin'
const PAQUET = 'pkg:composer/exemple/paquet'

const VULNS_A: SiteVulns = {
  site: 'site-a',
  runs: { agent: 4, ci: 5 },
  items: [
    vuln({
      group: 'CVE-2099-0002',
      ids: ['CVE-2099-0002', 'WF-2099-0002'],
      component: PLUGIN,
      severity: 'critical',
      versions: [
        { source: 'agent', version: '1.2.3' },
        { source: 'ci', version: '1.2.4' },
      ],
      rule: 'kev',
      kev: { date_added: '2099-01-10', ransomware: false },
      epss: { score: 123_456, percentile: 900_000 },
      score: 98,
      redistribution: 'internal',
      links: [{ source: 'wordfence', url: 'https://example.org/avis/WF-2099-0002' }],
      attributions: [ATTRIBUTION],
    }),
    vuln({
      group: 'CVE-2099-0003',
      component: PAQUET,
      severity: 'warning',
      redistribution: 'facts_only',
      waiver: { source: 'agent', until: NOW + 30 * DAY, state: 'valid' },
    }),
    vuln({
      group: 'GHSA-2099-aaaa-0004',
      component: 'pkg:npm/%40exemple/paquet',
      severity: 'info',
      verdict: 'version_unknown',
      versions: [{ source: 'ci', version: null }],
      fixed: [],
      rule: 'version_unknown',
      score: null,
      attributions: ['<b>Attribution</b> \ufffd fictive'],
    }),
  ],
  next_cursor: 'vulns-2',
}

const VULNS_A_2: SiteVulns = {
  site: 'site-a',
  runs: VULNS_A.runs,
  items: [
    vuln({
      group: 'CVE-2099-0005',
      component: 'pkg:wordpress/theme/exemple-theme',
      severity: 'warning',
      verdict: 'range_unknown',
      fixed: [],
      rule: 'range_unknown',
    }),
  ],
  next_cursor: null,
}

const COMPONENTS_A: SiteComponents = {
  site: 'site-a',
  runs: VULNS_A.runs,
  items: [
    { source: 'agent', purl: PLUGIN, version: '1.2.3', scope: 'required', vulns: 1, severity: 'critical' },
    { source: 'agent', purl: PAQUET, version: '1.2.3', scope: 'required', vulns: 1, severity: 'warning' },
  ],
  next_cursor: 'components-2',
}

const COMPONENTS_A_2: SiteComponents = {
  site: 'site-a',
  runs: VULNS_A.runs,
  items: [{ source: 'ci', purl: 'pkg:npm/sans-faille', version: '1.0.0', scope: 'required', vulns: 0, severity: null }],
  next_cursor: null,
}

const SOURCES: VulnSources = {
  sources: [
    {
      id: 'osv-packagist',
      kind: 'vulns',
      last_success_at: NOW - 3 * HOUR,
      last_outcome: 'loaded',
      entries: 1200,
      license: '',
      attribution: 'Données fictives de démonstration (https://example.org/)',
      redistribution: 'free',
      dataset: null,
      incident: null,
    },
    {
      id: 'wordfence',
      kind: 'vulns',
      last_success_at: NOW - 4 * DAY,
      last_outcome: 'failed',
      entries: 300,
      license: 'licence fictive',
      attribution: ATTRIBUTION,
      redistribution: 'internal',
      dataset: null,
      incident: { id: 21, severity: 'warning', opened_at: NOW - DAY },
    },
    {
      id: 'kev',
      kind: 'enrichment',
      last_success_at: NOW - HOUR,
      last_outcome: 'loaded',
      entries: 20,
      license: 'licence fictive',
      attribution: 'Données fictives (https://example.org/)',
      redistribution: 'free',
      dataset: { version: '2099.01.15', released: NOW - DAY },
      incident: null,
    },
    {
      id: 'epss',
      kind: 'enrichment',
      last_success_at: null,
      last_outcome: null,
      entries: 0,
      license: '',
      attribution: '',
      redistribution: 'free',
      dataset: null,
      incident: null,
    },
  ],
}

/** Heure de référence de l'analyse : 09:55 à Paris. */
const ANALYSED = NOW - 5 * MIN
/** Tranche horaire (`timestamp_ms / 3 600 000`) de `seconds`. */
const hourOf = (seconds: number): number => Math.floor(seconds / HOUR)

const LOGS_A: SiteLogs = {
  analysis: {
    generated_at: ANALYSED,
    bots: [
      {
        name: 'GPTBot',
        publisher: 'OpenAI',
        purpose: 'Collecte pour l’entraînement de modèles',
        honours_robots: true,
        class: 'ai_training',
        protected: false,
        requests: 42,
      },
      {
        name: 'Googlebot',
        publisher: 'Google',
        purpose: 'Indexation du moteur de recherche',
        honours_robots: true,
        class: 'search_engine',
        protected: true,
        requests: 17,
      },
    ],
    scored: 31,
    unscored: 2,
    rules: [
      {
        rule: 'spike-404',
        scope: 'site',
        severity: 'warning',
        window_secs: 300,
        min_count: 100,
        count: 140,
        distinct_ips: 12,
        exceeded: true,
      },
      {
        rule: 'login-burst',
        scope: 'ip',
        severity: 'critical',
        window_secs: 60,
        min_count: 20,
        count: 3,
        distinct_ips: 1,
        exceeded: false,
      },
    ],
    load: [
      { hour: hourOf(NOW - 2 * HOUR), requests: 300, refused: 4, timed: 300, service_us: 120_000_000, bots: 30 },
      { hour: hourOf(NOW - HOUR), requests: 900, refused: 12, timed: 900, service_us: 2_000_000_000, bots: 450 },
      { hour: hourOf(NOW), requests: 150, refused: 0, timed: 0, service_us: 0, bots: 15 },
    ],
    load_threshold_us: 1_800_000_000,
  },
}

const IPS_A: LogIps = {
  site: 'site-a',
  generated_at: ANALYSED,
  items: [
    { ip: '192.0.2.10', score: 85, level: 'eleve', reasons: ['facets', 'tool_user_agent'], class: 'tool' },
    { ip: '2001:db8:1::5', score: 62, level: 'moyen', reasons: ['burst', 'other'], class: 'browser' },
  ],
  next_cursor: 'ips-2',
}

const IPS_A_2: LogIps = {
  site: 'site-a',
  generated_at: ANALYSED,
  items: [{ ip: '198.51.100.7', score: 55, level: 'moyen', reasons: ['no_referer'], class: 'browser' }],
  next_cursor: null,
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
      'site-a': { site: 'site-a', since: NOW - 30 * DAY, incidents: [CLOSED], next_cursor: null },
      'site-b': { site: 'site-b', since: NOW - 30 * DAY, incidents: [], next_cursor: null },
    },
    moreHistory: {},
    logs: { 'site-a': LOGS_A },
    ips: { 'site-a': IPS_A },
    moreIps: { 'ips-2': IPS_A_2 },
    components: { 'site-a': COMPONENTS_A },
    moreComponents: { 'components-2': COMPONENTS_A_2 },
    vulns: { 'site-a': VULNS_A },
    moreVulns: { 'vulns-2': VULNS_A_2 },
    vulnSources: SOURCES,
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
  /** Appareil rendu par `status` et `pair`. */
  status: Status
  paired: boolean
  /** Le veilleur ne répond plus. */
  offline: boolean
  /** Le jeton de l'appareil a été révoqué côté veilleur. */
  revoked: boolean
  /** Tout curseur est refusé : instantané purgé (`cursor_expired`). */
  expired: boolean
  /** Limite de débit dépassée : 429, à réessayer dans 12 s. */
  limited: boolean
  /** Commandes reçues, dans l'ordre. */
  calls: string[]
}

const fail = (kind: ApiError['kind'], message: string): ApiError => ({ kind, message })

/** Installe le faux veilleur ; `clearMocks()` le retire. */
export function mockVeilleur(paired = true): Veilleur {
  const state: Veilleur = { data: fixture(), status: { ...STATUS }, paired, offline: false, revoked: false, expired: false, limited: false, calls: [] }

  const reach = (): void => {
    if (!state.paired) throw fail('not_paired', 'cet appareil n’est pas appairé')
    if (state.offline) throw fail('offline', 'le veilleur ne répond pas')
    if (state.revoked) {
      state.paired = false
      throw fail('unauthorized', 'jeton refusé')
    }
    if (state.limited) throw fail('too_many_requests', 'trop de requêtes, réessayer dans 12 s')
  }

  /** Page suivante d'une liste, ou `cursor_expired`. */
  const page = <T>(pages: Record<string, T>, cursor: unknown): T => {
    const found = typeof cursor === 'string' ? pages[cursor] : undefined
    if (state.expired || !found) throw fail('cursor_expired', 'la liste reprend au début')
    return found
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
        return state.paired ? state.status : null
      case 'pair':
        state.paired = true
        state.revoked = false
        return state.status
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
        return args.cursor ? page(state.data.moreHistory, args.cursor) : history
      }
      case 'logs': {
        reach()
        const logs = state.data.logs[String(args.site)]
        if (!logs) throw fail('not_found', 'introuvable')
        return logs
      }
      case 'log_ips': {
        reach()
        const ips = state.data.ips[String(args.site)]
        if (!ips) throw fail('not_found', 'introuvable')
        return args.cursor ? page(state.data.moreIps, args.cursor) : ips
      }
      case 'components': {
        reach()
        const components = state.data.components[String(args.site)]
        if (!components) throw fail('not_found', 'introuvable')
        return args.cursor ? page(state.data.moreComponents, args.cursor) : components
      }
      case 'vulns': {
        reach()
        const vulns = state.data.vulns[String(args.site)]
        if (!vulns) throw fail('not_found', 'introuvable')
        return args.cursor ? page(state.data.moreVulns, args.cursor) : vulns
      }
      case 'vuln_sources':
        reach()
        return state.data.vulnSources
      case 'incident': {
        reach()
        const found = findIncident(Number(args.id))
        if (!found) throw fail('not_found', 'incident inconnu')
        return found
      }
      case 'incident_mails': {
        reach()
        const found = findIncident(Number(args.id))
        if (!found) throw fail('not_found', 'incident inconnu')
        const sent: [Mail['kind'], number | null][] = [
          ['open', found.open_notified_at],
          ['reminder', found.last_reminder_at],
          ['close', found.close_notified_at],
        ]
        return {
          mails: sent
            .filter((entry): entry is [Mail['kind'], number] => entry[1] !== null)
            .map(([kind, sent_at]) => ({
              kind,
              sent_at,
              subject: `[Vigie] ${kind} n° ${found.id}`,
              body: `Corps fictif du message ${kind}.
Site A : ${found.detail}`,
            })),
        }
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
      case 'snooze': {
        reach()
        const found = findIncident(Number(args.id))
        if (!found) throw fail('not_found', 'incident inconnu')
        if (found.state === 'closed') throw fail('conflict', 'incident fermé')
        const seconds = args.duration === '24h' ? DAY : args.duration === '7d' ? 7 * DAY : null
        if (seconds === null) throw fail('not_found', 'durée inconnue')
        found.snoozed_until = Math.floor(Date.now() / 1000) + seconds
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

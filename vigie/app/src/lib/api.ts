import { invoke } from '@tauri-apps/api/core'

// Commandes Tauri de `src-tauri/src/lib.rs`. Le webview ne fait aucune
// requête réseau et ne reçoit jamais le jeton : seulement les réponses du
// veilleur (`vigie/docs/api-console.md`), réduites aux champs affichés.

export type Severity = 'info' | 'warning' | 'critical'
export type IncidentState = 'open' | 'acked' | 'closed'
export type SiteState = 'non_compliant' | 'blind' | 'to_check' | 'first_read' | 'ok'
export type CheckResult = 'ok' | 'finding' | 'error'

export interface Incident {
  id: number
  site: string
  check: string
  severity: Severity
  detail: string
  opened_at: number
  closed_at: number | null
  acked_at: number | null
  open_notified_at: number | null
  close_notified_at: number | null
  last_reminder_at: number | null
  state: IncidentState
}

export interface OverviewSite {
  id: string
  url: string
  kind: string
  state: SiteState
  /** Incidents ouverts hors information. */
  open_count: number
  worst: Incident | null
  last_read: number | null
}

export interface Overview {
  server_time: number
  last_tick: number | null
  /** Déjà triés par état, puis dans l'ordre de la configuration. */
  sites: OverviewSite[]
}

export interface Agent {
  declared_at: number
  last_report_at: number | null
  agent: string | null
  facts: unknown
}

export interface Check {
  name: string
  interval: number | null
  last_run: number | null
  result: CheckResult | null
  severity: Severity | null
  detail: string | null
  duration_ms: number | null
  observed: unknown
}

export interface SiteDetail {
  id: string
  url: string
  kind: string
  interval: number
  agent_silence: number
  state: SiteState
  last_read: number | null
  agent: Agent | null
  open_incidents: Incident[]
  checks: Check[]
}

/** Une page des incidents clos ; `next_cursor` à `null` sur la dernière. */
export interface SiteIncidents {
  site: string
  since: number
  incidents: Incident[]
  next_cursor: string | null
}

// Analyse des logs (#8). Les textes (`name`, `publisher`, `purpose`, `rule`,
// `ip`) viennent des logs : ils ne s'affichent qu'en interpolation de texte.

/** Robot du catalogue vu sur 24 h. */
export interface Bot {
  name: string
  publisher: string
  purpose: string
  honours_robots: boolean
  /** `search_engine`, `ai_training`… */
  class: string
  /** Jamais visé par une action robots.txt ou user-agent. */
  protected: boolean
  requests: number
}

/** Règle de l'analyse sur sa fenêtre ; aucune IP. */
export interface Rule {
  rule: string
  scope: 'ip' | 'site' | string
  severity: Severity
  window_secs: number
  min_count: number
  count: number
  distinct_ips: number
  exceeded: boolean
}

/** Charge d'une heure ; `hour` vaut `timestamp_ms / 3 600 000`. */
export interface LoadHour {
  hour: number
  requests: number
  refused: number
  /** Requêtes dont le log porte une durée. */
  timed: number
  service_us: number
  /** Requêtes de robots du catalogue. */
  bots: number
}

export interface Analysis {
  generated_at: number
  bots: Bot[]
  scored: number
  unscored: number
  rules: Rule[]
  load: LoadHour[]
  load_threshold_us: number
}

/** `analysis` à `null` : source déclarée, aucune analyse encore. */
export interface SiteLogs {
  analysis: Analysis | null
}

/** Verdict d'une IP : codes de raison, jamais de user-agent ni de chemin. */
export interface Verdict {
  ip: string
  score: number
  level: 'moyen' | 'eleve' | string
  reasons: string[]
  class: string
}

/** Une page des verdicts d'IP d'un instantané. */
export interface LogIps {
  site: string
  /** `null` : aucun instantané de moins de 48 h. */
  generated_at: number | null
  items: Verdict[]
  next_cursor: string | null
}

export interface SettingsSite {
  id: string
  url: string
  kind: string
  interval: number
  agent_silence: number
  agent: boolean
  checks: Record<string, number>
}

export interface Device {
  id: number
  name: string
  created_at: number
  seen_at: number | null
  revoked_at: number | null
  current: boolean
}

export interface Settings {
  sites: SettingsSite[]
  /** Destinataire masqué par le veilleur. */
  alerts: { to: string }
  reminder_period: number
  public_url: string | null
  devices: Device[]
}

/**
 * Où vit le jeton de l'appareil : Credential Manager (Windows), fichier
 * privé hors sauvegarde (Android), ou encore dans le fichier de l'appareil
 * parce que sa migration a échoué (seul état dégradé, retenté à chaque
 * lancement).
 */
export type TokenStorage = 'keyring' | 'file_legacy' | 'private_file'

/** Ce que le webview sait de l'appareil appairé : jamais le jeton. */
export interface Status {
  device_id: number
  name: string
  url: string
  token_storage: TokenStorage
}

export interface Unpaired {
  /** `false` : veilleur injoignable, l'appareil reste à révoquer en CLI. */
  revoked: boolean
  device_id: number
}

export type ErrorKind =
  | 'offline'
  | 'unauthorized'
  | 'not_found'
  | 'conflict'
  | 'cursor_expired'
  | 'bad_request'
  | 'unsupported_media_type'
  | 'too_many_requests'
  | 'server'
  | 'invalid_link'
  | 'not_paired'
  | 'storage'

export interface ApiError {
  kind: ErrorKind
  message: string
}

/**
 * Texte lisible d'une erreur quelconque. Un plugin mobile rejette souvent un
 * objet, que `String()` réduirait à « [object Object] ».
 */
export function errorText(err: unknown): string {
  if (typeof err === 'string') return err
  if (err instanceof Error) return err.message
  if (typeof err === 'object' && err !== null) {
    const { message } = err as { message?: unknown }
    if (typeof message === 'string') return message
    try {
      return JSON.stringify(err)
    } catch {
      return 'erreur inconnue'
    }
  }
  return String(err)
}

export function isApiError(value: unknown): value is ApiError {
  return (
    typeof value === 'object' &&
    value !== null &&
    typeof (value as ApiError).kind === 'string' &&
    typeof (value as ApiError).message === 'string'
  )
}

async function call<T>(cmd: string, args?: Record<string, unknown>): Promise<T> {
  try {
    return await invoke<T>(cmd, args)
  } catch (err) {
    if (isApiError(err)) throw err
    // Hors de Tauri (navigateur, tests sans mock) : aucune commande.
    throw { kind: 'server', message: errorText(err) } satisfies ApiError
  }
}

export const api = {
  status: () => call<Status | null>('status'),
  pair: (link: string) => call<Status>('pair', { link }),
  unpair: () => call<Unpaired>('unpair'),
  overview: () => call<Overview>('overview'),
  site: (id: string) => call<SiteDetail>('site', { id }),
  /** Une page ; sans `cursor`, la première. */
  incidents: (site: string, cursor: string | null = null) => call<SiteIncidents>('incidents', { site, cursor }),
  logs: (site: string) => call<SiteLogs>('logs', { site }),
  /** Une page ; sans `cursor`, la première. */
  logIps: (site: string, cursor: string | null = null) => call<LogIps>('log_ips', { site, cursor }),
  incident: (id: number) => call<Incident>('incident', { id }),
  ack: (id: number) => call<Incident>('ack', { id }),
  settings: () => call<Settings>('settings'),
}

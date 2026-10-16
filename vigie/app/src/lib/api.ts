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

export interface SiteIncidents {
  site: string
  since: number
  incidents: Incident[]
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

/** Ce que le webview sait de l'appareil appairé. */
export interface Status {
  device_id: number
  name: string
  url: string
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
  incidents: (site: string) => call<SiteIncidents>('incidents', { site }),
  incident: (id: number) => call<Incident>('incident', { id }),
  ack: (id: number) => call<Incident>('ack', { id }),
  settings: () => call<Settings>('settings'),
}

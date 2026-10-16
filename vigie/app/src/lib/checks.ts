import type { Check, Incident, Severity, SiteDetail } from '@/lib/api'
import type { State, Tone } from '@/lib/state'

// Libellés et regroupements des contrôles et des incidents du veilleur.

/** Contrôles externes, dans l'ordre de l'API. */
export const EXTERNAL_CHECKS: readonly string[] = ['content', 'installer', 'exposed', 'tls', 'headers']

const LABELS: Record<string, string> = {
  content: 'Contenu de la page',
  installer: 'Installeur exposé',
  exposed: 'Fichiers exposés',
  tls: 'Certificat TLS',
  headers: 'En-têtes de sécurité',
  heartbeat: 'Silence de l’agent',
  'agent:integrity': 'Intégrité des fichiers critiques',
  'agent:critical-file': 'Fichiers critiques',
  'agent:must-contain': 'Texte attendu dans les fichiers',
  'agent:root': 'Racine du site',
  'agent:uploads-php': 'PHP dans les uploads',
}

export function checkLabel(name: string): string {
  if (LABELS[name]) return LABELS[name]
  if (name.startsWith('agent:')) return `Agent · ${name.slice('agent:'.length)}`
  return name
}

export const isExternal = (name: string): boolean => EXTERNAL_CHECKS.includes(name)

/** Écran où un point se lit en détail. */
export function checkScreen(name: string): { label: string; route: string } {
  return isExternal(name)
    ? { label: 'Santé › Disponibilité', route: 'sante' }
    : { label: 'Santé › Contrôles', route: 'controles' }
}

const RANK: Record<Severity, number> = { critical: 0, warning: 1, info: 2 }

export const SEVERITY_LABEL: Record<Severity, string> = {
  critical: 'Critique',
  warning: 'Avertissement',
  info: 'Information',
}

export const SEVERITY_STATE: Record<Severity, State> = {
  critical: 'non_compliant',
  warning: 'to_check',
  info: 'first_read',
}

export const SEVERITY_TONE: Record<Severity, Tone> = {
  critical: 'danger',
  warning: 'warn',
  info: 'info',
}

/** Du plus grave au moins grave, puis du plus ancien au plus récent. */
export function bySeverity(a: Incident, b: Incident): number {
  return RANK[a.severity] - RANK[b.severity] || a.opened_at - b.opened_at
}

export const isSerious = (incident: Incident): boolean => incident.severity !== 'info'

/** Puce du dernier passage d'un contrôle. */
export function resultChip(check: Check): { tone: Tone; label: string } {
  switch (check.result) {
    case 'ok':
      return { tone: 'ok', label: 'Rien à signaler' }
    case 'finding':
      return check.severity
        ? { tone: SEVERITY_TONE[check.severity], label: SEVERITY_LABEL[check.severity] }
        : { tone: 'warn', label: 'Constat' }
    case 'error':
      return { tone: 'neutral', label: 'Non concluant' }
    default:
      return { tone: 'info', label: 'Jamais passé' }
  }
}

/** Badges de la barre : À traiter et Santé, incidents sérieux ouverts. */
export function siteBadges(detail: SiteDetail): { 'a-traiter': number; sante: number } {
  const serious = detail.open_incidents.filter(isSerious)
  const listed = new Set(detail.checks.map((c) => c.name))
  return {
    'a-traiter': serious.length,
    sante: serious.filter((i) => listed.has(i.check)).length,
  }
}

/** Date d'expiration du certificat, relevée par le contrôle tls. */
export function tlsNotAfter(checks: readonly Check[]): number | null {
  const observed = checks.find((c) => c.name === 'tls')?.observed
  if (typeof observed !== 'object' || observed === null) return null
  const value = (observed as Record<string, unknown>).tls_not_after
  return typeof value === 'number' ? value : null
}

export interface MailEvent {
  at: number
  kind: 'Ouverture' | 'Relance' | 'Clôture'
  incident: Incident
}

/** E-mails envoyés, tirés des dates de notification, du plus récent au plus ancien. */
export function mailEvents(incidents: readonly Incident[]): MailEvent[] {
  const seen = new Set<number>()
  const events: MailEvent[] = []
  for (const incident of incidents) {
    if (seen.has(incident.id)) continue
    seen.add(incident.id)
    if (incident.open_notified_at !== null) {
      events.push({ at: incident.open_notified_at, kind: 'Ouverture', incident })
    }
    if (incident.last_reminder_at !== null) {
      events.push({ at: incident.last_reminder_at, kind: 'Relance', incident })
    }
    if (incident.close_notified_at !== null) {
      events.push({ at: incident.close_notified_at, kind: 'Clôture', incident })
    }
  }
  return events.sort((a, b) => b.at - a.at)
}

/** Faits du rapport d'agent, à plat : clé et valeur lisible. */
export function factEntries(facts: unknown): [string, string][] {
  if (typeof facts !== 'object' || facts === null || Array.isArray(facts)) return []
  return Object.entries(facts as Record<string, unknown>).map(([key, value]) => [
    key,
    typeof value === 'string' ? value : JSON.stringify(value),
  ])
}

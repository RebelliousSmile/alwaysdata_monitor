import type { Redistribution, Severity, Vuln } from '@/lib/api'
import type { Tone } from '@/lib/state'

// Libellés de l'écran Failles (#21). La gravité vient du veilleur, règle de
// F4 : la console ne recalcule rien.

const RANK: Record<Severity, number> = { critical: 0, warning: 1, info: 2 }

const VERDICTS: Record<string, string> = {
  affected: 'Touché',
  version_unknown: 'Version inconnue',
  range_unknown: 'Plage inconnue',
}

/** « Touché », « Version inconnue », « Plage inconnue » : jamais « aucune faille ». */
export function verdictLabel(verdict: string): string {
  return VERDICTS[verdict] ?? verdict
}

const RULES: Record<string, string> = {
  kev: 'exploitée (CISA KEV)',
  malicious: 'paquet malveillant',
  cvss_critical: 'CVSS ≥ 9,0',
  cvss_high: 'CVSS ≥ 7,0',
  epss: 'EPSS ≥ 0,1',
  unknown_severity: 'gravité inconnue',
  informational: 'informational (Wordfence)',
  version_unknown: 'version inconnue',
  range_unknown: 'plage inconnue',
}

export function ruleLabel(rule: string): string {
  return RULES[rule] ?? 'aucune règle'
}

/** Mention de redistribution d'une faille ; rien pour une source libre. */
export function redistributionLabel(level: Redistribution | string): string | null {
  if (level === 'free') return null
  if (level === 'facts_only') return 'Faits seulement : ne pas transmettre le texte de l’avis'
  return 'Usage interne : ne pas transmettre à un client'
}

const WAIVER_STATES: Record<string, string> = {
  valid: 'valide',
  expired: 'expirée',
  version_changed: 'caduque, version changée',
  group_changed: 'caduque, groupe changé',
  kev: 'caduque, faille exploitée',
}

export function waiverLabel(state: string): string {
  return WAIVER_STATES[state] ?? state
}

/** CVSS en dixièmes, à la française : « 9,8 ». */
export function cvss(tenths: number): string {
  return `${Math.floor(tenths / 10)},${tenths % 10}`
}

/** Millionièmes en pour cent, une décimale : « 12,3 % ». */
export function percent(ppm: number): string {
  const tenths = Math.floor(ppm / 1000)
  return `${Math.floor(tenths / 10)},${tenths % 10} %`
}

export function severityTone(severity: Severity): Tone {
  return severity === 'critical' ? 'danger' : severity === 'warning' ? 'warn' : 'info'
}

/** Correctif lisible : « corrigée en 1.2.4 », ou « aucun correctif ». */
export function fixText(vuln: Vuln): string | null {
  if (vuln.verdict !== 'affected') return null
  return vuln.fixed.length ? `corrigée en ${vuln.fixed.join(' ou ')}` : 'aucun correctif'
}

/** Versions vues : « agent 1.2.3 · ci 1.2.4 ». */
export function versionsText(vuln: Vuln): string {
  return vuln.versions.map((v) => `${v.source} ${v.version ?? 'version inconnue'}`).join(' · ')
}

export interface ComponentGroup {
  purl: string
  severity: Severity
  vulns: Vuln[]
  /** Une faille touchée a un correctif. */
  fixable: boolean
}

/** Failles regroupées par composant, du plus grave au moins grave. */
export function byComponent(vulns: readonly Vuln[]): ComponentGroup[] {
  const groups = new Map<string, ComponentGroup>()
  for (const vuln of vulns) {
    let group = groups.get(vuln.component)
    if (!group) {
      group = { purl: vuln.component, severity: vuln.severity, vulns: [], fixable: false }
      groups.set(vuln.component, group)
    }
    group.vulns.push(vuln)
    if (RANK[vuln.severity] < RANK[group.severity]) group.severity = vuln.severity
    if (vuln.verdict === 'affected' && vuln.fixed.length) group.fixable = true
  }
  return [...groups.values()].sort(
    (a, b) => RANK[a.severity] - RANK[b.severity] || a.purl.localeCompare(b.purl),
  )
}

// États affichés par la console. Les cinq premiers sont ceux de l'API
// (`SiteState` du veilleur) ; `choice` est le « choix assumé » des contrôles.
// Chaque état porte un symbole et un libellé : jamais la couleur seule.

export type State = 'non_compliant' | 'blind' | 'to_check' | 'first_read' | 'ok' | 'choice'

export interface StateMeta {
  symbol: string
  label: string
  /** Classes Tailwind du symbole, tirées des jetons. */
  tone: string
  /** Contour d'une ligne dans cet état. */
  border: string
}

export const STATES: Record<State, StateMeta> = {
  non_compliant: { symbol: '×', label: 'Non conforme', tone: 'bg-danger-bg text-danger', border: 'border-danger-line' },
  blind: { symbol: '?', label: 'Aveugle', tone: 'bg-surface-3 text-text', border: 'border-control' },
  to_check: { symbol: '!', label: 'À vérifier', tone: 'bg-warn-bg text-warn', border: 'border-line' },
  first_read: { symbol: 'i', label: 'Première lecture', tone: 'bg-info-bg text-info', border: 'border-line' },
  ok: { symbol: '✓', label: 'OK', tone: 'bg-ok-bg text-ok', border: 'border-line' },
  choice: { symbol: 'i', label: 'Choix assumé', tone: 'bg-info-bg text-info', border: 'border-line' },
}

/** Ordre de l'écran Mes sites : le plus urgent d'abord. */
export const SITE_ORDER: readonly State[] = ['non_compliant', 'blind', 'to_check', 'first_read', 'ok']

export type Tone = 'danger' | 'warn' | 'info' | 'ok' | 'neutral'

export const TONES: Record<Tone, { symbol: string; classes: string }> = {
  danger: { symbol: '×', classes: 'bg-danger-bg text-danger' },
  warn: { symbol: '!', classes: 'bg-warn-bg text-warn' },
  info: { symbol: 'i', classes: 'bg-info-bg text-info' },
  ok: { symbol: '✓', classes: 'bg-ok-bg text-ok' },
  neutral: { symbol: '·', classes: 'bg-neutral-bg text-neutral' },
}

import type { IconName } from '@/lib/icons'
import type { NavKey, SegmentGroup } from '@/router'

// Barre d'un site (HANDOFF §3) et segments de Trafic et de Santé.

export interface NavItem {
  key: NavKey
  label: string
  icon: IconName
  /** Route ouverte par l'onglet. */
  name: string
}

export const SITE_NAV: readonly NavItem[] = [
  { key: 'a-traiter', label: 'À traiter', icon: 'todo', name: 'a-traiter' },
  { key: 'trafic', label: 'Trafic', icon: 'traffic', name: 'trafic' },
  { key: 'erreurs', label: 'Erreurs', icon: 'errors', name: 'erreurs' },
  { key: 'sante', label: 'Santé', icon: 'health', name: 'sante' },
]

/**
 * Nombre de points ouverts par onglet. Trafic et Erreurs n'ont pas de
 * points ouverts à compter : leur badge n'existe pas, pas même « 0 ».
 */
export interface NavBadges {
  'a-traiter'?: number
  sante?: number
}

export function badgeOf(badges: NavBadges, key: NavKey): number | undefined {
  if (key !== 'a-traiter' && key !== 'sante') return undefined
  const count = badges[key]
  return count !== undefined && count > 0 ? count : undefined
}

export const SEGMENTS: Record<SegmentGroup, { label: string; name: string }[]> = {
  trafic: [
    { label: 'Visiteurs', name: 'trafic' },
    { label: 'Journal', name: 'journal' },
    { label: 'Blocages', name: 'blocages' },
  ],
  sante: [
    { label: 'Disponibilité', name: 'sante' },
    { label: 'Ressources', name: 'ressources' },
    { label: 'Contrôles', name: 'controles' },
  ],
}

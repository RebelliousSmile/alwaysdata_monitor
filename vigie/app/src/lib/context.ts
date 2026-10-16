import type { LocationQuery, LocationQueryRaw } from 'vue-router'

// Contexte transmis par tout lien interne (HANDOFF §3) : jour, fenêtre
// horaire, sources et filtre.
export const CONTEXT_KEYS = ['date', 'de', 'a', 'src', 'q'] as const

/** Garde du `query` courant les seules clés de contexte. */
export function pickContext(query: LocationQuery): LocationQueryRaw {
  const kept: LocationQueryRaw = {}
  for (const key of CONTEXT_KEYS) {
    const value = query[key]
    if (value !== undefined && value !== null && value !== '') kept[key] = value
  }
  return kept
}

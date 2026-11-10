// Thème de la console : sombre par défaut, clair au choix. Le choix est une
// préférence d'affichage, mémorisée sur l'appareil ; rien n'est envoyé au
// veilleur. Le stockage du webview peut manquer ou refuser (mode privé,
// politique du système) : la console reste alors en sombre, sans erreur.

export type Theme = 'dark' | 'light'

export const THEMES: { value: Theme; label: string }[] = [
  { value: 'dark', label: 'Sombre' },
  { value: 'light', label: 'Clair' },
]

export const THEME_KEY = 'vigie.theme'
export const DEFAULT_THEME: Theme = 'dark'

export const isTheme = (value: unknown): value is Theme => value === 'dark' || value === 'light'

export function readTheme(storage: Pick<Storage, 'getItem'> | null = safeStorage()): Theme {
  try {
    const value = storage?.getItem(THEME_KEY)
    return isTheme(value) ? value : DEFAULT_THEME
  } catch {
    return DEFAULT_THEME
  }
}

export function saveTheme(theme: Theme, storage: Pick<Storage, 'setItem'> | null = safeStorage()): void {
  try {
    storage?.setItem(THEME_KEY, theme)
  } catch {
    // Choix valable pour cette session seulement.
  }
}

/** Applique le thème à la page : jetons (`data-theme`) et schéma de couleurs des contrôles natifs. */
export function applyTheme(theme: Theme, doc: Document = document): void {
  doc.documentElement.dataset.theme = theme
  doc.querySelector('meta[name="color-scheme"]')?.setAttribute('content', theme)
}

function safeStorage(): Storage | null {
  try {
    return typeof localStorage === 'undefined' ? null : localStorage
  } catch {
    return null
  }
}

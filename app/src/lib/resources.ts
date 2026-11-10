// Ressources du compte, relevées par l'agent PHP depuis l'intérieur du compte
// (`"resources": true` dans sa config.json) et portées par les `facts` du
// dernier rapport. Une valeur absente reste absente : rien n'est complété.

export interface AccountResources {
  /** Mémoire utilisée, Mo ; `limit` absent quand l'agent n'a pas lu de cgroup. */
  ram: { used: number; limit: number | null } | null
  /** Charge de la machine sur 1, 5 et 15 minutes. */
  load: [number, number, number] | null
  /** Disque du site, Go. */
  disk: { used: number; total: number } | null
}

function num(facts: Record<string, unknown>, key: string): number | null {
  const value = facts[key]
  return typeof value === 'number' && Number.isFinite(value) && value >= 0 ? value : null
}

/** Les ressources lisibles dans `facts`, ou `null` si l'agent n'en a relevé aucune. */
export function accountResources(facts: unknown): AccountResources | null {
  if (typeof facts !== 'object' || facts === null || Array.isArray(facts)) return null
  const f = facts as Record<string, unknown>
  const used = num(f, 'ram_used_mb')
  const [l1, l5, l15] = [num(f, 'load_1'), num(f, 'load_5'), num(f, 'load_15')]
  const [diskUsed, diskTotal] = [num(f, 'disk_used_gb'), num(f, 'disk_total_gb')]
  const resources: AccountResources = {
    ram: used === null ? null : { used, limit: num(f, 'ram_limit_mb') },
    load: l1 === null || l5 === null || l15 === null ? null : [l1, l5, l15],
    disk: diskUsed === null || diskTotal === null || diskTotal === 0 ? null : { used: diskUsed, total: diskTotal },
  }
  return resources.ram || resources.load || resources.disk ? resources : null
}

const number = new Intl.NumberFormat('fr-FR', { maximumFractionDigits: 2 })

export function formatMb(mb: number): string {
  return mb >= 1024 ? `${number.format(mb / 1024)} Go` : `${number.format(mb)} Mo`
}

export function formatGb(gb: number): string {
  return `${number.format(gb)} Go`
}

export function formatLoad(load: number): string {
  return number.format(load)
}

/** Part utilisée, en pourcentage entier, bornée à 100. */
export function percent(used: number, total: number): number {
  return Math.min(100, Math.round((used / total) * 100))
}

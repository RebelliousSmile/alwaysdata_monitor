import type { Bot, LoadHour, Verdict } from '@/lib/api'
import type { Tone } from '@/lib/state'

// Libellés de l'analyse des logs (`vigie/docs/api-console.md`) et
// propositions tirées des maquettes Trafic. La console n'applique rien : une
// action de la maquette devient le texte d'une commande à passer sur le VPS.

/** Classe d'un robot (`BotClass` du veilleur) ; une classe inconnue garde son code. */
export const CLASS_LABEL: Record<string, string> = {
  search_engine: 'Moteur de recherche',
  other_engine: 'Autre moteur',
  social_preview: 'Aperçu de liens',
  ai_training: 'Robot IA (entraînement)',
  ai_search: 'Recherche IA',
  ai_user: 'Assistant IA pour une personne',
  seo: 'Robot SEO',
  tool: 'Outil',
  browser: 'Navigateur',
  unknown: 'Robot inconnu',
}

export const classLabel = (code: string): string => CLASS_LABEL[code] ?? code

/** Raisons d'un verdict, par code. `other` : raison inconnue du veilleur. */
export const REASON_LABEL: Record<string, string> = {
  fake_search_engine: 'se présente comme un moteur sans en être un',
  search_engine: 'moteur de recherche vérifié',
  declared_bot: 'robot déclaré',
  facets: 'beaucoup de pages à facettes',
  no_static_resources: 'aucune ressource statique',
  no_referer: 'pages sans referer',
  tool_user_agent: 'user-agent d’outil',
  user_agent_rotation: 'user-agents qui changent',
  burst: 'rafale de requêtes',
  hosting_network: 'réseau d’hébergeur',
  consumer_isp: 'fournisseur d’accès grand public',
  no_reverse_dns: 'sans DNS inverse',
  shared_signature: 'signature partagée avec d’autres IP',
  other: 'autre raison',
}

export const reasonLabel = (code: string): string => REASON_LABEL[code] ?? code

export function levelChip(level: string): { tone: Tone; label: string } {
  if (level === 'eleve') return { tone: 'danger', label: 'Élevé' }
  if (level === 'moyen') return { tone: 'warn', label: 'Moyen' }
  return { tone: 'neutral', label: level }
}

/** Commande qui calcule les recommandations du site, à passer sur le VPS. */
export const recommendCommand = (site: string): string => `vigie site recommend ${site}`

export interface Option {
  label: string
  effect: string
}

const ALLOW: Option = { label: 'Autoriser', effect: 'Ne serait plus signalé ni bloqué automatiquement.' }

/** Actions de la maquette Visiteurs pour une IP, en propositions. */
export function ipOptions(verdict: Verdict): Option[] {
  if (verdict.ip.includes(':')) {
    return [
      {
        label: 'Bloquer l’abonnement (/64)',
        effect: 'Toutes les adresses de cet abonnement : un foyer, une box. Les autres abonnés ne seraient pas touchés.',
      },
      {
        label: 'Bloquer cette adresse seule',
        effect: 'Plus doux, mais une box IPv6 change souvent d’adresse : le blocage peut ne plus servir demain.',
      },
      ALLOW,
    ]
  }
  return [{ label: 'Bloquer cette IP', effect: 'Réponse 403 sur tout le site, sans lancer PHP.' }, ALLOW]
}

/** Actions de la maquette pour un robot ; aucune pour un robot protégé. */
export function botOptions(bot: Bot): Option[] {
  if (bot.protected) return []
  return [
    { label: 'Bloquer (.htaccess)', effect: 'Réponse 403, même si le robot ignore robots.txt.' },
    { label: 'Interdire dans robots.txt', effect: 'Seuls les robots honnêtes le respectent. Aucun 403.' },
    ALLOW,
  ]
}

/** Début de la tranche horaire, en secondes Unix. */
export const hourStart = (hour: LoadHour): number => hour.hour * 3600

/** Secondes de service, arrondies au dixième : « 12,5 s ». */
export function formatService(us: number): string {
  const seconds = us / 1_000_000
  return `${new Intl.NumberFormat('fr-FR', { maximumFractionDigits: 1 }).format(seconds)} s`
}

/** L'heure dépasse le seuil de charge ; jamais sans durée dans les logs. */
export const overThreshold = (hour: LoadHour, threshold: number): boolean =>
  hour.timed > 0 && hour.service_us > threshold

/** Part des requêtes faites par des robots, en pour cent entier. */
export const botShare = (hour: LoadHour): number =>
  hour.requests > 0 ? Math.round((hour.bots / hour.requests) * 100) : 0

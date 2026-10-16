// Fonctionnalités dessinées dans les maquettes mais sans source de données
// dans le veilleur. Chacune est nommée, dit ce qu'elle montrera et ce qui
// manque pour l'alimenter, sans aucune donnée d'exemple (plan, Décisions).

export type FeatureKey =
  | 'visiteurs'
  | 'journal'
  | 'blocages'
  | 'erreurs'
  | 'ressources'
  | 'ajouter'
  | 'emails'
  | 'theme'
  | 'sourdine'
  | 'file'
  | 'wordpress'
  | 'personnalises'

export interface Feature {
  title: string
  /** Ce que l'écran montrera. */
  shows: string
  /** La source qui manque au veilleur. */
  missing: string
  /** Écran alimenté le plus proche. */
  link?: { label: string; name: string }
}

const LOGS =
  'Les logs du site. Le veilleur reçoit les rapports signés de l’agent et ses propres contrôles externes ; il ne lit aucun log chez l’hébergeur.'

const WRITE =
  'Une écriture sur le site. Le veilleur n’écrit jamais sur un site : aucun accès n’est conservé chez l’hébergeur.'

export const FEATURES: Record<FeatureKey, Feature> = {
  visiteurs: {
    title: 'Visiteurs automatisés',
    shows: 'Les robots et visiteurs automatisés du jour, ceux qui restent à trier en tête, avec leur nature et leur volume.',
    missing: LOGS,
    link: { label: 'Voir la santé du site', name: 'sante' },
  },
  journal: {
    title: 'Journal des requêtes',
    shows: 'Les requêtes regroupées par visiteur et par rafale, toutes sources mêlées dans l’ordre du temps.',
    missing: LOGS,
    link: { label: 'Voir la santé du site', name: 'sante' },
  },
  blocages: {
    title: 'Blocages',
    shows: 'Les règles en place et leurs refus du jour, le blocage manuel, la liste blanche et les sauvegardes du .htaccess.',
    missing: WRITE,
    link: { label: 'Voir les contrôles', name: 'controles' },
  },
  erreurs: {
    title: 'Erreurs',
    shows: 'Les erreurs regroupées par message, avec une sourdine limitée dans le temps.',
    missing: LOGS,
    link: { label: 'Voir les points à traiter', name: 'a-traiter' },
  },
  ressources: {
    title: 'Ressources du compte',
    shows: 'La charge, la mémoire et le disque du compte d’hébergement, partagés entre ses sites, et les moments les plus chargés.',
    missing: 'Un relevé des ressources du compte chez l’hébergeur, que le veilleur ne fait pas.',
    link: { label: 'Voir la disponibilité', name: 'sante' },
  },
  ajouter: {
    title: 'Ajouter un site',
    shows: 'L’ajout guidé d’un site : adresse, détection du CMS, choix des contrôles.',
    missing:
      'Ajouter un site change la confiance accordée au veilleur : il se déclare dans config.toml sur le VPS, puis sa clé d’agent par « vigie site add ».',
    link: { label: 'Revenir à mes sites', name: 'sites' },
  },
  emails: {
    title: 'Modèles d’e-mail',
    shows: 'L’aperçu des e-mails envoyés : alerte immédiate, e-mail du matin, « Vigie ne voit plus le site ».',
    missing: 'Le veilleur n’expose pas ses modèles d’e-mail à la console.',
    link: { label: 'Revenir aux réglages', name: 'reglages' },
  },
  theme: {
    title: 'Thème clair',
    shows: 'Le choix entre le thème sombre et un thème clair aux mêmes jetons.',
    missing: 'Le thème clair n’est pas dessiné ; la console reste en thème sombre.',
  },
  sourdine: {
    title: 'Sourdine',
    shows: 'Faire taire une alerte pour 24 h, 7 jours ou jusqu’à la prochaine mise à jour.',
    missing: 'Le veilleur ne connaît que l’acquittement, qui arrête les relances.',
  },
  file: {
    title: 'File d’écriture',
    shows: 'Les modifications du .htaccess et du robots.txt en attente, vérifiées puis appliquées avec sauvegarde.',
    missing: WRITE,
  },
  wordpress: {
    title: 'WordPress détaillé',
    shows: 'Le jeu de contrôles propre à WordPress : versions du cœur, des extensions et des thèmes, comptes administrateurs, fichiers modifiés.',
    missing: 'Un jeu de contrôles WordPress dans le veilleur. Il ne reçoit aujourd’hui que les faits envoyés par l’agent, montrés dans les contrôles « Agent ».',
  },
  personnalises: {
    title: 'Contrôles personnalisés',
    shows: 'Des contrôles propres à un site, définis à la main : page attendue, texte à trouver, réponse à exclure.',
    missing: 'Le veilleur n’a que ses contrôles intégrés ; il ne lit aucune définition de contrôle personnalisé.',
  },
}

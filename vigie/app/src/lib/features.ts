// Fonctionnalités dessinées dans les maquettes mais sans source de données
// dans le veilleur, ou sans source pour ce site. Chacune est nommée, dit ce
// qu'elle montrera et ce qui manque pour l'alimenter, sans aucune donnée
// d'exemple (plan, Décisions).

export type FeatureKey =
  | 'visiteurs'
  | 'journal'
  | 'blocages'
  | 'erreurs'
  | 'ressources'
  | 'htaccess'
  | 'compte'
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

// Visiteurs, Blocages et Ressources sont alimentés par l'analyse des logs
// (`GET /api/v1/sites/{id}/logs`) ; ce texte n'apparaît que sur un 404.
const LOGS =
  'Une analyse des logs de ce site. L’agent pousse les logs HTTP au veilleur, qui les analyse ; il ne lit jamais l’hébergeur. Ce site n’a pas de source de logs déclarée (section [sites.logs] de config.toml sur le VPS), ou le veilleur ne sert pas encore cette lecture.'

const WRITE =
  'Une écriture sur le site. Le veilleur n’écrit jamais sur un site : aucun accès n’est conservé chez l’hébergeur.'

export const FEATURES: Record<FeatureKey, Feature> = {
  visiteurs: {
    title: 'Visiteurs automatisés',
    shows: 'Les adresses IP au score moyen ou élevé de la dernière analyse, les plus suspectes en tête, avec leurs raisons.',
    missing: LOGS,
    link: { label: 'Voir la santé du site', name: 'sante' },
  },
  journal: {
    title: 'Journal des requêtes',
    shows: 'Les requêtes regroupées par visiteur et par rafale, toutes sources mêlées dans l’ordre du temps.',
    missing:
      'Les lignes de logs elles-mêmes. Le veilleur n’en sert aucune à la console, par minimisation des données personnelles : seulement leur analyse, dans Visiteurs, Blocages et Ressources.',
    link: { label: 'Voir les visiteurs', name: 'trafic' },
  },
  blocages: {
    title: 'Blocages',
    shows: 'Les robots vus sur la dernière journée et les règles de l’analyse, dépassées ou non.',
    missing: LOGS,
    link: { label: 'Voir les contrôles', name: 'controles' },
  },
  erreurs: {
    title: 'Erreurs',
    shows: 'Les erreurs regroupées par message, avec une sourdine limitée dans le temps.',
    missing: 'Les logs d’erreurs du site. L’agent ne pousse au veilleur que les logs HTTP, analysés dans Trafic.',
    link: { label: 'Voir les points à traiter', name: 'a-traiter' },
  },
  ressources: {
    title: 'Charge du site',
    shows: 'La charge du site heure par heure sur la dernière journée : requêtes, refus et temps de service.',
    missing: LOGS,
    link: { label: 'Voir la disponibilité', name: 'sante' },
  },
  htaccess: {
    title: 'Blocage manuel et liste blanche',
    shows: 'Les règles en place dans le .htaccess et leurs refus, le blocage à la main, la liste blanche et les sauvegardes.',
    missing: WRITE,
  },
  compte: {
    title: 'Ressources du compte',
    shows: 'La mémoire, la charge processeur et le disque du compte d’hébergement, partagés entre ses sites.',
    missing: 'Un relevé des ressources du compte chez l’hébergeur, que le veilleur ne fait pas.',
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

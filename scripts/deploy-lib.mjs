// Fonctions pures du déploiement : aucune n'appelle git, WSL ni le réseau,
// pour rester testables avec `node --test`.

// Liste blanche de ce qui part sur la boutique. Tout le reste (tests, outillage
// PHP et Node, CHANGELOG, vendor/) reste local : le module se charge sans
// vendor/ grâce au repli spl_autoload_register de sc_alwaysdata.php.
export const DEPLOY_PATHS = [
  'config',
  'controllers',
  'src',
  'upgrade',
  'views',
  'config.xml',
  'config_fr.xml',
  'index.php',
  'sc_alwaysdata.php',
]

// Présents sur la cible mais jamais gérés par le déploiement : ni écrasés, ni
// comptés comme fichiers en trop.
export const REMOTE_PROTECTED = ['/vendor/', '/.git/']

const SAFE_PATH = /^[A-Za-z0-9._/-]+$/
const SAFE_HOST = /^[a-z0-9.-]+$/i
const SAFE_USER = /^[a-z0-9._-]+$/i

const FLAGS = {
  '--apply': 'apply',
  '--check': 'check',
  '--any-branch': 'anyBranch',
  '--allow-downgrade': 'allowDowngrade',
  '--clear-cache': 'clearCache',
}

export function parseArgs(argv) {
  const options = { target: null, apply: false, check: false, anyBranch: false, allowDowngrade: false, clearCache: false }
  for (const arg of argv) {
    if (arg === '--') continue
    if (arg.startsWith('--')) {
      const key = FLAGS[arg]
      if (!key) throw new Error(`Option inconnue : ${arg}`)
      options[key] = true
      continue
    }
    if (options.target) throw new Error(`Une seule cible attendue, reçu « ${options.target} » et « ${arg} »`)
    options.target = arg
  }
  if (!options.target) throw new Error('Cible manquante : node scripts/deploy.mjs <cible> [--apply]')
  if (options.apply && options.check) throw new Error('--apply et --check sont incompatibles')
  return options
}

export function shQuote(value) {
  return `'${String(value).replace(/'/g, `'\\''`)}'`
}

export function validateTarget(name, raw) {
  if (!/^[a-z0-9-]+$/.test(name)) throw new Error(`Nom de cible invalide : ${name}`)
  if (!raw || typeof raw !== 'object') throw new Error(`Cible « ${name} » absente de deploy/targets.json`)
  const { host, user, sshKey, shopRoot, siteUrl, lifecycleRevision } = raw
  if (!SAFE_HOST.test(host ?? '')) throw new Error(`host invalide pour « ${name} » : ${host}`)
  if (!SAFE_USER.test(user ?? '')) throw new Error(`user invalide pour « ${name} » : ${user}`)
  if (!/^~\/\.ssh\/[A-Za-z0-9._-]+$/.test(sshKey ?? '')) {
    throw new Error(`sshKey doit être une clé de ~/.ssh côté WSL (reçu : ${sshKey})`)
  }
  // Relatif au home SSH : on ne devine pas /home/<compte>.
  if (!SAFE_PATH.test(shopRoot ?? '') || shopRoot.startsWith('/') || shopRoot.includes('..')) {
    throw new Error(`shopRoot doit être un chemin relatif au home SSH (reçu : ${shopRoot})`)
  }
  let url
  try {
    url = new URL(siteUrl)
  }
  catch {
    throw new Error(`siteUrl invalide pour « ${name} » : ${siteUrl}`)
  }
  if (url.protocol !== 'https:') throw new Error(`siteUrl doit être en https (reçu : ${siteUrl})`)
  if (!Number.isInteger(lifecycleRevision) || lifecycleRevision < 1) {
    throw new Error(`lifecycleRevision doit être un entier ≥ 1 pour « ${name} »`)
  }

  const stateDir = `deploy/sc_alwaysdata-${name}`
  return {
    name,
    host,
    user,
    sshKey,
    siteUrl: url.href,
    remote: `${user}@${host}`,
    moduleDir: `${shopRoot}/modules/sc_alwaysdata`,
    shopRoot,
    stateDir,
    guardPath: `${stateDir}/guard.json`,
    lockPath: `${stateDir}/lock`,
    backupDir: `${stateDir}/backups`,
    guard: { targetId: name, phase: 'production', lifecycleRevision },
  }
}

export function parseVersion(raw) {
  const match = /^(\d+)\.(\d+)\.(\d+)$/.exec(String(raw).trim())
  if (!match) throw new Error(`Version non numérique MAJOR.MINOR.PATCH : ${raw}`)
  return match.slice(1).map(Number)
}

export function compareVersions(a, b) {
  const [left, right] = [parseVersion(a), parseVersion(b)]
  for (let i = 0; i < 3; i++) {
    if (left[i] !== right[i]) return left[i] < right[i] ? -1 : 1
  }
  return 0
}

export function extractXmlVersion(xml) {
  const match = /<version>\s*(?:<!\[CDATA\[)?\s*([^\]<\s]+)\s*(?:\]\]>)?\s*<\/version>/.exec(xml)
  if (!match) throw new Error('Balise <version> introuvable')
  return match[1]
}

export function extractPhpVersion(php) {
  const match = /const\s+VERSION\s*=\s*'([^']+)'/.exec(php)
  if (!match) throw new Error('Constante VERSION introuvable dans sc_alwaysdata.php')
  return match[1]
}

// PrestaShop compare la version en base à celle des fichiers : les trois
// déclarations doivent être identiques, sinon les scripts upgrade/ dérapent.
export function assertVersionsAligned({ configXml, configFrXml, modulePhp }) {
  const versions = {
    'config.xml': extractXmlVersion(configXml),
    'config_fr.xml': extractXmlVersion(configFrXml),
    'sc_alwaysdata.php': extractPhpVersion(modulePhp),
  }
  const distinct = new Set(Object.values(versions))
  if (distinct.size !== 1) {
    const detail = Object.entries(versions).map(([file, v]) => `${file}=${v}`).join(', ')
    throw new Error(`Versions désalignées : ${detail}`)
  }
  const [version] = distinct
  parseVersion(version)
  return version
}

// Sortie de `rsync --itemize-changes` : « YXcstpoguax chemin ».
export function parseItemized(output) {
  const changes = []
  const deletions = []
  for (const line of output.split(/\r?\n/)) {
    const deleting = /^\*deleting\s+(.+)$/.exec(line)
    if (deleting) {
      deletions.push(deleting[1])
      continue
    }
    const item = /^([<>ch.][fdLDS][^ ]{9})\s+(.+)$/.exec(line)
    if (!item || item[2] === './') continue
    changes.push({ flags: item[1], path: item[2] })
  }
  return { changes, deletions }
}

// config/ porte services et routes compilés dans le conteneur Symfony : sans
// vidage du cache prod, la boutique sert l'ancienne définition.
export function touchesContainer(changes) {
  return changes.some(({ path }) => path.startsWith('config/'))
}

export function backupFileName(date, version) {
  const stamp = date.toISOString().replace(/[-:]/g, '').replace(/\.\d+Z$/, 'Z')
  return `sc_alwaysdata-${stamp}-v${version}.tar.gz`
}

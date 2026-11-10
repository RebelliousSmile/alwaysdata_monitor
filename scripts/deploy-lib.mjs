// Fonctions pures du déploiement, partagées par scripts/deploy.mjs
// (veilleur) et scripts/deploy-agent.mjs (agent) : aucune n'appelle git,
// WSL ni le réseau, pour rester testables avec `node --test`. withRemoteLock
// reçoit la fonction ssh en paramètre pour la même raison.

const SAFE_PATH = /^[A-Za-z0-9._/-]+$/
const SAFE_HOST = /^[a-z0-9.-]+$/i
const SAFE_USER = /^[a-z0-9._-]+$/i

const FLAGS = {
  '--apply': 'apply',
  '--check': 'check',
  '--any-branch': 'anyBranch',
}

export function parseArgs(argv) {
  const options = { target: null, apply: false, check: false, anyBranch: false }
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

// Nom, hôte, compte et clé d'une cible : commun au veilleur et à l'agent.
// `file` ne sert qu'au message d'erreur.
export function validateSshAccess(name, raw, file) {
  if (!/^[a-z0-9-]+$/.test(name ?? '')) throw new Error(`Nom de cible invalide : ${name}`)
  if (!raw || typeof raw !== 'object') throw new Error(`Cible « ${name} » absente de ${file}`)
  const { host, user, sshKey } = raw
  if (!SAFE_HOST.test(host ?? '')) throw new Error(`host invalide pour « ${name} » : ${host}`)
  if (!SAFE_USER.test(user ?? '')) throw new Error(`user invalide pour « ${name} » : ${user}`)
  if (!/^~\/\.ssh\/[A-Za-z0-9._-]+$/.test(sshKey ?? '')) {
    throw new Error(`sshKey doit être une clé de ~/.ssh côté WSL (reçu : ${sshKey})`)
  }
  return { name, host, user, sshKey, remote: `${user}@${host}` }
}

// Relatif au home SSH : on ne devine pas /home/<compte>. Le chemin est ensuite
// interpolé sans guillemets dans des commandes distantes, d'où la liste blanche.
export function validateRemoteRelativePath(field, value) {
  if (!SAFE_PATH.test(value ?? '') || value.startsWith('/') || value.includes('..')) {
    throw new Error(`${field} doit être un chemin relatif au home SSH (reçu : ${value})`)
  }
  return value
}

// HOME de WSL, interpolé dans un `rm -rf` de staging : refuser tout ce qui
// n'est pas /home/<utilisateur> ou /root.
export function assertWslHome(home) {
  if (!/^\/(?:root|home\/[A-Za-z0-9._-]+)$/.test(home ?? '')) {
    throw new Error(`HOME de WSL inattendu : « ${home} » (attendu /home/<utilisateur> ou /root)`)
  }
  return home
}

export function sshOptions(keyPath, wslHome) {
  return [
    '-i', keyPath,
    '-o', 'IdentitiesOnly=yes',
    '-o', 'BatchMode=yes',
    '-o', 'StrictHostKeyChecking=accept-new',
    '-o', 'ServerAliveInterval=15',
    '-o', 'ServerAliveCountMax=4',
    '-o', 'ControlMaster=auto',
    '-o', `ControlPath=${wslHome}/.ssh/cm-%r@%h:%p`,
    '-o', 'ControlPersist=60s',
  ]
}

export function missingKeyHelp({ keyPath, sshKey, remote, comment }) {
  return [
    `Clé SSH absente côté WSL : ${keyPath}`,
    `  wsl ssh-keygen -t ed25519 -N "" -C ${comment} -f ${sshKey}`,
    `  wsl ssh-copy-id -i ${sshKey}.pub ${remote}`,
  ].join('\n')
}

// Verrou distant par `mkdir` (atomique) : pris avant `body`, toujours rendu
// après, même si `body` échoue. Un verrou non rendu est signalé, pas masqué.
export async function withRemoteLock(ssh, { lockPath, sshKey, remote }, body) {
  try {
    await ssh(`mkdir ${lockPath}`)
  }
  catch {
    throw new Error(`Verrou déjà pris (~/${lockPath}) : un autre déploiement est en cours, ou un précédent a été interrompu`)
  }
  try {
    return await body()
  }
  finally {
    try {
      await ssh(`rmdir ${lockPath}`)
    }
    catch {
      console.error(`✖ Verrou non libéré : wsl ssh -i ${sshKey} ${remote} "rmdir ${lockPath}"`)
    }
  }
}

// L'agent n'a rien à faire sous le webroot d'Alwaysdata (~/www) : appelé par
// le web, il sort sans rien faire, mais rien ne doit pouvoir l'exposer.
export function validateAgentTarget(name, raw, file) {
  const access = validateSshAccess(name, raw, file)
  const remoteDir = validateRemoteRelativePath('remoteDir', raw.remoteDir ?? 'vigie-agent')
  if (/^www/i.test(remoteDir)) {
    throw new Error(`remoteDir ne doit pas être sous le webroot ~/www (reçu : ${remoteDir})`)
  }
  return {
    ...access,
    remoteDir,
    script: `${remoteDir}/vigie-agent.php`,
    lockPath: `${remoteDir}/deploy.lock`,
    recordPath: `${remoteDir}/last-deploy.json`,
  }
}

// Chemin absolu résolu sur la cible (liens compris) : sous ~/www, refus.
export function assertOutsideWebroot(resolved, home) {
  if (!resolved.startsWith('/') || !home.startsWith('/')) {
    throw new Error(`Chemins distants illisibles : ${resolved} (home ${home})`)
  }
  const webroot = `${home.replace(/\/+$/, '')}/www`
  if (resolved === webroot || resolved.startsWith(`${webroot}/`)) {
    throw new Error(`Destination ${resolved} sous le webroot ${webroot} : refusé`)
  }
  return resolved
}

export function extractAgentVersion(php) {
  const match = /^const VERSION = '([^']+)';$/m.exec(php)
  if (!match) throw new Error('Constante VERSION introuvable dans vigie-agent.php')
  parseVersion(match[1])
  return match[1]
}

export function parseVersion(raw) {
  const match = /^(\d+)\.(\d+)\.(\d+)$/.exec(String(raw).trim())
  if (!match) throw new Error(`Version non numérique MAJOR.MINOR.PATCH : ${raw}`)
  return match.slice(1).map(Number)
}

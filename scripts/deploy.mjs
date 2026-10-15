// Déploie le module sc_alwaysdata sur une boutique PrestaShop hébergée chez Alwaysdata.
//
//   pnpm deploy:check <cible>              validations locales, sans contacter la cible
//   pnpm deploy:module <cible>             prévisualisation (aucune écriture distante)
//   pnpm deploy:module <cible> -- --apply  sauvegarde, synchronisation, preuve HTTP
//
// Seul le contenu d'un commit part (git archive, en LF), jamais la copie de
// travail : Windows la stocke en CRLF et elle peut contenir des fichiers non commités.
// Transport : rsync et ssh de WSL, clé dédiée par cible.

import { execFileSync } from 'node:child_process'
import { existsSync, readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import {
  DEPLOY_PATHS,
  REMOTE_PROTECTED,
  assertVersionsAligned,
  backupFileName,
  compareVersions,
  extractXmlVersion,
  parseArgs,
  parseItemized,
  shQuote,
  touchesContainer,
  validateTarget,
} from './deploy-lib.mjs'

const repoRoot = join(dirname(fileURLToPath(import.meta.url)), '..')
const options = parseArgs(process.argv.slice(2))

function git(args, extra = {}) {
  return execFileSync('git', args, { cwd: repoRoot, encoding: 'utf-8', ...extra })
}

// --exec : aucun shell WSL ne réinterprète les arguments.
function wsl(args, extra = {}) {
  return execFileSync('wsl', ['--exec', ...args], { encoding: 'utf-8', ...extra })
}

// --- Cible ------------------------------------------------------------------

const targetsPath = join(repoRoot, 'deploy', 'targets.json')
if (!existsSync(targetsPath)) {
  throw new Error('deploy/targets.json absent : copier deploy/targets.example.json et le renseigner (fichier ignoré par git, le dépôt est public)')
}
const target = validateTarget(options.target, JSON.parse(readFileSync(targetsPath, 'utf-8'))[options.target])

// --- Validations locales ----------------------------------------------------

const branch = git(['rev-parse', '--abbrev-ref', 'HEAD']).trim()
if (branch !== 'main' && !options.anyBranch) {
  throw new Error(`Déploiement refusé : branche « ${branch} », attendu « main » (forcer avec --any-branch)`)
}
const commit = git(['rev-parse', 'HEAD']).trim()
const shortCommit = commit.slice(0, 7)
if (git(['status', '--porcelain']).trim()) {
  console.warn(`⚠ Copie de travail modifiée : ces changements ne partiront pas, seul le commit ${shortCommit} est envoyé.`)
}
const version = assertVersionsAligned({
  configXml: git(['show', `${commit}:config.xml`]),
  configFrXml: git(['show', `${commit}:config_fr.xml`]),
  modulePhp: git(['show', `${commit}:sc_alwaysdata.php`]),
})
console.log(`Module sc_alwaysdata v${version} — commit ${shortCommit} (${branch}) → cible ${target.name}`)

// --- Staging Linux natif (WSL) ----------------------------------------------

const wslHome = wsl(['printenv', 'HOME']).trim()
const stageDir = `${wslHome}/deploy-stage/sc_alwaysdata-${target.name}`
// git archive applique la conversion de fin de ligne de la copie de travail :
// avec core.autocrlf=true (Windows), il produirait du CRLF.
const archive = execFileSync('git', ['-c', 'core.autocrlf=false', '-c', 'core.eol=lf', 'archive', '--format=tar', commit, '--', ...DEPLOY_PATHS], {
  cwd: repoRoot,
  maxBuffer: 64 * 1024 * 1024,
})
wsl(['bash', '-c', 'rm -rf "$1" && mkdir -p "$1" && tar -xf - -C "$1"', 'stage', stageDir], { input: archive })
const stagedCount = wsl(['find', stageDir, '-type', 'f']).trim().split('\n').length
console.log(`Staging : ${stagedCount} fichiers dans ${stageDir}`)

if (options.check) {
  console.log('Validations locales OK — aucune connexion à la cible.')
  process.exit(0)
}

// --- Accès distant ----------------------------------------------------------

const keyPath = target.sshKey.replace(/^~/, wslHome)
try {
  wsl(['test', '-f', keyPath])
}
catch {
  throw new Error([
    `Clé SSH absente côté WSL : ${keyPath}`,
    `  wsl ssh-keygen -t ed25519 -N "" -C sc_alwaysdata-${target.name} -f ${target.sshKey}`,
    `  wsl ssh-copy-id -i ${target.sshKey}.pub ${target.remote}`,
  ].join('\n'))
}

const sshOpts = [
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

function ssh(remoteCommand, { inherit = false } = {}) {
  return wsl(['ssh', ...sshOpts, target.remote, remoteCommand], inherit ? { stdio: 'inherit' } : {})
}

function rsync({ dryRun, deleteRemote }) {
  const args = ['rsync', '-rlz', '--checksum', '--chmod=D755,F644', '--itemize-changes']
  if (dryRun) args.push('--dry-run')
  if (deleteRemote) args.push('--delete')
  for (const pattern of REMOTE_PROTECTED) args.push(`--exclude=${pattern}`)
  args.push('-e', `ssh ${sshOpts.join(' ')}`, `${stageDir}/`, `${target.remote}:${target.moduleDir}/`)
  return wsl(args)
}

// --- État de la cible -------------------------------------------------------

if (ssh(`test -f ${target.moduleDir}/sc_alwaysdata.php && echo present || echo absent`).trim() !== 'present') {
  throw new Error(`Module introuvable sur la cible (${target.moduleDir}) : la première installation passe par le back-office, pas par ce script`)
}
const remoteVersion = extractXmlVersion(ssh(`cat ${target.moduleDir}/config.xml`))
const direction = compareVersions(version, remoteVersion)
if (direction < 0 && !options.allowDowngrade) {
  throw new Error(`Retour arrière refusé : cible en v${remoteVersion}, commit en v${version} (forcer avec --allow-downgrade)`)
}
console.log(`Version en ligne : v${remoteVersion}${direction === 0 ? ' (identique : aucun script upgrade/ ne sera joué)' : ''}`)

const guardRaw = ssh(`cat ${target.guardPath} 2>/dev/null || true`).trim()
if (guardRaw) {
  const guard = JSON.parse(guardRaw)
  const expected = target.guard
  if (guard.targetId !== expected.targetId || guard.phase !== expected.phase || guard.lifecycleRevision !== expected.lifecycleRevision) {
    throw new Error(`Garde distante incompatible : attendu ${JSON.stringify(expected)}, trouvé ${guardRaw}`)
  }
}

// --- Prévisualisation -------------------------------------------------------

const { changes, deletions } = parseItemized(rsync({ dryRun: true, deleteRemote: true }))
if (deletions.length) {
  console.log(`\n${deletions.length} fichier(s) présents sur la cible et absents du commit — laissés en place :`)
  for (const path of deletions.slice(0, 20)) console.log(`  ${path}`)
  if (deletions.length > 20) console.log(`  … et ${deletions.length - 20} autres`)
}
if (!changes.length) {
  console.log('\nRien à envoyer : la cible correspond déjà au commit.')
  process.exit(0)
}
console.log(`\n${changes.length} changement(s) à envoyer :`)
for (const { flags, path } of changes) console.log(`  ${flags} ${path}`)
const clearCache = options.clearCache || touchesContainer(changes)
if (clearCache) console.log('\nLe cache prod de PrestaShop sera vidé (config/ modifié ou --clear-cache).')
if (!guardRaw) console.log(`\nGarde absente : elle sera posée dans ~/${target.guardPath}.`)

if (!options.apply) {
  console.log('\nPrévisualisation seulement. Relancer avec --apply pour envoyer.')
  process.exit(0)
}

// --- Application ------------------------------------------------------------

ssh(`mkdir -p ${target.backupDir}`)
if (!guardRaw) ssh(`printf '%s\\n' ${shQuote(JSON.stringify(target.guard))} > ${target.guardPath}`)

try {
  ssh(`mkdir ${target.lockPath}`)
}
catch {
  throw new Error(`Verrou déjà pris (~/${target.lockPath}) : un autre déploiement est en cours, ou un précédent a été interrompu`)
}

let failed = false
try {
  const backup = `${target.backupDir}/${backupFileName(new Date(), remoteVersion)}`
  console.log(`\nSauvegarde du module en ligne → ~/${backup}`)
  ssh(`tar -czf ${backup} -C ${target.shopRoot}/modules sc_alwaysdata`)

  console.log('Synchronisation (sans suppression)...')
  rsync({ dryRun: false, deleteRemote: false })

  const record = { commit, version, previousVersion: remoteVersion, at: new Date().toISOString() }
  ssh(`printf '%s\\n' ${shQuote(JSON.stringify(record))} > ${target.stateDir}/last-deploy.json`)

  if (clearCache) {
    console.log('Vidage du cache prod...')
    try {
      ssh(`cd ${target.shopRoot} && php bin/console cache:clear --no-warmup --env=prod`, { inherit: true })
    }
    catch {
      failed = true
      console.error(`✖ Vidage du cache échoué : relancer à la main dans ~/${target.shopRoot}`)
    }
  }

  console.log(`Preuve HTTP : ${target.siteUrl}`)
  const response = await fetch(target.siteUrl, { redirect: 'follow', signal: AbortSignal.timeout(30_000) })
  if (response.status !== 200) {
    failed = true
    console.error(`✖ ${target.siteUrl} répond ${response.status}`)
  }

  console.log(`\nRestauration si besoin :\n  wsl ssh -i ${target.sshKey} ${target.remote} "cd ${target.shopRoot}/modules && mv sc_alwaysdata sc_alwaysdata.broken && tar -xzf ~/${backup}"`)
  if (direction > 0) {
    console.log(`\nv${remoteVersion} → v${version} : lancer la mise à jour du module dans le back-office (Modules > Gestionnaire de modules) pour jouer les scripts upgrade/.`)
  }
}
finally {
  try {
    ssh(`rmdir ${target.lockPath}`)
  }
  catch {
    console.error(`✖ Verrou non libéré : wsl ssh -i ${target.sshKey} ${target.remote} "rmdir ${target.lockPath}"`)
  }
}

if (failed) process.exit(1)
console.log(`\nDéployé : sc_alwaysdata v${version} (${shortCommit}) sur ${target.name}.`)

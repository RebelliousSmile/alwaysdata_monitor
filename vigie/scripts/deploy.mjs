// Déploie le binaire Linux du veilleur sur son VPS (utilisateur vigie).
//
//   node vigie/scripts/deploy.mjs veilleur --check    build et validations locales, sans contacter la cible
//   node vigie/scripts/deploy.mjs veilleur            prévisualisation (aucune écriture distante)
//   node vigie/scripts/deploy.mjs veilleur --apply    envoi, bascule atomique, redémarrage de serve, preuve /health
//
// Comme pour le module : seul le contenu d'un commit est compilé (git archive),
// jamais la copie de travail. Build statique musl dans WSL avec cargo-zigbuild,
// transport ssh et scp de WSL avec une clé dédiée. Le redémarrage passe par la
// seule règle sudo posée par deploy/provision.sh.

import { execFileSync } from 'node:child_process'
import { createHash } from 'node:crypto'
import { existsSync, readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import {
  assertWslHome,
  missingKeyHelp,
  parseArgs,
  shQuote,
  sshOptions,
  validateRemoteRelativePath,
  validateSshAccess,
  withRemoteLock,
} from '../../scripts/deploy-lib.mjs'

const vigieRoot = join(dirname(fileURLToPath(import.meta.url)), '..')
const repoRoot = join(vigieRoot, '..')
const options = parseArgs(process.argv.slice(2))
if (options.allowDowngrade || options.clearCache) {
  throw new Error('--allow-downgrade et --clear-cache ne concernent que le module PrestaShop')
}

const TARGET_TRIPLE = 'x86_64-unknown-linux-musl'
// Mot pour mot la règle de /etc/sudoers.d/vigie : sudo refuse toute variante.
const RESTART_SERVE = 'sudo -n /usr/bin/systemctl restart vigie-serve.service'

function git(args, extra = {}) {
  return execFileSync('git', args, { cwd: repoRoot, encoding: 'utf-8', ...extra })
}

// --exec : aucun shell WSL ne réinterprète les arguments.
function wsl(args, extra = {}) {
  return execFileSync('wsl', ['--exec', ...args], { encoding: 'utf-8', ...extra })
}

// --- Cible ------------------------------------------------------------------

function validateTarget(name, raw) {
  const access = validateSshAccess(name, raw, 'vigie/deploy/targets.json')
  const { remoteDir, healthUrl } = raw
  validateRemoteRelativePath('remoteDir', remoteDir)
  let health = null
  if (healthUrl != null) {
    try {
      health = new URL(healthUrl)
    }
    catch {
      throw new Error(`healthUrl invalide pour « ${name} » : ${healthUrl}`)
    }
    if (health.protocol !== 'https:') throw new Error(`healthUrl doit être en https (reçu : ${healthUrl})`)
  }
  return {
    ...access,
    binDir: `${remoteDir}/bin`,
    binary: `${remoteDir}/bin/vigie`,
    lockPath: `${remoteDir}/deploy.lock`,
    recordPath: `${remoteDir}/last-deploy.json`,
    healthUrl: health?.href ?? null,
  }
}

const targetsPath = join(vigieRoot, 'deploy', 'targets.json')
if (!existsSync(targetsPath)) {
  throw new Error('vigie/deploy/targets.json absent : copier targets.example.json et le renseigner (fichier ignoré par git, le dépôt est public)')
}
const target = validateTarget(options.target, JSON.parse(readFileSync(targetsPath, 'utf-8'))[options.target])

// --- Validations locales ----------------------------------------------------

const branch = git(['rev-parse', '--abbrev-ref', 'HEAD']).trim()
if (branch !== 'main' && !options.anyBranch) {
  throw new Error(`Déploiement refusé : branche « ${branch} », attendu « main » (forcer avec --any-branch)`)
}
const commit = git(['rev-parse', 'HEAD']).trim()
const shortCommit = commit.slice(0, 7)
if (git(['status', '--porcelain', '--', 'vigie']).trim()) {
  console.warn(`⚠ vigie/ modifié dans la copie de travail : seul le commit ${shortCommit} est compilé.`)
}

// --- Build statique dans WSL ------------------------------------------------

const wslHome = assertWslHome(wsl(['printenv', 'HOME']).trim())
const srcDir = `${wslHome}/deploy-stage/vigie-src`
const targetDir = `${wslHome}/deploy-stage/vigie-target`
const localBinary = `${targetDir}/${TARGET_TRIPLE}/release/vigie`

// Archive du sous-arbre : l'attribut « /vigie export-ignore » de la racine
// ne s'y applique pas, et aucune conversion CRLF n'a lieu.
const archive = execFileSync('git', ['-c', 'core.autocrlf=false', 'archive', '--format=tar', `${commit}:vigie`], {
  cwd: repoRoot,
  maxBuffer: 64 * 1024 * 1024,
})
wsl(['bash', '-c', 'rm -rf "$1" && mkdir -p "$1" && tar -xf - -C "$1"', 'stage', srcDir], { input: archive })
if (!wsl(['bash', '-c', 'test -f "$1/Cargo.toml" && echo ok || echo absent', 'stage', srcDir]).includes('ok')) {
  throw new Error(`vigie/Cargo.toml absent du commit ${shortCommit}`)
}

console.log(`Build ${TARGET_TRIPLE} du commit ${shortCommit} (${branch})...`)
wsl(['bash', '-lc', 'cd "$1" && PATH="$HOME/.local/bin:$HOME/.cargo/bin:$PATH" CARGO_TARGET_DIR="$2" cargo zigbuild --release --locked --target "$3"', 'build', srcDir, targetDir, TARGET_TRIPLE], { stdio: ['ignore', 'inherit', 'inherit'] })

const kind = wsl(['file', '-b', localBinary])
if (!/statically linked|static-pie linked/.test(kind)) throw new Error(`Binaire non statique : ${kind.trim()}`)
const localVersion = wsl([localBinary, '--version']).trim()
const localBytes = execFileSync('wsl', ['--exec', 'cat', localBinary], { maxBuffer: 64 * 1024 * 1024 })
const localSha = createHash('sha256').update(localBytes).digest('hex')
console.log(`${localVersion} — ${localBytes.length} octets — sha256 ${localSha.slice(0, 16)}…`)

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
  throw new Error(missingKeyHelp({ keyPath, sshKey: target.sshKey, remote: target.remote, comment: `vigie-${target.name}` }))
}

const sshOpts = sshOptions(keyPath, wslHome)

function ssh(remoteCommand) {
  return wsl(['ssh', ...sshOpts, target.remote, remoteCommand])
}

const remoteState = ssh(`if test -x ${target.binary}; then sha256sum ${target.binary} | cut -d' ' -f1; ${target.binary} --version; else echo absent; fi`).trim().split('\n')
const remoteSha = remoteState[0] === 'absent' ? null : remoteState[0]
const remoteVersion = remoteSha ? (remoteState[1] ?? 'version illisible') : null
console.log(`En ligne : ${remoteSha ? `${remoteVersion} — sha256 ${remoteSha.slice(0, 16)}…` : `aucun binaire dans ~/${target.binary}`}`)

if (remoteSha === localSha) {
  console.log('\nRien à envoyer : le binaire en ligne est identique.')
  process.exit(0)
}
console.log(`\nÀ envoyer : ~/${target.binary}${remoteSha ? ` (l'actuel sera conservé en ~/${target.binary}.prev)` : ''}`)

if (!options.apply) {
  console.log('\nPrévisualisation seulement. Relancer avec --apply pour envoyer.')
  process.exit(0)
}

// --- Application ------------------------------------------------------------

ssh(`mkdir -p ${target.binDir}`)

// /health ne prouve la bascule que si le tick qu'il rapporte est postérieur :
// un 200 seul peut venir d'un tick de l'ancien binaire.
async function healthAfter(url, since) {
  let last = 'sans réponse'
  for (let attempt = 0; attempt < 18; attempt++) {
    if (attempt) await new Promise(resolve => setTimeout(resolve, 10_000))
    try {
      const response = await fetch(url, { signal: AbortSignal.timeout(15_000) })
      const body = await response.json().catch(() => null)
      const tick = Number.isInteger(body?.last_tick) ? body.last_tick : null
      if (response.status === 200 && tick !== null && tick > since) return { ok: true, last: `200, tick ${tick}` }
      last = `${response.status}${tick !== null ? `, dernier tick ${tick} (bascule ${since})` : ''}`
    }
    catch {
      last = 'sans réponse'
    }
  }
  return { ok: false, last }
}

// Un arrêt silencieux a déjà laissé le verrou en place (2026-10-15, cause non
// établie) : au moins nommer l'étape et le code de sortie.
let step = 'envoi'
let finished = false
process.on('exit', (code) => {
  if (!finished && code !== 1) console.error(`✖ Arrêt inattendu pendant « ${step} » (code ${code})`)
})

let failed = false
const swapAt = await withRemoteLock(ssh, target, async () => {
  const staged = `${target.binary}.new`
  wsl(['scp', '-q', ...sshOpts, localBinary, `${target.remote}:${staged}`])
  const stagedVersion = ssh(`chmod 755 ${staged} && sha256sum ${staged} | cut -d' ' -f1 && ${staged} --version`).trim().split('\n')
  if (stagedVersion[0] !== localSha || stagedVersion[1] !== localVersion) {
    throw new Error(`Binaire reçu différent (sha256 ${stagedVersion[0]}, ${stagedVersion[1]}) : rien n'a été basculé, ~/${staged} reste à examiner`)
  }

  // ln -f garde l'ancien inode en .prev ; mv -f dans le même dossier est atomique.
  // Heure de la bascule prise sur le veilleur : `tick` horodate avec la même horloge.
  const swapAt = Number(ssh(`${remoteSha ? `ln -f ${target.binary} ${target.binary}.prev && ` : ''}mv -f ${staged} ${target.binary} && date +%s`).trim())
  if (!Number.isInteger(swapAt)) throw new Error(`Basculé, mais heure du veilleur illisible : /health non vérifiable`)
  const record = { commit, version: localVersion, sha256: localSha, previousSha256: remoteSha, at: new Date().toISOString() }
  ssh(`printf '%s\\n' ${shQuote(JSON.stringify(record))} > ${target.recordPath}`)
  console.log(`Basculé : ~/${target.binary} (${localVersion})`)

  // Le timer lance déjà le nouveau binaire pour tick ; serve garde l'ancien en
  // mémoire tant qu'il n'est pas redémarré.
  step = 'redémarrage de serve'
  try {
    ssh(RESTART_SERVE)
    console.log('serve redémarré.')
  }
  catch (error) {
    // Sans redémarrage, /health rapporterait l'ancien serve : pas de preuve à chercher.
    failed = true
    console.error(`✖ Redémarrage de serve refusé ou en échec : ${String(error.stderr ?? error.message).trim()}`)
    console.error(`Relancer à la main : wsl ssh -i ${target.sshKey} ${target.remote} "${RESTART_SERVE}"`)
  }
  return swapAt
})

// Hors du verrou : la preuve n'écrit rien sur le veilleur, et un arrêt pendant
// ces 3 minutes ne doit pas bloquer le déploiement suivant.
if (!failed && target.healthUrl) {
  step = 'preuve HTTP'
  console.log(`Preuve HTTP : ${target.healthUrl} (jusqu'à 3 min, le temps d'un tick du nouveau binaire)`)
  const proof = await healthAfter(target.healthUrl, swapAt)
  if (proof.ok) {
    console.log(`/health : ${proof.last}`)
  }
  else {
    failed = true
    console.error(`✖ ${target.healthUrl} : aucun tick postérieur à la bascule en 3 min (dernière réponse : ${proof.last})`)
  }
}
else if (!failed) {
  console.warn('⚠ healthUrl absent de la cible : /health non vérifié.')
}
if (remoteSha) {
  console.log(`\nRetour arrière :\n  wsl ssh -i ${target.sshKey} ${target.remote} "mv -f ${target.binary}.prev ${target.binary} && ${RESTART_SERVE}"`)
}

finished = true
if (failed) process.exit(1)
console.log(`\nDéployé : ${localVersion} (${shortCommit}) sur ${target.name}.`)

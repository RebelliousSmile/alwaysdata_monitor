// Envoie l'agent PHP sur le compte SSH d'un site, hors du webroot.
//
//   node vigie/scripts/deploy-agent.mjs site-a-agent --check    validations locales, sans contacter la cible
//   node vigie/scripts/deploy-agent.mjs site-a-agent            prévisualisation (aucune écriture distante)
//   node vigie/scripts/deploy-agent.mjs site-a-agent --apply    envoi, contrôle php -l distant, bascule atomique
//
// Comme pour le veilleur : seul le contenu d'un commit part (git show), jamais
// la copie de travail. Transport ssh de WSL avec une clé dédiée. Le script ne
// touche ni à la configuration ni à la clé de l'agent (~/.vigie-agent) : la
// pose est décrite dans vigie/docs/agent-php.md.

import { execFileSync } from 'node:child_process'
import { createHash } from 'node:crypto'
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import {
  assertOutsideWebroot,
  assertWslHome,
  extractAgentVersion,
  missingKeyHelp,
  parseArgs,
  shQuote,
  sshOptions,
  validateAgentTarget,
  withRemoteLock,
} from '../../scripts/deploy-lib.mjs'

const vigieRoot = join(dirname(fileURLToPath(import.meta.url)), '..')
const repoRoot = join(vigieRoot, '..')
const options = parseArgs(process.argv.slice(2))
if (options.allowDowngrade || options.clearCache) {
  throw new Error('--allow-downgrade et --clear-cache ne concernent que le module PrestaShop')
}

const AGENT_PATH = 'vigie/agent/php/vigie-agent.php'

function git(args, extra = {}) {
  return execFileSync('git', args, { cwd: repoRoot, encoding: 'utf-8', ...extra })
}

// --exec : aucun shell WSL ne réinterprète les arguments.
function wsl(args, extra = {}) {
  return execFileSync('wsl', ['--exec', ...args], { encoding: 'utf-8', ...extra })
}

// --- Cible ------------------------------------------------------------------

const targetsPath = join(vigieRoot, 'deploy', 'targets.json')
if (!existsSync(targetsPath)) {
  throw new Error('vigie/deploy/targets.json absent : copier targets.example.json et le renseigner (fichier ignoré par git, le dépôt est public)')
}
const target = validateAgentTarget(
  options.target,
  JSON.parse(readFileSync(targetsPath, 'utf-8'))[options.target],
  'vigie/deploy/targets.json',
)

// --- Validations locales ----------------------------------------------------

const branch = git(['rev-parse', '--abbrev-ref', 'HEAD']).trim()
if (branch !== 'main' && !options.anyBranch) {
  throw new Error(`Déploiement refusé : branche « ${branch} », attendu « main » (forcer avec --any-branch)`)
}
const commit = git(['rev-parse', 'HEAD']).trim()
const shortCommit = commit.slice(0, 7)
if (git(['status', '--porcelain', '--', AGENT_PATH]).trim()) {
  console.warn(`⚠ ${AGENT_PATH} modifié dans la copie de travail : seul le commit ${shortCommit} est envoyé.`)
}

// Le blob tel qu'il est dans le commit : git show n'applique aucune
// conversion de fins de ligne.
let agent
try {
  agent = execFileSync('git', ['show', `${commit}:${AGENT_PATH}`], { cwd: repoRoot, maxBuffer: 4 * 1024 * 1024, stdio: ['ignore', 'pipe', 'pipe'] })
}
catch {
  throw new Error(`${AGENT_PATH} absent du commit ${shortCommit} : rien à envoyer`)
}
const version = extractAgentVersion(agent.toString('utf-8'))
const localSha = createHash('sha256').update(agent).digest('hex')
console.log(`vigie-agent-php ${version} du commit ${shortCommit} (${branch}) — ${agent.length} octets — sha256 ${localSha.slice(0, 16)}…`)

// php -l local si un PHP est disponible (PHP=<chemin> pour en désigner un) ;
// le contrôle qui compte est celui du PHP de la cible, avant la bascule.
const php = process.env.PHP ?? 'php'
const stage = mkdtempSync(join(tmpdir(), 'vigie-agent-'))
try {
  const staged = join(stage, 'vigie-agent.php')
  writeFileSync(staged, agent)
  console.log(`php -l local : ${execFileSync(php, ['-l', staged], { encoding: 'utf-8' }).trim()}`)
}
catch (error) {
  if (error.code !== 'ENOENT') throw new Error(`php -l local en échec : ${String(error.stdout ?? error.message).trim()}`)
  console.warn(`⚠ ${php} introuvable : php -l local sauté (le PHP de la cible le fera avant la bascule).`)
}
finally {
  rmSync(stage, { recursive: true, force: true })
}

if (options.check) {
  console.log('Validations locales OK — aucune connexion à la cible.')
  process.exit(0)
}

// --- Accès distant ----------------------------------------------------------

const wslHome = assertWslHome(wsl(['printenv', 'HOME']).trim())
const keyPath = target.sshKey.replace(/^~/, wslHome)
try {
  wsl(['test', '-f', keyPath])
}
catch {
  throw new Error(missingKeyHelp({ keyPath, sshKey: target.sshKey, remote: target.remote, comment: `vigie-${target.name}` }))
}

const sshOpts = sshOptions(keyPath, wslHome)

function ssh(remoteCommand, extra = {}) {
  return wsl(['ssh', ...sshOpts, target.remote, remoteCommand], extra)
}

// Chemin résolu par la cible elle-même : un lien symbolique vers ~/www est refusé.
const [remoteHome, resolved] = ssh(`printf '%s\\n' "$HOME" && realpath -m ${target.remoteDir}`).trim().split('\n')
assertOutsideWebroot(resolved ?? '', remoteHome ?? '')

const remoteState = ssh(`if test -f ${target.script}; then sha256sum ${target.script} | cut -d' ' -f1; grep -m1 "^const VERSION = " ${target.script} || echo "version illisible"; else echo absent; fi`).trim().split('\n')
const remoteSha = remoteState[0] === 'absent' ? null : remoteState[0]
const remoteVersion = remoteSha ? (/'([^']+)'/.exec(remoteState[1] ?? '')?.[1] ?? 'version illisible') : null
console.log(`En ligne : ${remoteSha ? `${remoteVersion} — sha256 ${remoteSha.slice(0, 16)}…` : `aucun agent dans ~/${target.script}`}`)

// Rappel de la pose : la clé est créée par --init, jamais par ce script.
const keyState = ssh('test -f .vigie-agent/secret.key && echo present || echo absent').trim()
const nextSteps = keyState === 'present'
  ? []
  : [
      'Clé de l\'agent absente (~/.vigie-agent/secret.key) : après envoi, voir vigie/docs/agent-php.md',
      `  wsl ssh -i ${target.sshKey} ${target.remote} "php ${target.script} --init"`,
    ]

if (remoteSha === localSha) {
  console.log('\nRien à envoyer : l\'agent en ligne est identique.')
  for (const line of nextSteps) console.log(line)
  process.exit(0)
}
console.log(`\nÀ envoyer : ~/${target.script}${remoteSha ? ` (l'actuel sera conservé en ~/${target.script}.prev)` : ''}`)

if (!options.apply) {
  console.log('\nPrévisualisation seulement. Relancer avec --apply pour envoyer.')
  process.exit(0)
}

// --- Application ------------------------------------------------------------

ssh(`mkdir -p ${target.remoteDir} && chmod 700 ${target.remoteDir}`)

await withRemoteLock(ssh, target, async () => {
  const staged = `${target.script}.new`
  ssh(`umask 077 && cat > ${staged}`, { input: agent })
  const received = ssh(`sha256sum ${staged} | cut -d' ' -f1`).trim()
  if (received !== localSha) {
    throw new Error(`Agent reçu différent (sha256 ${received}) : rien n'a été basculé, ~/${staged} reste à examiner`)
  }
  // Le PHP de la cible (8.1 sur le site A) juge la syntaxe, pas celui du poste.
  try {
    console.log(`php -l distant : ${ssh(`php -l ${staged}`).trim()}`)
  }
  catch (error) {
    throw new Error(`php -l distant en échec : ${String(error.stdout ?? error.message).trim()} — rien n'a été basculé`)
  }

  // ln -f garde l'ancien inode en .prev ; mv -f dans le même dossier est atomique.
  ssh(`${remoteSha ? `ln -f ${target.script} ${target.script}.prev && ` : ''}mv -f ${staged} ${target.script}`)
  const record = { commit, version, sha256: localSha, previousSha256: remoteSha, at: new Date().toISOString() }
  ssh(`printf '%s\\n' ${shQuote(JSON.stringify(record))} > ${target.recordPath}`)
  console.log(`Basculé : ~/${target.script} (${version})`)
  if (remoteSha) {
    console.log(`\nRetour arrière :\n  wsl ssh -i ${target.sshKey} ${target.remote} "mv -f ${target.script}.prev ${target.script}"`)
  }
})

for (const line of nextSteps) console.log(line)
console.log(`\nDéployé : vigie-agent-php ${version} (${shortCommit}) sur ${target.name}. La tâche planifiée prend le nouveau fichier à son prochain passage.`)

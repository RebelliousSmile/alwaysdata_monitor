// Reprise locale réelle de l'incident du 2026-09-07, chronométrée.
//
//   node vigie/scripts/replay-incident.mjs [--delay <s>] [--keep]
//
// Processus réels, en local, dans un dossier temporaire :
//   - `vigie serve` (le binaire) reçoit les rapports de l'agent ;
//   - l'agent PHP (`vigie-agent.php`) tourne toutes les 5 min sur une copie de
//     l'arborescence de test `wp-healthy` ;
//   - l'exemple Cargo `replay_local` sert le site A en HTTPS local et passe
//     `tick` chaque minute (autorité de test, e-mails sur sa sortie standard :
//     voir examples/replay_local.rs pour la seule différence avec `vigie tick`).
//
// Une fois l'état sain établi (un rapport accepté, un passage des contrôles),
// le script attend --delay secondes (60 par défaut), puis note T0, supprime
// wp-config.php de l'arborescence et met le site servi dans l'état de
// l'incident. Il attend le premier e-mail de chaque canal (agent, contrôles
// externes), 10 min au plus, et sort en 0 si les deux sont partis moins de
// 10 min après T0. Tout est arrêté dans un finally ; --keep garde le dossier.
//
// Prérequis : cargo, php avec l'extension sodium chargeable (`-d extension=sodium`).

import { execFile, execFileSync, spawn } from 'node:child_process'
import { cpSync, createWriteStream, mkdirSync, mkdtempSync, rmSync, unlinkSync, writeFileSync } from 'node:fs'
import { createServer } from 'node:net'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import { createInterface } from 'node:readline'
import { fileURLToPath } from 'node:url'

const vigieRoot = join(dirname(fileURLToPath(import.meta.url)), '..')
const PROMISE_S = 600
const AGENT_PERIOD_MS = 5 * 60 * 1000
const CRITICAL = ['wp-config.php', '.htaccess', '.user.ini', 'wordfence-waf.php', 'index.php']

function parseArgs(argv) {
  const options = { delay: 60, keep: false }
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === '--keep') options.keep = true
    else if (argv[i] === '--delay' && /^\d+$/.test(argv[i + 1] ?? '')) options.delay = Number(argv[++i])
    else throw new Error('Usage : node vigie/scripts/replay-incident.mjs [--delay <s>] [--keep]')
  }
  return options
}

const options = parseArgs(process.argv.slice(2))
const exe = process.platform === 'win32' ? '.exe' : ''
const vigieBin = join(vigieRoot, 'target', 'debug', `vigie${exe}`)
const replayBin = join(vigieRoot, 'target', 'debug', 'examples', `replay_local${exe}`)
const agentScript = join(vigieRoot, 'agent', 'php', 'vigie-agent.php')
const php = ['-d', 'extension=sodium']

const stamp = () => new Date().toISOString().slice(11, 19)
const log = (message) => console.log(`[${stamp()}] ${message}`)
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms))

function freePort() {
  return new Promise((resolve, reject) => {
    const server = createServer()
    server.once('error', reject)
    server.listen(0, '127.0.0.1', () => {
      const { port } = server.address()
      server.close(() => resolve(port))
    })
  })
}

// --- Préparation ------------------------------------------------------------

log('compilation de vigie et de l\'exemple replay_local')
execFileSync('cargo', ['build', '--locked', '--bin', 'vigie', '--example', 'replay_local'], {
  cwd: vigieRoot,
  stdio: 'inherit',
})

const dir = mkdtempSync(join(tmpdir(), 'vigie-replay-'))
const children = new Set()
const timers = new Set()
const result = { t0: null, agent: null, external: null, early: [], mails: [] }
let cleaned = false

async function stopAll() {
  if (cleaned) return []
  cleaned = true
  for (const timer of timers) clearInterval(timer)
  const exits = [...children].map((child) => new Promise((resolve) => {
    if (child.exitCode !== null || child.signalCode !== null) return resolve(null)
    const timeout = setTimeout(() => resolve(child), 5000)
    child.once('exit', () => { clearTimeout(timeout); resolve(null) })
    child.kill()
  }))
  const survivors = (await Promise.all(exits)).filter(Boolean)
  if (!options.keep) rmSync(dir, { recursive: true, force: true })
  return survivors
}

process.once('SIGINT', async () => {
  log('interrompu : arrêt des processus')
  await stopAll()
  process.exit(130)
})

function track(child, name) {
  children.add(child)
  child.once('exit', (code, signal) => {
    children.delete(child)
    if (!cleaned && code !== 0) log(`${name} s'est arrêté (code ${code ?? signal})`)
  })
  return child
}

async function main() {
  const [servePort, sitePort] = [await freePort(), await freePort()]
  const www = join(dir, 'www')
  cpSync(join(vigieRoot, 'agent', 'php', 'tests', 'fixtures', 'wp-healthy'), www, { recursive: true })
  const flag = join(dir, 'incident')
  const configPath = join(dir, 'config.toml')
  const base = `https://127.0.0.1:${sitePort}`
  // JSON.stringify : une chaîne TOML de base valide, chemins Windows compris.
  writeFileSync(configPath, [
    `database = ${JSON.stringify(join(dir, 'vigie.db'))}`,
    '',
    '[alerts]',
    'to = "alertes@example.org"',
    'from = "vigie@example.org"',
    'smtp_host = "smtp.example.org"',
    `password_file = ${JSON.stringify(join(dir, 'smtp-password'))}`,
    '',
    '[[sites]]',
    'id = "site-a"',
    `url = "${base}/"`,
    'kind = "wordpress"',
    `keyword_url = "${base}/kb/"`,
    'keyword = "/problemes/"',
    'interval = 300',
    '',
  ].join('\n'))

  const agentDir = join(dir, 'agent')
  mkdirSync(agentDir)
  const agentConfig = join(agentDir, 'config.json')
  writeFileSync(agentConfig, JSON.stringify({
    site: 'site-a',
    endpoint: `http://127.0.0.1:${servePort}/r/v1/report`,
    root: www,
    kind: 'wordpress',
    critical: CRITICAL,
    must_contain: [{ file: '.htaccess', text: '# BEGIN site-a installer lock' }],
  }, null, 2))
  const init = execFileSync('php', [...php, agentScript, '--init', '--config', agentConfig], { encoding: 'utf-8' })
  const pubkey = init.match(/^[A-Za-z0-9+/]{43}=$/m)?.[0]
  if (!pubkey) throw new Error(`clé publique introuvable dans la sortie de --init :\n${init}`)
  execFileSync(vigieBin, ['--config', configPath, 'site', 'add', 'site-a', '--pubkey', pubkey], { stdio: 'inherit' })

  // --- Processus ------------------------------------------------------------

  const serveLog = createWriteStream(join(dir, 'serve.log'))
  const serve = track(spawn(vigieBin, ['--config', configPath, 'serve', '--ip', '127.0.0.1', '--port', String(servePort)], {
    stdio: ['ignore', 'pipe', 'pipe'],
  }), 'vigie serve')
  serve.stdout.pipe(serveLog)
  serve.stderr.pipe(serveLog)
  for (let i = 0; ; i++) {
    try {
      await fetch(`http://127.0.0.1:${servePort}/health`)
      break
    } catch {
      if (i >= 50) throw new Error(`vigie serve ne répond pas (voir ${join(dir, 'serve.log')})`)
      await sleep(100)
    }
  }
  log(`vigie serve écoute sur 127.0.0.1:${servePort}`)

  let firstCheck = null
  const replayLog = createWriteStream(join(dir, 'replay.log'))
  const replay = track(spawn(replayBin, ['--config', configPath, '--port', String(sitePort), '--incident-flag', flag], {
    stdio: ['ignore', 'pipe', 'pipe'],
  }), 'replay_local')
  replay.stderr.pipe(replayLog)
  createInterface({ input: replay.stdout }).on('line', (line) => {
    replayLog.write(`${line}\n`)
    const [kind, ...rest] = line.split(' ')
    const data = rest.length ? JSON.parse(rest.join(' ')) : {}
    if (kind === 'READY') log(`site A servi sur ${data.base}`)
    if (kind === 'TICK') {
      if (data.error) log(`tick en erreur : ${data.error}`)
      else if (data.checks > 0 && firstCheck === null) firstCheck = data.at
    }
    if (kind === 'MAIL') {
      const channel = data.body.includes('Contrôle : agent:') ? 'agent' : 'external'
      const mail = { channel, subject: data.subject, at: data.at }
      result.mails.push(mail)
      if (result.t0 === null) {
        result.early.push(mail)
        log(`e-mail AVANT l'injection : ${data.subject}`)
        return
      }
      const delay = data.at - result.t0
      log(`e-mail ${channel === 'agent' ? 'agent' : 'externe'} à T0+${delay} s : ${data.subject}`)
      result[channel] ??= delay
    }
  })

  let accepted = 0
  let agentRunning = null
  const runAgent = () => {
    if (agentRunning) return
    agentRunning = track(execFile('php', [...php, agentScript, '--config', agentConfig], { encoding: 'utf-8' }, (err, _out, stderr) => {
      agentRunning = null
      if (cleaned) return
      if (err) log(`agent en échec (code ${err.code}) : ${stderr.trim()}`)
      else {
        accepted++
        log(`rapport de l'agent accepté (${accepted})`)
      }
    }), 'agent PHP')
  }
  runAgent()
  timers.add(setInterval(runAgent, AGENT_PERIOD_MS))

  // --- Mesure ---------------------------------------------------------------

  while (accepted === 0 || firstCheck === null) {
    if (children.size === 0) throw new Error('plus aucun processus en vie')
    await sleep(1000)
  }
  log(`état sain établi ; injection dans ${options.delay} s`)
  await sleep(options.delay * 1000)
  if (result.early.length) throw new Error(`${result.early.length} e-mail(s) avant l'injection`)

  result.t0 = Math.floor(Date.now() / 1000)
  unlinkSync(join(www, 'wp-config.php'))
  writeFileSync(flag, '')
  log('T0 : wp-config.php supprimé, site servi dans l\'état de l\'incident')

  const deadline = (result.t0 + PROMISE_S + 60) * 1000
  while ((result.agent === null || result.external === null) && Date.now() < deadline) {
    await sleep(1000)
  }
}

let failure = null
try {
  await main()
} catch (err) {
  failure = err
} finally {
  const survivors = await stopAll()
  const summary = {
    date: new Date().toISOString(),
    t0: result.t0 && new Date(result.t0 * 1000).toISOString(),
    first_alert_s: [result.agent, result.external].filter((d) => d !== null).sort((a, b) => a - b)[0] ?? null,
    agent_s: result.agent,
    external_s: result.external,
    mails: result.mails.length,
    survivors: survivors.length,
    dir: options.keep ? dir : null,
  }
  console.log(`RESULT ${JSON.stringify(summary)}`)
  const ok = !failure
    && survivors.length === 0
    && result.early.length === 0
    && result.agent !== null && result.agent < PROMISE_S
    && result.external !== null && result.external < PROMISE_S
  if (failure) console.error(`échec : ${failure.message}`)
  if (survivors.length) console.error(`${survivors.length} processus encore en vie`)
  log(ok ? `réception locale validée : chaque canal sous ${PROMISE_S} s` : 'réception locale NON validée')
  process.exitCode = ok ? 0 : 1
}

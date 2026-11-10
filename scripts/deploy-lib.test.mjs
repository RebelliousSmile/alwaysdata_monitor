import assert from 'node:assert/strict'
import { test } from 'node:test'
import {
  assertOutsideWebroot,
  assertWslHome,
  missingKeyHelp,
  parseArgs,
  shQuote,
  sshOptions,
  extractAgentVersion,
  judgeHealth,
  validateAgentTarget,
  validateRemoteRelativePath,
  validateSshAccess,
  withRemoteLock,
} from './deploy-lib.mjs'

const TARGET = {
  host: 'ssh-site.example.org',
  user: 'site',
  sshKey: '~/.ssh/site_ci',
}

test('parseArgs ignore le séparateur pnpm et lit les options', () => {
  assert.deepEqual(parseArgs(['shop', '--', '--apply']), {
    target: 'shop', apply: true, check: false, anyBranch: false,
  })
})

test('parseArgs refuse une option inconnue', () => {
  assert.throws(() => parseArgs(['shop', '--force']), /Option inconnue/)
})

test('parseArgs refuse --apply avec --check', () => {
  assert.throws(() => parseArgs(['shop', '--apply', '--check']), /incompatibles/)
})

test('shQuote échappe les apostrophes', () => {
  assert.equal(shQuote(`l'heure`), `'l'\\''heure'`)
})

test('validateSshAccess compose le remote et cite le fichier de la cible absente', () => {
  assert.deepEqual(validateSshAccess('shop', TARGET, 'x.json'), {
    name: 'shop', host: TARGET.host, user: 'site', sshKey: '~/.ssh/site_ci', remote: 'site@ssh-site.example.org',
  })
  assert.throws(() => validateSshAccess('shop', undefined, 'deploy/targets.json'), /absente de deploy\/targets\.json/)
})

test('validateSshAccess refuse un nom, un hôte ou une clé hors liste blanche', () => {
  assert.throws(() => validateSshAccess('Shop', TARGET, 'x.json'), /Nom de cible invalide/)
  assert.throws(() => validateSshAccess('shop', { ...TARGET, host: 'a;b' }, 'x.json'), /host invalide/)
  assert.throws(() => validateSshAccess('shop', { ...TARGET, sshKey: '/etc/key' }, 'x.json'), /sshKey/)
})

test('validateRemoteRelativePath nomme le champ refusé', () => {
  assert.equal(validateRemoteRelativePath('remoteDir', 'vigie'), 'vigie')
  assert.throws(() => validateRemoteRelativePath('remoteDir', '/home/x'), /^Error: remoteDir doit être un chemin relatif/)
  assert.throws(() => validateRemoteRelativePath('remoteDir', 'a b'), /remoteDir/)
  assert.throws(() => validateRemoteRelativePath('remoteDir', undefined), /remoteDir/)
})

test('assertWslHome n\'accepte que /home/<utilisateur> ou /root', () => {
  assert.equal(assertWslHome('/home/fx'), '/home/fx')
  assert.equal(assertWslHome('/root'), '/root')
  for (const bad of ['', '/', '/home', '/home/', '/home/a/b', '/tmp', 'home/fx', '/home/a b', undefined]) {
    assert.throws(() => assertWslHome(bad), /HOME de WSL/, String(bad))
  }
})

test('sshOptions force la clé dédiée en BatchMode', () => {
  const opts = sshOptions('/home/fx/.ssh/k', '/home/fx')
  assert.deepEqual(opts.slice(0, 2), ['-i', '/home/fx/.ssh/k'])
  assert.ok(opts.includes('BatchMode=yes'))
  assert.ok(opts.includes('IdentitiesOnly=yes'))
  assert.ok(opts.includes('ControlPath=/home/fx/.ssh/cm-%r@%h:%p'))
})

test('missingKeyHelp donne les deux commandes à lancer', () => {
  const help = missingKeyHelp({ keyPath: '/home/fx/.ssh/k', sshKey: '~/.ssh/k', remote: 'u@h', comment: 'vigie-v' })
  assert.match(help, /ssh-keygen -t ed25519 -N "" -C vigie-v -f ~\/\.ssh\/k/)
  assert.match(help, /ssh-copy-id -i ~\/\.ssh\/k\.pub u@h/)
})

function fakeSsh({ lockTaken = false, rmdirFails = false } = {}) {
  const calls = []
  const ssh = (command) => {
    calls.push(command)
    if (command.startsWith('mkdir ') && lockTaken) throw new Error('exists')
    if (command.startsWith('rmdir ') && rmdirFails) throw new Error('busy')
    return ''
  }
  return { ssh, calls }
}

const LOCK = { lockPath: 'vigie/deploy.lock', sshKey: '~/.ssh/k', remote: 'u@h' }

test('withRemoteLock prend puis rend le verrou autour du corps', async () => {
  const { ssh, calls } = fakeSsh()
  const result = await withRemoteLock(ssh, LOCK, async () => {
    calls.push('body')
    return 42
  })
  assert.equal(result, 42)
  assert.deepEqual(calls, ['mkdir vigie/deploy.lock', 'body', 'rmdir vigie/deploy.lock'])
})

test('withRemoteLock rend le verrou quand le corps échoue', async () => {
  const { ssh, calls } = fakeSsh()
  await assert.rejects(withRemoteLock(ssh, LOCK, async () => {
    throw new Error('scp')
  }), /scp/)
  assert.deepEqual(calls, ['mkdir vigie/deploy.lock', 'rmdir vigie/deploy.lock'])
})

test('withRemoteLock refuse un verrou déjà pris sans lancer le corps', async () => {
  const { ssh, calls } = fakeSsh({ lockTaken: true })
  await assert.rejects(withRemoteLock(ssh, LOCK, async () => calls.push('body')), /Verrou déjà pris/)
  assert.deepEqual(calls, ['mkdir vigie/deploy.lock'])
})

test('withRemoteLock signale un verrou non rendu sans masquer le résultat', async (t) => {
  const { ssh } = fakeSsh({ rmdirFails: true })
  const errors = []
  t.mock.method(console, 'error', message => errors.push(message))
  assert.equal(await withRemoteLock(ssh, LOCK, async () => 'ok'), 'ok')
  assert.match(errors[0], /Verrou non libéré.*rmdir vigie\/deploy\.lock/)
})

const AGENT = { host: 'ssh-site.example.org', user: 'site', sshKey: '~/.ssh/vigie_agent' }

test('validateAgentTarget pose ~/vigie-agent par défaut', () => {
  const target = validateAgentTarget('site-a-agent', AGENT, 'x.json')
  assert.equal(target.script, 'vigie-agent/vigie-agent.php')
  assert.equal(target.lockPath, 'vigie-agent/deploy.lock')
  assert.equal(target.remote, 'site@ssh-site.example.org')
})

test('validateAgentTarget refuse une destination sous ~/www', () => {
  for (const remoteDir of ['www', 'www/vigie', 'WWW/x', 'www-old']) {
    assert.throws(() => validateAgentTarget('a', { ...AGENT, remoteDir }, 'x.json'), /webroot/)
  }
  assert.throws(() => validateAgentTarget('a', { ...AGENT, remoteDir: '../www' }, 'x.json'), /relatif/)
})

test('assertOutsideWebroot juge le chemin résolu, liens compris', () => {
  assert.equal(assertOutsideWebroot('/home/site/vigie-agent', '/home/site'), '/home/site/vigie-agent')
  assert.equal(assertOutsideWebroot('/home/site/wwwx', '/home/site/'), '/home/site/wwwx')
  assert.throws(() => assertOutsideWebroot('/home/site/www', '/home/site'), /webroot/)
  assert.throws(() => assertOutsideWebroot('/home/site/www/a', '/home/site'), /webroot/)
  assert.throws(() => assertOutsideWebroot('', '/home/site'), /illisibles/)
})

test('extractAgentVersion lit la constante de l\'agent', () => {
  assert.equal(extractAgentVersion("<?php\nconst VERSION = '0.1.0';\nconst AGENT = 'x';\n"), '0.1.0')
  assert.throws(() => extractAgentVersion('<?php\n'), /VERSION introuvable/)
  assert.throws(() => extractAgentVersion("const VERSION = '0.1';"), /non numérique/)
})

test('judgeHealth : seul un 200 au tick postérieur à la bascule prouve', () => {
  const since = 1700000000
  const out = (body, code) => `${body}\n${code}`
  assert.deepEqual(judgeHealth(out('{"last_tick":1700000060}', 200), since), { ok: true, last: '200, tick 1700000060' })
  assert.deepEqual(judgeHealth(out('{"last_tick":1700000000}', 200), since), { ok: false, last: '200, dernier tick 1700000000 (bascule 1700000000)' })
  assert.deepEqual(judgeHealth(out('{"last_tick":1700000060}', 503), since), { ok: false, last: '503, dernier tick 1700000060 (bascule 1700000000)' })
  assert.deepEqual(judgeHealth(out('<html>erreur</html>', 502), since), { ok: false, last: '502' })
  assert.deepEqual(judgeHealth(out('{"last_tick":"1700000060"}', 200), since), { ok: false, last: '200' })
  assert.deepEqual(judgeHealth('', since), { ok: false, last: 'sans code' })
})

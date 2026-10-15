import assert from 'node:assert/strict'
import { test } from 'node:test'
import {
  assertVersionsAligned,
  assertWslHome,
  backupFileName,
  compareVersions,
  extractXmlVersion,
  missingKeyHelp,
  parseArgs,
  parseItemized,
  shQuote,
  sshOptions,
  touchesContainer,
  validateRemoteRelativePath,
  validateSshAccess,
  validateTarget,
  withRemoteLock,
} from './deploy-lib.mjs'

const TARGET = {
  host: 'ssh-shop.alwaysdata.net',
  user: 'shop',
  sshKey: '~/.ssh/shop_ci',
  shopRoot: 'www/prestashop',
  siteUrl: 'https://www.example.com/',
  lifecycleRevision: 1,
}

test('parseArgs ignore le séparateur pnpm et lit les options', () => {
  assert.deepEqual(parseArgs(['shop', '--', '--apply']), {
    target: 'shop', apply: true, check: false, anyBranch: false, allowDowngrade: false, clearCache: false,
  })
})

test('parseArgs refuse une option inconnue', () => {
  assert.throws(() => parseArgs(['shop', '--force']), /Option inconnue/)
})

test('parseArgs refuse --apply avec --check', () => {
  assert.throws(() => parseArgs(['shop', '--apply', '--check']), /incompatibles/)
})

test('validateTarget dérive les chemins distants relatifs au home', () => {
  const target = validateTarget('shop', TARGET)
  assert.equal(target.moduleDir, 'www/prestashop/modules/sc_alwaysdata')
  assert.equal(target.lockPath, 'deploy/sc_alwaysdata-shop/lock')
})

test('validateTarget refuse un shopRoot absolu', () => {
  assert.throws(() => validateTarget('shop', { ...TARGET, shopRoot: '/home/shop/www' }), /relatif/)
})

test('validateTarget refuse un shopRoot qui remonte', () => {
  assert.throws(() => validateTarget('shop', { ...TARGET, shopRoot: 'www/../..' }), /relatif/)
})

test('validateTarget refuse une siteUrl en http', () => {
  assert.throws(() => validateTarget('shop', { ...TARGET, siteUrl: 'http://www.example.com/' }), /https/)
})

test('compareVersions compare numériquement', () => {
  assert.equal(compareVersions('1.10.0', '1.9.3'), 1)
})

test('compareVersions refuse un suffixe', () => {
  assert.throws(() => compareVersions('1.10.0-beta', '1.9.0'), /non numérique/)
})

test('extractXmlVersion lit une version en CDATA', () => {
  assert.equal(extractXmlVersion('<module><version><![CDATA[1.10.0]]></version></module>'), '1.10.0')
})

test('assertVersionsAligned signale le fichier désaligné', () => {
  assert.throws(() => assertVersionsAligned({
    configXml: '<version><![CDATA[1.10.0]]></version>',
    configFrXml: '<version><![CDATA[1.9.0]]></version>',
    modulePhp: "public const VERSION = '1.10.0';",
  }), /config_fr\.xml=1\.9\.0/)
})

test('parseItemized sépare envois et fichiers en trop', () => {
  const output = [
    '<f.st...... src/Service/IpSuspicionScorer.php',
    'cd+++++++++ src/Agent/',
    '*deleting   tests/Service/OldTest.php',
    '.d          ./',
    '',
  ].join('\n')
  assert.deepEqual(parseItemized(output), {
    changes: [
      { flags: '<f.st......', path: 'src/Service/IpSuspicionScorer.php' },
      { flags: 'cd+++++++++', path: 'src/Agent/' },
    ],
    deletions: ['tests/Service/OldTest.php'],
  })
})

test('touchesContainer détecte un changement sous config/', () => {
  assert.equal(touchesContainer([{ flags: '<f.st......', path: 'config/services.yml' }]), true)
})

test('shQuote échappe les apostrophes', () => {
  assert.equal(shQuote(`l'heure`), `'l'\\''heure'`)
})

test('backupFileName horodate en UTC sans séparateurs', () => {
  assert.equal(backupFileName(new Date('2026-10-15T08:30:05.123Z'), '1.9.0'), 'sc_alwaysdata-20261015T083005Z-v1.9.0.tar.gz')
})

test('validateSshAccess compose le remote et cite le fichier de la cible absente', () => {
  assert.deepEqual(validateSshAccess('shop', TARGET, 'x.json'), {
    name: 'shop', host: TARGET.host, user: 'shop', sshKey: '~/.ssh/shop_ci', remote: 'shop@ssh-shop.alwaysdata.net',
  })
  assert.throws(() => validateSshAccess('shop', undefined, 'vigie/deploy/targets.json'), /absente de vigie\/deploy\/targets\.json/)
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

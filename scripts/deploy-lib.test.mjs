import assert from 'node:assert/strict'
import { test } from 'node:test'
import {
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

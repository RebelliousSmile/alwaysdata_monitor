<?php

declare(strict_types=1);

// Rapport et inventaire signés par l'agent avec une graine fixe, que
// tests/interop.rs et tests/inventory_vectors.rs font accepter (ou refuser)
// par le veilleur :
//   php vigie/agent/php/tests/make-interop-fixture.php
// écrit vigie/tests/fixtures/php-signed-report.json,
// php-signed-inventory.json (fixture wp-inventory du site A fictif) et
// inventory-vectors.json (domaine, corps valide, corps d'autres usages
// rejoués sur /r/v1/inventory, inventaire sans préfixe). Tout y est fixe
// (graine, seq, heure, numéro de série, version de PHP), si bien que
// AgentTest.php vérifie que les fichiers suivis correspondent toujours à ce
// que l'agent produit.

namespace Vigie\Agent\Tests;

use Vigie\Agent\Config;

use function Vigie\Agent\build_body;
use function Vigie\Agent\build_inventory_body;
use function Vigie\Agent\collect;
use function Vigie\Agent\collect_inventory;
use function Vigie\Agent\finding;
use function Vigie\Agent\uuid_v4;

require_once __DIR__ . '/../vigie-agent.php';

// Graine de test publique : la clé qui en découle ne signe que cette fixture.
const INTEROP_SEED_HEX = '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f';
const INTEROP_SEQ = 1_792_079_580_123;
const INTEROP_NOW = 1_792_079_580;

/** Numéro de série fixe de l'inventaire de la fixture. */
const INTEROP_SERIAL_HEX = '00112233445566778899aabbccddeeff';

function interop_path(string $name = 'php-signed-report.json'): string
{
    return \dirname(__DIR__, 3) . '/tests/fixtures/' . $name;
}

/** Paire de clés de la graine de test. */
function interop_pair(): string
{
    return sodium_crypto_sign_seed_keypair(hex2bin(INTEROP_SEED_HEX));
}

/** Configuration d'inventaire du site A fictif (fixture wp-inventory). */
function interop_inventory_config(): Config
{
    return new Config(
        'site-a', 'https://vigie.invalid/r/v1/report', __DIR__ . '/fixtures/wp-inventory', 'wordpress', [], [], null,
        inventory: ['composer' => ['app/composer.lock'], 'npm' => []],
        inventoryEndpoint: 'https://vigie.invalid/r/v1/inventory',
    );
}

/** @return array{seed_hex: string, public_key: string, body: string, signature: string} */
function interop_inventory(): array
{
    $config = interop_inventory_config();
    $inventory = collect_inventory($config, \PHP_INT_MAX);
    $body = build_inventory_body($config, $inventory, INTEROP_SEQ, INTEROP_NOW, uuid_v4(hex2bin(INTEROP_SERIAL_HEX)));
    $pair = interop_pair();

    return [
        'seed_hex' => INTEROP_SEED_HEX,
        'public_key' => base64_encode(sodium_crypto_sign_publickey($pair)),
        'body' => $body,
        'signature' => base64_encode(sodium_crypto_sign_detached(\Vigie\Agent\DOMAIN_INVENTORY . $body, sodium_crypto_sign_secretkey($pair))),
    ];
}

/**
 * Vecteurs de /r/v1/inventory : chaque corps signé sous son propre domaine,
 * posté sur /r/v1/inventory ; seul l'inventaire valide est accepté.
 */
function inventory_vectors(): array
{
    $secret = sodium_crypto_sign_secretkey(interop_pair());
    $sign = static fn (string $domain, string $body): string => base64_encode(sodium_crypto_sign_detached($domain . $body, $secret));
    $inventory = interop_inventory();
    $report = interop_fixture();
    $flags = \JSON_UNESCAPED_SLASHES | \JSON_UNESCAPED_UNICODE | \JSON_THROW_ON_ERROR;
    $pull = json_encode(['v' => 1, 'type' => 'pull', 'site' => 'site-a', 'seq' => INTEROP_SEQ + 1, 'sent_at' => INTEROP_NOW,
        'nonce' => 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA', 'agent' => \Vigie\Agent\AGENT], $flags);
    $logs = \Vigie\Agent\log_batch_body(interop_inventory_config(), INTEROP_SEQ + 2, INTEROP_NOW,
        ['file' => 'http-2026-10-15.log', 'gen' => 1, 'start' => 0, 'end' => 10], 0, "site-a\n");

    return [
        'domain' => \Vigie\Agent\DOMAIN_INVENTORY,
        'seed_hex' => INTEROP_SEED_HEX,
        'public_key' => $inventory['public_key'],
        'now' => INTEROP_NOW,
        'vectors' => [
            ['name' => 'valid', 'body' => $inventory['body'], 'signature' => $inventory['signature'], 'status' => 204],
            ['name' => 'report-replayed', 'body' => $report['body'], 'signature' => $report['signature'], 'status' => 404],
            ['name' => 'pull-replayed', 'body' => $pull, 'signature' => $sign(\Vigie\Agent\DOMAIN_PULL, $pull), 'status' => 404],
            ['name' => 'logs-replayed', 'body' => $logs, 'signature' => $sign(\Vigie\Agent\DOMAIN_LOGS, $logs), 'status' => 404],
            ['name' => 'unprefixed', 'body' => $inventory['body'], 'signature' => $sign('', $inventory['body']), 'status' => 404],
        ],
    ];
}

/** Contenu exact de chaque fichier suivi, par nom. */
function interop_files(): array
{
    $flags = \JSON_PRETTY_PRINT | \JSON_UNESCAPED_SLASHES | \JSON_UNESCAPED_UNICODE | \JSON_THROW_ON_ERROR;

    return [
        'php-signed-report.json' => interop_json(),
        'php-signed-inventory.json' => json_encode(interop_inventory(), $flags) . "\n",
        'inventory-vectors.json' => json_encode(inventory_vectors(), $flags) . "\n",
    ];
}

/** @return array{seed_hex: string, public_key: string, body: string, signature: string} */
function interop_fixture(): array
{
    $config = new Config(
        'site-a',
        'https://vigie.invalid/r/v1/report',
        __DIR__ . '/fixtures/wp-healthy',
        'wordpress',
        ['wp-config.php', '.htaccess', '.user.ini', 'wordfence-waf.php', 'index.php'],
        [['file' => '.htaccess', 'text' => '# BEGIN site-a installer lock']],
        'wp-content/uploads',
    );
    $collected = collect($config);
    $collected['facts']['php_version'] = '8.1.34';
    // Deux constats de la forme exacte de l'agent, dont un avec des caractères
    // non ASCII, pour que le test Rust lise autre chose qu'un rapport vide.
    $collected['findings'][] = finding('uploads-php', 'critical', 'wp-content/uploads/2026/10/shell.php', 'Fichier PHP dans uploads : wp-content/uploads/2026/10/shell.php (31 octets, sha256 5f0c4d1e2a3b4c5d…)');
    $collected['findings'][] = finding('must-contain', 'critical', '.htaccess', '.htaccess ne contient plus « # BEGIN site-a installer lock »');
    $pair = sodium_crypto_sign_seed_keypair(hex2bin(INTEROP_SEED_HEX));
    $body = build_body($config, $collected, INTEROP_SEQ, INTEROP_NOW);

    return [
        'seed_hex' => INTEROP_SEED_HEX,
        'public_key' => base64_encode(sodium_crypto_sign_publickey($pair)),
        'body' => $body,
        'signature' => base64_encode(sodium_crypto_sign_detached($body, sodium_crypto_sign_secretkey($pair))),
    ];
}

function interop_json(): string
{
    return json_encode(interop_fixture(), \JSON_PRETTY_PRINT | \JSON_UNESCAPED_SLASHES | \JSON_UNESCAPED_UNICODE | \JSON_THROW_ON_ERROR) . "\n";
}

if (get_included_files()[0] === __FILE__) {
    if (!\extension_loaded('sodium')) {
        fwrite(\STDERR, "Extension sodium absente.\n");
        exit(3);
    }
    foreach (interop_files() as $name => $content) {
        file_put_contents(interop_path($name), $content);
        echo 'Écrit : ' . interop_path($name) . "\n";
    }
}

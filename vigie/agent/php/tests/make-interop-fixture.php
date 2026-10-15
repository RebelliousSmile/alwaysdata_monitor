<?php

declare(strict_types=1);

// Rapport signé par l'agent avec une graine fixe, que tests/interop.rs fait
// accepter par l'ingestion du veilleur :
//   php vigie/agent/php/tests/make-interop-fixture.php
// écrit vigie/tests/fixtures/php-signed-report.json. Tout y est fixe (graine,
// seq, heure, version de PHP), si bien que AgentTest.php vérifie que le
// fichier suivi correspond toujours à ce que l'agent produit.

namespace Vigie\Agent\Tests;

use Vigie\Agent\Config;

use function Vigie\Agent\build_body;
use function Vigie\Agent\collect;
use function Vigie\Agent\finding;

require_once __DIR__ . '/../vigie-agent.php';

// Graine de test publique : la clé qui en découle ne signe que cette fixture.
const INTEROP_SEED_HEX = '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f';
const INTEROP_SEQ = 1_792_079_580_123;
const INTEROP_NOW = 1_792_079_580;

function interop_path(): string
{
    return \dirname(__DIR__, 3) . '/tests/fixtures/php-signed-report.json';
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
    file_put_contents(interop_path(), interop_json());
    echo 'Écrit : ' . interop_path() . "\n";
}

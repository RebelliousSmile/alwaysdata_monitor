<?php

declare(strict_types=1);

// Tests de l'agent, lancés par run.php. Chaque scénario part d'une copie de
// fixtures/wp-healthy dans un dossier temporaire ; la fixture elle-même n'est
// que lue.
//
// Les fichiers PHP « suspects » des scénarios ne contiennent que du code
// anodin : seul leur nom et leur emplacement comptent pour l'agent, et un
// contenu de webshell fait mettre ce fichier en quarantaine par l'antivirus.

namespace Vigie\Agent\Tests;

use Vigie\Agent\UsageError;

use function Vigie\Agent\collect;
use function Vigie\Agent\load_config;
use function Vigie\Agent\load_secret;
use function Vigie\Agent\printable;

/** Constats du site, indexés par « check/key ». */
function findings_of(string $root, array $override = []): array
{
    $collected = collect(load_config(write_config($root, $override)));
    $byKey = [];
    foreach ($collected['findings'] as $finding) {
        $byKey[$finding['check'] . '/' . $finding['key']] = $finding;
    }

    return $byKey;
}

function refused_load(string $path, string $expected): void
{
    try {
        load_config($path);
    } catch (UsageError $e) {
        check(str_contains($e->getMessage(), $expected), "message inattendu : {$e->getMessage()}");

        return;
    }
    throw new Failure("configuration acceptée : {$path}");
}

function refused_config(array $override, string $expected): void
{
    try {
        load_config(write_config(fixture(), $override));
    } catch (UsageError $e) {
        check(str_contains($e->getMessage(), $expected), "message inattendu : {$e->getMessage()}");

        return;
    }
    throw new Failure('configuration acceptée : ' . json_encode($override));
}

/** Initialise une clé dans un dossier neuf ; rend la config et la clé publique. */
function init_agent(string $root, array $override = []): array
{
    $config = write_config($root, $override);
    $init = agent('--init', '--config', $config);
    same(0, $init['code'], "--init : {$init['stderr']}");
    check(preg_match('#^([A-Za-z0-9+/]{43}=)$#m', $init['stdout'], $m) === 1, "clé publique absente : {$init['stdout']}");

    return [$config, base64_decode($m[1], true)];
}

/** Routeur `php -S` qui enregistre la requête et répond 204 sur /r/v1/report. */
function recording_router(string $dir): string
{
    $router = $dir . '/router.php';
    file_put_contents($router, <<<'PHP'
        <?php
        file_put_contents(__DIR__ . '/received.json', json_encode([
            'method' => $_SERVER['REQUEST_METHOD'],
            'uri' => $_SERVER['REQUEST_URI'],
            'headers' => array_change_key_case(getallheaders(), CASE_LOWER),
            'body' => file_get_contents('php://input'),
        ]));
        http_response_code($_SERVER['REQUEST_URI'] === '/r/v1/report' ? 204 : 404);
        PHP);

    return $router;
}

function mtimes(string $dir): array
{
    clearstatcache();
    $mtimes = [];
    $iterator = new \RecursiveIteratorIterator(
        new \RecursiveDirectoryIterator($dir, \FilesystemIterator::SKIP_DOTS),
        \RecursiveIteratorIterator::SELF_FIRST,
    );
    foreach ($iterator as $path => $info) {
        $mtimes[$path] = $info->getMTime();
    }
    ksort($mtimes);

    return $mtimes;
}

const CRITICAL = ['wp-config.php', '.htaccess', '.user.ini', 'wordfence-waf.php', 'index.php'];

// --- Commandes -------------------------------------------------------------

/** Vecteurs partagés avec les tests Rust (vigie/tests/commands_vectors.rs). */
function vectors(): array
{
    return json_decode((string) file_get_contents(__DIR__ . '/../../../tests/fixtures/commands-vectors.json'), true, 32, \JSON_THROW_ON_ERROR);
}

/** Agent initialisé avec un canal de commandes vers ce port ; config en 0600. */
function commands_agent(int $port, array $override = []): array
{
    $config = write_config(fixture(), array_replace([
        'endpoint' => "http://127.0.0.1:{$port}/r/v1/report",
        'commands' => ['endpoint' => "http://127.0.0.1:{$port}/r/v1/commands", 'pubkey' => vectors()['commands_pubkey']],
    ], $override));
    chmod($config, 0600);
    $init = agent('--init', '--config', $config);
    same(0, $init['code'], "--init : {$init['stderr']}");

    return [$config, \dirname($config)];
}

/**
 * Routeur `php -S` qui joue le veilleur : 204 aux rapports ; aux retraits,
 * l'accusé du résultat reçu, puis la commande du scénario tant qu'aucun
 * résultat n'est venu. Signé par la clé de commandes des vecteurs, ou par la
 * clé du scénario (intrusion).
 */
function veilleur_router(string $dir, array $scenario): string
{
    file_put_contents("{$dir}/scenario.json", json_encode($scenario + [
        'command' => null, 'accepted' => true, 'seed' => vectors()['commands_seed'], 'nonce' => null, 'prefix' => "vigie-commands-v1\n",
    ]));
    $router = $dir . '/router.php';
    file_put_contents($router, <<<'PHP'
        <?php
        $scenario = json_decode(file_get_contents(__DIR__ . '/scenario.json'), true);
        if ($_SERVER['REQUEST_URI'] === '/r/v1/report') {
            http_response_code(204);
            return true;
        }
        $body = file_get_contents('php://input');
        file_put_contents(__DIR__ . '/pulls.jsonl', $body . "\n", FILE_APPEND);
        $request = json_decode($body, true);
        $result = $request['result'] ?? null;
        $served = is_file(__DIR__ . '/served');
        $command = null;
        if ($result === null && $scenario['command'] !== null) {
            $command = $scenario['command'] + ['site' => 'site-a', 'v' => 1, 'runtime' => 'php', 'params' => new stdClass(),
                'issued_at' => time() - 10, 'expires_at' => time() + 3600];
            touch(__DIR__ . '/served');
        }
        $now = time();
        $response = json_encode([
            'v' => 1, 'site' => 'site-a', 'nonce' => $scenario['nonce'] ?? $request['nonce'], 'server_time' => $now,
            'acked' => $result['command_id'] ?? null, 'accepted' => $result === null ? null : $scenario['accepted'],
            'command' => $command,
        ]);
        $pair = sodium_crypto_sign_seed_keypair(base64_decode($scenario['seed']));
        $signature = sodium_crypto_sign_detached($scenario['prefix'] . $now . "\n" . $response, sodium_crypto_sign_secretkey($pair));
        header('Content-Type: application/json');
        header('X-Vigie-Timestamp: ' . $now);
        header('X-Vigie-Signature: ' . base64_encode($signature));
        echo $response;
        PHP);

    return $router;
}

function state_of(string $dir): array
{
    return json_decode((string) file_get_contents("{$dir}/state.json"), true);
}

/** Lignes des retraits reçus par le routeur. */
function pulls_of(string $server): array
{
    $lines = is_file("{$server}/pulls.jsonl") ? file("{$server}/pulls.jsonl", \FILE_IGNORE_NEW_LINES) : [];

    return array_map(static fn (string $l): array => json_decode($l, true), $lines);
}

const PING = ['id' => '01a1e2f3-0000-7000-8000-00000000000a', 'seq' => 1, 'name' => 'ping'];
const ROTATE = ['id' => '01a1e2f3-0000-7000-8000-00000000000b', 'seq' => 2, 'name' => 'rotate-key'];


return [
    'arborescence saine : aucun constat, faits complets' => function (): void {
        $root = tmp_site();
        $collected = collect(load_config(write_config($root)));
        same([], $collected['findings'], 'constats');
        same('6.6.2', $collected['facts']['wp_version'], 'version de WordPress');
        same(0, $collected['facts']['uploads_php'], 'PHP dans uploads');
        same(\Vigie\Agent\VERSION, $collected['facts']['agent_version'], "version de l'agent");
        same(\PHP_VERSION, $collected['facts']['php_version'], 'version de PHP');
        same(CRITICAL, array_keys($collected['files']), 'fichiers critiques');
        foreach ($collected['files'] as $file => $hash) {
            same(hash_file('sha256', "{$root}/{$file}"), $hash, "empreinte de {$file}");
        }
    },

    'sans wp-config.php : constat critique' => function (): void {
        $root = tmp_site();
        unlink("{$root}/wp-config.php");
        $collected = collect(load_config(write_config($root)));
        same(null, $collected['files']['wp-config.php'], 'empreinte absente');
        same(
            [['check' => 'critical-file', 'severity' => 'critical', 'key' => 'wp-config.php', 'detail' => 'Fichier critique absent : wp-config.php']],
            $collected['findings'],
            'constats',
        );
    },

    'verrou installeur retiré : constat critique' => function (): void {
        $root = tmp_site();
        $htaccess = (string) file_get_contents("{$root}/.htaccess");
        file_put_contents("{$root}/.htaccess", str_replace('# BEGIN site-a installer lock', '# BEGIN autre', $htaccess));
        $findings = findings_of($root);
        same(['must-contain/.htaccess'], array_keys($findings), 'constats');
        same('critical', $findings['must-contain/.htaccess']['severity'], 'gravité');
        check(str_contains($findings['must-contain/.htaccess']['detail'], '# BEGIN site-a installer lock'), 'texte attendu cité');
    },

    'shell.php dans uploads : constat critique avec son chemin' => function (): void {
        $root = tmp_site();
        $shell = "{$root}/wp-content/uploads/2026/10/shell.php";
        file_put_contents($shell, '<?php echo "fixture";');
        file_put_contents("{$root}/wp-content/uploads/2026/10/Image.PHTML", 'x');
        $collected = collect(load_config(write_config($root)));
        same(2, $collected['facts']['uploads_php'], 'PHP dans uploads');
        $findings = findings_of($root);
        $key = 'uploads-php/wp-content/uploads/2026/10/shell.php';
        check(isset($findings[$key]), 'constat absent : ' . implode(', ', array_keys($findings)));
        same('critical', $findings[$key]['severity'], 'gravité');
        $expected = filesize($shell) . ' octets, sha256 ' . substr(hash_file('sha256', $shell), 0, 16);
        check(str_contains($findings[$key]['detail'], $expected), $findings[$key]['detail']);
        check(isset($findings['uploads-php/wp-content/uploads/2026/10/Image.PHTML']), 'extension en majuscules');
    },

    'index.php de silence : exempté seulement sans code et sous 64 octets' => function (): void {
        $root = tmp_site();
        same([], findings_of($root), 'silence exempté');
        file_put_contents("{$root}/wp-content/uploads/index.php", "<?php\n// Silence is golden." . str_repeat(' ', 40));
        check(isset(findings_of($root)['uploads-php/wp-content/uploads/index.php']), '64 octets ou plus : signalé');
        file_put_contents("{$root}/wp-content/uploads/index.php", '<?php echo 1;');
        check(isset(findings_of($root)['uploads-php/wp-content/uploads/index.php']), 'petit index.php avec du code : signalé');
        unlink("{$root}/wp-content/uploads/index.php");
        mkdir("{$root}/wp-content/uploads/2026/11");
        file_put_contents("{$root}/wp-content/uploads/2026/11/index.php", "<?php /* Silence is golden. */ ?>\n");
        same([], findings_of($root), 'commentaire bloc exempté');
    },

    'uploads : plafond des constats envoyés' => function (): void {
        $root = tmp_site();
        for ($i = 0; $i < 60; ++$i) {
            file_put_contents("{$root}/wp-content/uploads/2026/10/f{$i}.php", '<?php');
        }
        $collected = collect(load_config(write_config($root)));
        same(60, $collected['facts']['uploads_php'], 'tous comptés');
        $uploads = array_values(array_filter($collected['findings'], static fn (array $f): bool => $f['check'] === 'uploads-php'));
        same(51, \count($uploads), '50 constats et un résumé');
        same('_autres', $uploads[50]['key'], 'clé du résumé');
    },

    'liens symboliques : jamais suivis hors de la racine' => function (): void {
        $root = tmp_site();
        $outside = \dirname($root) . '/dehors.php';
        file_put_contents($outside, '<?php // hors racine');
        unlink("{$root}/index.php");
        skip_unless(@symlink($outside, "{$root}/index.php"), 'symlink indisponible (Windows sans mode développeur)');
        symlink($outside, "{$root}/wp-content/uploads/2026/10/lien.php");
        symlink(\dirname($root), "{$root}/wp-content/uploads/2026/sortie");
        $collected = collect(load_config(write_config($root)));
        $findings = [];
        foreach ($collected['findings'] as $finding) {
            $findings[$finding['check'] . '/' . $finding['key']] = $finding['detail'];
        }
        same(null, $collected['files']['index.php'], 'empreinte non calculée');
        check(str_contains($findings['critical-file/index.php'] ?? '', 'hors de la racine'), 'critique hors racine');
        check(str_contains($findings['uploads-php/wp-content/uploads/2026/10/lien.php'] ?? '', 'lien symbolique'), 'lien .php signalé');
        same(1, $collected['facts']['uploads_php'], "le dossier lié « sortie » n'est pas parcouru");
    },

    'racine introuvable : constat critique, rapport quand même' => function (): void {
        $collected = collect(load_config(write_config(tmp_dir() . '/absent')));
        same(['root'], array_column($collected['findings'], 'key'), 'constats');
        same(array_fill_keys(CRITICAL, null), $collected['files'], 'empreintes nulles');
    },

    'lecture seule : la fixture garde ses fichiers et ses mtime' => function (): void {
        $before = mtimes(fixture());
        collect(load_config(write_config(fixture())));
        same($before, mtimes(fixture()), 'fichiers et mtime');
    },

    'configuration : clés inconnues et chemins hors racine refusés' => function (): void {
        refused_config(['extra' => 1], 'clé inconnue');
        refused_config(['critical' => ['../wp-config.php']], 'critical');
        refused_config(['critical' => ['/etc/passwd']], 'critical');
        refused_config(['critical' => ['a//b']], 'critical');
        refused_config(['critical' => ['C:/x']], 'critical');
        refused_config(['critical' => ['a\\b']], 'critical');
        refused_config(['critical' => ['x', 'x']], 'double');
        refused_config(['critical' => array_map('strval', range(1, 31))], 'critical');
        refused_config(['uploads' => 'wp-content/../..'], 'uploads');
        refused_config(['must_contain' => [['file' => 'a', 'text' => 'b', 'x' => 1]]], 'must_contain');
        refused_config(['endpoint' => 'http://vigie.example/r/v1/report'], 'endpoint');
        refused_config(['endpoint' => 'https://u:p@vigie.example/r/v1/report'], 'endpoint');
        refused_config(['root' => 'www'], 'root');
        refused_config(['site' => 'Site A'], 'site');
        refused_config(['kind' => 'drupal'], 'kind');
        load_config(write_config(fixture(), ['endpoint' => 'http://127.0.0.1:8080/r/v1/report']));
        $cli = agent('--dry-run', '--config', write_config(fixture(), ['extra' => 1]));
        same(2, $cli['code'], 'code de retour en CLI');
    },

    'libellés : contrôles et UTF-8 invalide remplacés, longueur bornée' => function (): void {
        same('a?b?c?', printable("a\nb\u{85}c\x7F", 300), 'contrôles C0, C1, DEL');
        same('a?', printable("a\xFF", 300), 'UTF-8 invalide');
        same(str_repeat('é', 199) . '…', printable(str_repeat('é', 250), 200), 'troncature en caractères');
        same(str_repeat('é', 200), printable(str_repeat('é', 200), 200), 'limite exacte');
    },

    '--init : clé 0600, jamais écrasée' => function (): void {
        [$config] = init_agent(fixture());
        $key = \dirname($config) . '/secret.key';
        $first = file_get_contents($key);
        if (\DIRECTORY_SEPARATOR === '/') {
            same(0600, fileperms($key) & 0777, 'droits de la clé');
        }
        $again = agent('--init', '--config', $config);
        same(2, $again['code'], 'second --init refusé');
        same($first, file_get_contents($key), 'clé inchangée');
        same(\SODIUM_CRYPTO_SIGN_SECRETKEYBYTES, \strlen(load_secret(\dirname($config))), 'clé relue');
    },

    "clé lisible par d'autres : refusée" => function (): void {
        skip_unless(\DIRECTORY_SEPARATOR === '/', 'droits Unix');
        [$config] = init_agent(fixture());
        chmod(\dirname($config) . '/secret.key', 0644);
        $run = agent('--config', $config);
        same(2, $run['code'], 'code de retour');
        check(str_contains($run['stderr'], 'chmod 600'), $run['stderr']);
    },

    '--dry-run : rapport affiché, rien envoyé ni signé' => function (): void {
        $config = write_config(fixture(), ['endpoint' => 'http://127.0.0.1:' . free_port() . '/r/v1/report']);
        $run = agent('--dry-run', '--config', $config);
        same(0, $run['code'], "code de retour : {$run['stderr']}");
        $report = json_decode($run['stdout'], true);
        same('site-a', $report['site'] ?? null, 'site');
        same([], $report['findings'], 'constats');
        check(!file_exists(\dirname($config) . '/secret.key'), 'aucune clé créée');
    },

    'envoi vers un port fermé : code 1' => function (): void {
        [$config] = init_agent(fixture(), ['endpoint' => 'http://127.0.0.1:' . free_port() . '/r/v1/report']);
        $run = agent('--config', $config);
        same(1, $run['code'], "code de retour : {$run['stderr']}");
        check(str_contains($run['stderr'], 'Envoi échoué'), $run['stderr']);
    },

    'envoi : 204, en-têtes et signature vérifiable ; un autre statut donne 1' => function (): void {
        $server = tmp_dir();
        [$port, $stop] = php_server(recording_router($server), $server);
        try {
            [$config, $public] = init_agent(fixture(), ['endpoint' => "http://127.0.0.1:{$port}/r/v1/report"]);
            $run = agent('--config', $config);
            same(0, $run['code'], "code de retour : {$run['stderr']}");
            $received = json_decode((string) file_get_contents("{$server}/received.json"), true);
            same('POST', $received['method'], 'méthode');
            same('site-a', $received['headers']['x-vigie-site'] ?? null, 'X-Vigie-Site');
            same('application/json', $received['headers']['content-type'] ?? null, 'Content-Type');
            same(\Vigie\Agent\AGENT, $received['headers']['user-agent'] ?? null, 'User-Agent');
            $signature = base64_decode($received['headers']['x-vigie-signature'] ?? '', true);
            check(\is_string($signature) && sodium_crypto_sign_verify_detached($signature, $received['body'], $public), 'signature invalide');
            $report = json_decode($received['body'], true);
            same(1, $report['v'], 'version');
            check(abs($report['seq'] - (int) (microtime(true) * 1000)) < 60_000, 'seq en millisecondes');

            [$other] = init_agent(fixture(), ['endpoint' => "http://127.0.0.1:{$port}/autre"]);
            $refused = agent('--config', $other);
            same(1, $refused['code'], 'statut 404');
            check(str_contains($refused['stderr'], 'statut 404'), $refused['stderr']);
        } finally {
            $stop();
        }
    },

    'appel par le web : sortie immédiate, corps vide' => function (): void {
        $docroot = tmp_dir();
        [$port, $stop] = php_server(\dirname(__DIR__) . '/vigie-agent.php', $docroot);
        try {
            $context = stream_context_create(['http' => ['timeout' => 10, 'ignore_errors' => true]]);
            $response = file_get_contents("http://127.0.0.1:{$port}/?--init", false, $context);
            same('', $response, 'corps de la réponse');
            same(['.', '..'], scandir($docroot), 'rien écrit dans le docroot');
        } finally {
            $stop();
        }
    },

    "fixture d'interopérabilité à jour et signature valide" => function (): void {
        $tracked = @file_get_contents(interop_path());
        check($tracked !== false, 'fixture absente : php vigie/agent/php/tests/make-interop-fixture.php');
        same(interop_json(), $tracked, 'fixture périmée : relancer make-interop-fixture.php');
        $fixture = json_decode($tracked, true);
        check(sodium_crypto_sign_verify_detached(base64_decode($fixture['signature']), $fixture['body'], base64_decode($fixture['public_key'])), 'signature');
    },

    'commandes : chaque vecteur de réponse reçoit son verdict' => function (): void {
        $v = vectors();
        $key = base64_decode($v['commands_pubkey'], true);
        foreach ($v['responses'] as $vector) {
            [$verdict] = \Vigie\Agent\verify_response(200, [
                'x-vigie-timestamp' => $vector['timestamp'], 'x-vigie-signature' => $vector['signature'],
            ], $vector['body'], $key, $v['site'], $v['request_nonce'], $v['now']);
            same($vector['verdict'], $verdict, $vector['name']);
        }
        $valid = $v['responses'][0];
        $headers = ['x-vigie-timestamp' => $valid['timestamp'], 'x-vigie-signature' => $valid['signature']];
        same('empty', \Vigie\Agent\verify_response(200, $headers, '', $key, 'site-a', $v['request_nonce'], $v['now'])[0], 'corps vide (php -S en erreur fatale)');
        same('status', \Vigie\Agent\verify_response(500, $headers, $valid['body'], $key, 'site-a', $v['request_nonce'], $v['now'])[0], 'statut');
        same('bad-signature', \Vigie\Agent\verify_response(200, $headers, $valid['body'] . ' ', $key, 'site-a', $v['request_nonce'], $v['now'])[0], 'corps altéré');
    },

    'commandes : retrait et preuve de rotation identiques aux vecteurs' => function (): void {
        $v = vectors();
        $agent = sodium_crypto_sign_secretkey(sodium_crypto_sign_seed_keypair(base64_decode($v['agent_seed'])));
        foreach ($v['pulls'] as $pull) {
            $prefixed = base64_encode(sodium_crypto_sign_detached(\Vigie\Agent\DOMAIN_PULL . $pull['body'], $agent));
            same($pull['verdict'] === 'valid', $prefixed === $pull['signature'], $pull['name']);
        }
        $r = $v['rotation'];
        $new = sodium_crypto_sign_secretkey(sodium_crypto_sign_seed_keypair(base64_decode($r['new_seed'])));
        $proof = base64_encode(sodium_crypto_sign_detached(\Vigie\Agent\DOMAIN_ROTATE . $r['site'] . "\n" . $r['command_id'] . "\n" . $r['new_pubkey'], $new));
        same($r['proof'], $proof, 'preuve de rotation');
    },

    'commandes : configuration ouverte, lien ou clé illisible refusés' => function (): void {
        skip_unless(\DIRECTORY_SEPARATOR === '/', 'droits Unix');
        $commands = ['endpoint' => 'https://vigie.invalid/r/v1/commands', 'pubkey' => vectors()['commands_pubkey']];
        $open = write_config(fixture(), ['commands' => $commands]);
        chmod($open, 0644);
        try {
            load_config($open);
            throw new Failure('config.json en 0644 acceptée');
        } catch (UsageError $e) {
            check(str_contains($e->getMessage(), 'chmod 600'), $e->getMessage());
        }
        chmod($open, 0600);
        load_config($open);
        chmod(\dirname($open), 0755);
        try {
            load_config($open);
            throw new Failure('dossier en 0755 accepté');
        } catch (UsageError $e) {
            check(str_contains($e->getMessage(), 'chmod 700'), $e->getMessage());
        } finally {
            chmod(\dirname($open), 0700);
        }
        $link = \dirname($open) . '/lien.json';
        symlink($open, $link);
        refused_load($link, 'jamais un lien');
        $bad = write_config(fixture(), ['commands' => ['endpoint' => $commands['endpoint'], 'pubkey' => 'court']]);
        chmod($bad, 0600);
        refused_load($bad, 'commands.pubkey');
        $extra = write_config(fixture(), ['commands' => $commands + ['shell' => 'id']]);
        chmod($extra, 0600);
        refused_load($extra, 'sans autre clé');
    },

    'commandes : ping exécuté une fois, résultat renvoyé jusqu\'à l\'accusé' => function (): void {
        $server = tmp_dir();
        [$port, $stop] = php_server(veilleur_router($server, ['command' => PING]), $server);
        try {
            [$config, $dir] = commands_agent($port);
            $first = agent('--config', $config);
            same(0, $first['code'], "premier passage : {$first['stderr']}");
            $state = state_of($dir);
            same(1, $state['last_command_seq'], 'commande exécutée');
            same('ok', $state['result']['status'] ?? null, 'résultat en attente');
            same('pong', $state['result']['detail'] ?? null, 'détail');
            check((fileperms("{$dir}/state.json") & 0777) === 0600, 'état en 0600');
            $second = agent('--config', $config);
            same(0, $second['code'], "second passage : {$second['stderr']}");
            same(null, state_of($dir)['result'], 'résultat accusé');
            $pulls = pulls_of($server);
            same(2, \count($pulls), 'deux retraits');
            same(PING['id'], $pulls[1]['result']['command_id'] ?? null, 'résultat renvoyé');
            check(!\array_key_exists('data', $pulls[1]['result']), 'pas de data vide (refusée par le veilleur)');
            check($pulls[1]['seq'] > $pulls[0]['seq'], 'seq croissant');
            check($pulls[0]['nonce'] !== $pulls[1]['nonce'], 'nonce neuf');
            same([], glob("{$dir}/.state-*") ?: [], 'aucun fichier temporaire laissé');
        } finally {
            $stop();
        }
    },

    'commandes : réponse non signée par la clé épinglée, préfixe faux ou nonce rejoué : rien ne s\'exécute' => function (): void {
        $agentSeed = vectors()['agent_seed'];
        foreach ([
            'clé de l\'agent' => ['seed' => $agentSeed],
            'préfixe de retrait' => ['prefix' => "vigie-pull-v1\n"],
            'nonce rejoué' => ['nonce' => 'QXV0cmVOb25jZUF1dHJlTm9uY2U'],
        ] as $case => $override) {
            $server = tmp_dir();
            [$port, $stop] = php_server(veilleur_router($server, ['command' => PING] + $override), $server);
            try {
                [$config, $dir] = commands_agent($port);
                $run = agent('--config', $config);
                same(1, $run['code'], "{$case} : code");
                check(str_contains($run['stderr'], 'rien n\'est exécuté'), "{$case} : {$run['stderr']}");
                same(0, state_of($dir)['last_command_seq'], "{$case} : rien exécuté");
            } finally {
                $stop();
            }
        }
    },

    'commandes : un état forgé n\'exécute rien, un état ouvert arrête le canal' => function (): void {
        skip_unless(\DIRECTORY_SEPARATOR === '/', 'droits Unix');
        $server = tmp_dir();
        [$port, $stop] = php_server(veilleur_router($server, []), $server);
        try {
            [$config, $dir] = commands_agent($port);
            // Un attaquant écrit une « commande » dans l'état : schéma strict, refus.
            file_put_contents("{$dir}/state.json", json_encode(['pull_seq' => 0, 'last_command_seq' => 0, 'running' => null,
                'result' => null, 'rotation' => null, 'command' => ['name' => 'ping']]));
            chmod("{$dir}/state.json", 0600);
            $run = agent('--config', $config);
            same(2, $run['code'], 'état forgé : code');
            check(str_contains($run['stderr'], 'État illisible'), $run['stderr']);
            same([], pulls_of($server), 'aucun retrait avec un état forgé');
            unlink("{$dir}/state.json");
            agent('--config', $config);
            chmod("{$dir}/state.json", 0644);
            $run = agent('--config', $config);
            check(str_contains($run['stderr'], 'chmod 600'), $run['stderr']);
        } finally {
            $stop();
        }
    },

    'commandes : rotate-key bascule sur un accusé accepté, sinon la nouvelle paire disparaît' => function (): void {
        foreach ([true, false] as $accepted) {
            $server = tmp_dir();
            [$port, $stop] = php_server(veilleur_router($server, ['command' => ROTATE, 'accepted' => $accepted]), $server);
            try {
                [$config, $dir] = commands_agent($port);
                $old = file_get_contents("{$dir}/secret.key");
                same(0, agent('--config', $config)['code'], 'rotation exécutée');
                check(is_file("{$dir}/secret.key.new"), 'nouvelle paire créée');
                same(0600, fileperms("{$dir}/secret.key.new") & 0777, 'nouvelle paire en 0600');
                $result = state_of($dir)['result'];
                $proof = base64_decode($result['data']['proof'], true);
                $newPublic = base64_decode($result['data']['new_pubkey'], true);
                check(sodium_crypto_sign_verify_detached($proof, \Vigie\Agent\DOMAIN_ROTATE . "site-a\n" . ROTATE['id'] . "\n" . $result['data']['new_pubkey'], $newPublic), 'preuve vérifiable');
                $second = agent('--config', $config);
                same(0, $second['code'], "accusé reçu : {$second['stderr']}");
                clearstatcache();
                check(!is_file("{$dir}/secret.key.new"), 'plus de nouvelle paire en attente');
                if ($accepted) {
                    check(file_get_contents("{$dir}/secret.key") !== $old, 'clé basculée');
                    same($old, file_get_contents("{$dir}/secret.key.old"), 'ancienne clé gardée');
                } else {
                    same($old, file_get_contents("{$dir}/secret.key"), 'ancienne clé conservée');
                }
                same(null, state_of($dir)['rotation'], 'rotation close');
            } finally {
                $stop();
            }
        }
    },
];

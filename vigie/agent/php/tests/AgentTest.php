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
use function Vigie\Agent\collect_inventory;
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

// --- Logs ------------------------------------------------------------------
//
// Fichiers de logs générés par chaque test (gzencode pour les .gz) : hôtes
// *.example.org, IP de documentation (RFC 5737), aucun binaire commité.

/** 2026-10-16T12:00:00Z. */
const LOG_NOW = 1_792_152_000;

function log_line(string $host, int $at, string $path = '/', string $ua = 'Mozilla/5.0'): string
{
    return sprintf("%s 192.0.2.10 - - [%s] \"GET %s HTTP/1.1\" 200 512 \"-\" \"%s\"\n", $host, gmdate('d/M/Y:H:i:s +0000', $at), $path, $ua);
}

/** Écrit http-<date>.log (ou .log.gz) dans <logs>/<année>/ ; rend son chemin. */
function write_log(string $logs, string $date, string $content, bool $gz = false): string
{
    $dir = $logs . '/' . substr($date, 0, 4);
    if (!is_dir($dir)) {
        mkdir($dir, 0755, true);
    }
    $path = "{$dir}/http-{$date}.log" . ($gz ? '.gz' : '');
    file_put_contents($path, $gz ? gzencode($content) : $content);

    return $path;
}

/** Compression d'Alwaysdata : le .log devient .log.gz (autre inode). */
function compress_log(string $logs, string $date, string $append = ''): void
{
    $plain = $logs . '/' . substr($date, 0, 4) . "/http-{$date}.log";
    write_log($logs, $date, file_get_contents($plain) . $append, true);
    unlink($plain);
}

/**
 * Routeur `php -S` du veilleur des logs : enregistre chaque lot reçu ; 204,
 * ou 502 tant que le fichier `lose` existe (réponse perdue).
 */
function logs_router(string $dir): string
{
    $router = $dir . '/router.php';
    file_put_contents($router, <<<'PHP'
        <?php
        if ($_SERVER['REQUEST_URI'] === '/r/v1/logs') {
            file_put_contents(__DIR__ . '/logs.jsonl', json_encode([
                'body' => file_get_contents('php://input'),
                'signature' => $_SERVER['HTTP_X_VIGIE_SIGNATURE'] ?? '',
            ]) . "\n", FILE_APPEND);
            http_response_code(is_file(__DIR__ . '/lose') ? 502 : 204);
            return true;
        }
        http_response_code(404);
        PHP);

    return $router;
}

/** Agent du site A avec une section logs, clé créée ; rend [Config, dossier, clé publique]. */
function logs_agent(int $port, string $logs, array $hosts = ['site-a.example.org']): array
{
    $path = write_config(fixture(), [
        'endpoint' => "http://127.0.0.1:{$port}/r/v1/report",
        'logs' => ['dir' => $logs, 'hosts' => $hosts],
    ]);
    $public = base64_decode(\Vigie\Agent\init_key(\dirname($path)), true);

    return [load_config($path), \dirname($path), $public];
}

/** Lots reçus par le routeur, corps décodé et chunk en clair. */
function batches_of(string $server): array
{
    $lines = is_file("{$server}/logs.jsonl") ? file("{$server}/logs.jsonl", \FILE_IGNORE_NEW_LINES) : [];

    return array_map(static function (string $line): array {
        $received = json_decode($line, true);
        $batch = json_decode($received['body'], true);
        $batch['chunk'] = base64_decode($batch['chunk'], true);
        $batch['raw'] = $received['body'];
        $batch['signature'] = $received['signature'];

        return $batch;
    }, $lines);
}

/** Passage des logs ; rend le message d'un échec d'envoi, null sinon. */
function logs_pass_at(\Vigie\Agent\Config $config, string $dir, int $now): ?string
{
    try {
        \Vigie\Agent\send_logs($config, $dir, $now);
    } catch (\Vigie\Agent\SendError $e) {
        return $e->getMessage();
    }

    return null;
}

/** Lance $fn avec un faux veilleur des logs : fn(port, dossier du serveur, dossier des logs). */
function with_logs_server(callable $fn): void
{
    $server = tmp_dir();
    $logs = tmp_dir() . '/http';
    mkdir($logs, 0755);
    [$port, $stop] = php_server(logs_router($server), $server);
    try {
        $fn($port, $server, $logs);
    } finally {
        $stop();
    }
}


// --- .htaccess (#13) ------------------------------------------------------
//
// Le site est servi par `php -S` : son routeur lit le bloc vigie du
// .htaccess du dossier demandé et en applique les groupes (UA « contient,
// sans casse », REMOTE_ADDR, %{TIME} à l'heure du scénario), à la place
// d'Apache. Le scénario simule les pannes : 500 dans le bac à sable, 200
// sans la page témoin, horloge décalée, accueil en 500 une fois le bloc
// posé, fichier modifié par un tiers.

/** Vecteurs de la grammaire, générés par vigie/tests/htaccess.rs. */
function htaccess_vectors(): array
{
    return json_decode((string) file_get_contents(__DIR__ . '/../../../tests/fixtures/htaccess/vectors.json'), true, 32, \JSON_THROW_ON_ERROR);
}

function site_router(string $dir, array $scenario): string
{
    file_put_contents("{$dir}/site.json", json_encode($scenario + ['tz' => 'Europe/Paris', 'clock_offset' => 0]));

    return __DIR__ . '/site-router.php';
}

/**
 * Site servi par php -S et son agent configuré (url, tz) ; fn(Config,
 * dossier de l'agent, racine, dossier du serveur, port).
 */
function with_htaccess_site(array $scenario, callable $fn, array $override = []): void
{
    $root = tmp_site();
    file_put_contents("{$root}/.htaccess", SC_BLOCK . "\n" . file_get_contents("{$root}/.htaccess"));
    $server = tmp_dir();
    [$port, $stop] = php_server(site_router($server, $scenario), $root, ['VIGIE_SITE_DIR' => $server]);
    try {
        $path = write_config($root, ['url' => "http://127.0.0.1:{$port}/", 'tz' => 'Europe/Paris'] + $override);
        $fn(load_config($path), \dirname($path), $root, $server, $port);
    } finally {
        $stop();
    }
}

/** Bloc du module PrestaShop, à garder intact. */
const SC_BLOCK = "# BEGIN sc_alwaysdata protection\n<IfModule mod_rewrite.c>\nRewriteEngine on\n</IfModule>\n# END sc_alwaysdata protection";

/** Bloc valide maintenant : un groupe d'UA de 24 h, et une IP si donnée. */
function block_now(array $literals = ['Bytespider'], ?string $ip = null): string
{
    $until = (new \DateTimeImmutable('@' . (time() + 86400)))->setTimezone(new \DateTimeZone('Europe/Paris'))->format('YmdHis');
    $lines = [\Vigie\Agent\HTACCESS_BEGIN, '# essai', \Vigie\Agent\HTACCESS_ENGINE];
    foreach ($literals as $i => $literal) {
        $lines[] = \Vigie\Agent\HTACCESS_UA . '"' . str_replace('.', '\\.', $literal) . '" ' . ($i + 1 === \count($literals) ? '[NC]' : '[NC,OR]');
    }
    $lines[] = \Vigie\Agent\HTACCESS_TIME . $until;
    $lines[] = \Vigie\Agent\HTACCESS_RULE;
    if ($ip !== null) {
        $lines[] = \Vigie\Agent\HTACCESS_IP . '"^' . str_replace('.', '\\.', $ip) . '$"';
        $lines[] = \Vigie\Agent\HTACCESS_TIME . $until;
        $lines[] = \Vigie\Agent\HTACCESS_RULE;
    }
    $lines[] = \Vigie\Agent\HTACCESS_END;

    return implode("\n", $lines) . "\n";
}

/** Exécute une commande htaccess-* comme le ferait un passage ; rend [résultat, état]. */
function run_htaccess(\Vigie\Agent\Config $config, string $dir, string $name, array $params, ?array $state = null): array
{
    $state ??= \Vigie\Agent\empty_state();
    $command = ['id' => '01a1e2f3-0000-7000-8000-0000000000c1', 'seq' => 5, 'name' => $name, 'params' => $params, 'expires_at' => time() + 3600];
    $result = \Vigie\Agent\execute_command($config, $dir, $command, $state);

    return [$result, $state];
}

/** Calcul seul puis application ; rend [résultat, empreinte d'avant, empreinte d'après]. */
function apply_block(\Vigie\Agent\Config $config, string $dir, string $root, string $block): array
{
    $previous = hash_file('sha256', "{$root}/.htaccess");
    [$computed] = run_htaccess($config, $dir, 'htaccess-apply', ['block' => $block, 'previous_sha256' => $previous, 'new_sha256' => null]);
    same('ok', $computed['status'], "calcul : {$computed['detail']}");
    $new = $computed['data']['new_sha256'];
    [$result] = run_htaccess($config, $dir, 'htaccess-apply', ['block' => $block, 'previous_sha256' => $previous, 'new_sha256' => $new]);

    return [$result, $previous, $new];
}

/** Aucun dossier de bac à sable laissé dans la racine. */
function no_sandbox_left(string $root): void
{
    same([], glob("{$root}/vigie-essai-*") ?: [], 'dossiers du bac à sable supprimés');
}

// --- Inventaire ------------------------------------------------------------

/** Fixture d'inventaire (site A WordPress, site B PrestaShop), en lecture seule. */
function inventory_fixture(string $name): string
{
    return __DIR__ . '/fixtures/' . $name;
}

/** Copie d'une fixture d'inventaire, modifiable par le test. */
function tmp_inventory_site(string $name): string
{
    $dir = tmp_dir() . \DIRECTORY_SEPARATOR . 'www';
    copy_tree(inventory_fixture($name), $dir);

    return $dir;
}

/** Configuration d'inventaire chargée comme par l'agent. */
function inventory_config_for(string $root, string $kind, array $inventory = []): \Vigie\Agent\Config
{
    return load_config(write_config($root, [
        'kind' => $kind, 'critical' => [], 'must_contain' => [],
        'inventory' => ['enabled' => true] + $inventory,
    ]));
}

/** Relevé du site ; `$seconds` : budget de temps (négatif : déjà dépassé). */
function inventory_of(string $root, string $kind, array $inventory = [], int $seconds = 20): array
{
    return collect_inventory(inventory_config_for($root, $kind, $inventory), hrtime(true) + $seconds * 1_000_000_000);
}

/** Composants relevés, au format de inventory-expected.json. */
function expected_form(array $components): array
{
    return array_map(static function (array $c): array {
        $out = ['purl' => $c['purl'], 'version' => $c['version'], 'scope' => $c['scope'], 'vigie:scope' => $c['vscope'], 'vigie:path' => $c['path']];
        if (isset($c['parent'])) {
            $out['vigie:parent'] = $c['parent'];
        }
        if (isset($c['config_version'])) {
            $out['vigie:config-version'] = $c['config_version'];
        }

        return $out;
    }, $components);
}

/** purl relevés, indexés par purl sans version. */
function purls_by_base(array $inventory): array
{
    $out = [];
    foreach ($inventory['components'] as $c) {
        $at = strpos($c['purl'], '@');
        $out[$at === false ? $c['purl'] : substr($c['purl'], 0, $at)] = $c['purl'];
    }

    return $out;
}

/** composer.lock fictif de paquets Packagist. */
function composer_lock(array $names, string $version = '1.0.0'): string
{
    $packages = array_map(static fn (string $n): array => ['name' => $n, 'version' => $version, 'type' => 'library', 'notification-url' => 'https://packagist.org/downloads/'], $names);

    return json_encode(['packages' => $packages, 'packages-dev' => []], \JSON_UNESCAPED_SLASHES);
}

/** Clés de tous les objets d'un document, chemin compris (indices de liste remplacés par []). */
function key_paths(mixed $value, string $prefix = ''): array
{
    if (!\is_array($value)) {
        return [];
    }
    $paths = [];
    foreach ($value as $key => $child) {
        $path = array_is_list($value) ? "{$prefix}[]" : "{$prefix}.{$key}";
        if (!array_is_list($value)) {
            $paths[$path] = true;
        }
        $paths += array_fill_keys(key_paths($child, $path), true);
    }
    $paths = array_keys($paths);
    sort($paths);

    return $paths;
}

/** Contenu et mtime de tous les fichiers d'un dossier. */
function snapshot(string $dir): array
{
    $files = [];
    foreach (mtimes($dir) as $path => $mtime) {
        $files[$path] = [$mtime, is_file($path) ? hash_file('sha256', $path) : 'dossier'];
    }

    return $files;
}


/**
 * Apache réel (opt-in : VIGIE_APACHE, chemin du binaire apache2) sur un
 * port libre, fuseau $tz pour %{TIME} ; fn(Config, dossier de l'agent,
 * racine). Configuration autonome : mod_rewrite, AllowOverride All.
 */
function with_apache(string $apache, string $tz, string $agentTz, callable $fn): void
{
    $base = tmp_dir();
    chmod($base, 0755);
    $root = "{$base}/www";
    copy_tree(fixture(), $root);
    $port = free_port();
    $modules = '/usr/lib/apache2/modules';
    $user = \function_exists('posix_geteuid') && posix_geteuid() === 0 ? "User www-data\nGroup www-data\n" : '';
    file_put_contents("{$base}/httpd.conf", implode("\n", [
        "ServerRoot \"{$base}\"",
        "Listen 127.0.0.1:{$port}",
        'ServerName 127.0.0.1',
        "PidFile \"{$base}/httpd.pid\"",
        "ErrorLog \"{$base}/error.log\"",
        "LoadModule mpm_prefork_module {$modules}/mod_mpm_prefork.so",
        "LoadModule authz_core_module {$modules}/mod_authz_core.so",
        "LoadModule rewrite_module {$modules}/mod_rewrite.so",
        "LoadModule dir_module {$modules}/mod_dir.so",
        $user . 'DirectoryIndex index.php',
        "DocumentRoot \"{$root}\"",
        "<Directory \"{$root}\">",
        '    AllowOverride All',
        '    Require all granted',
        '</Directory>',
        '',
    ]));
    $run = static fn (string $action): array => run_process([$apache, '-f', "{$base}/httpd.conf", '-k', $action], ['TZ' => $tz, 'PATH' => (string) getenv('PATH')]);
    $started = $run('start');
    same(0, $started['code'], 'apache : ' . $started['stderr'] . @file_get_contents("{$base}/error.log"));
    try {
        $deadline = microtime(true) + 10;
        while (@fsockopen('127.0.0.1', $port) === false && microtime(true) < $deadline) {
            usleep(100_000);
        }
        $path = write_config($root, ['url' => "http://127.0.0.1:{$port}/", 'tz' => $agentTz]);
        $fn(load_config($path), \dirname($path), $root);
    } finally {
        $run('stop');
        $deadline = microtime(true) + 10;
        while (is_file("{$base}/httpd.pid") && microtime(true) < $deadline) {
            usleep(100_000);
        }
    }
}

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
        foreach (['wp-inventory' => 'wordpress', 'ps16-inventory' => 'prestashop', 'ps8-inventory' => 'prestashop', 'ps-hostile' => 'prestashop'] as $name => $kind) {
            $before = snapshot(inventory_fixture($name));
            inventory_of(inventory_fixture($name), $kind, ['composer' => ['app/composer.lock']]);
            same($before, snapshot(inventory_fixture($name)), "fichiers et mtime de {$name}");
        }
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

    'inventaire : chaque fixture donne exactement inventory-expected.json' => function (): void {
        $expected = json_decode((string) file_get_contents(inventory_fixture('inventory-expected.json')), true, 32, \JSON_THROW_ON_ERROR);
        foreach ($expected as $name => $e) {
            $inventory = inventory_of(inventory_fixture($name), $e['kind'], $e['inventory'] ?? []);
            same($e['components'], expected_form($inventory['components']), "composants de {$name}");
            same([$e['complete'], $e['skipped']], [$inventory['complete'], $inventory['skipped']], "complete et skipped de {$name}");
        }
    },

    'inventaire : purl.json de F1 rejoué à l\'identique' => function (): void {
        $vectors = json_decode((string) file_get_contents(__DIR__ . '/../../../tests/fixtures/vulns/purl.json'), true, 8, \JSON_THROW_ON_ERROR);
        check(\count($vectors) > 50, 'vecteurs lus');
        foreach ($vectors as $v) {
            same($v['out'], \Vigie\Agent\purl_canonical($v['in']), $v['why']);
        }
        // Le constructeur et l'analyse donnent la même forme.
        same('pkg:npm/%40Scope/Nom@1.0.0%2Bb', \Vigie\Agent\purl('npm', '@Scope', 'Nom', '1.0.0+b'), 'npm à scope');
        same('pkg:composer/exemple/outil', \Vigie\Agent\purl('composer', 'Exemple', 'Outil', ''), 'Composer en minuscules, sans version');
        same(null, \Vigie\Agent\purl('prestashop', 'module', 'exemple.module', '1.0'), 'module à point');
    },

    'inventaire : npm-alias.json, vecteur commun avec l\'outil d\'inventaire, rejoué' => function (): void {
        $vectors = json_decode((string) file_get_contents(__DIR__ . '/../../../tests/fixtures/inventory/npm-alias.json'), true, 16, \JSON_THROW_ON_ERROR);
        foreach ($vectors as $v) {
            same(['entry', 'key', 'out', 'why'], \Vigie\Agent\sorted_keys($v), 'champs du vecteur');
            [$verdict, $purl] = \Vigie\Agent\npm_entry($v['key'], $v['entry']);
            same($v['out'], $verdict === 'component' ? $purl : null, $v['why']);
        }
    },

    'inventaire : document limité à la liste blanche, CycloneDX 1.7, UUID v4, digest stable' => function (): void {
        $config = inventory_config_for(inventory_fixture('ps8-inventory'), 'prestashop');
        $inventory = collect_inventory($config, hrtime(true) + 20_000_000_000);
        $body = \Vigie\Agent\build_inventory_body($config, $inventory, 7, 1_792_152_000, \Vigie\Agent\uuid_v4(random_bytes(16)));
        $doc = json_decode($body, true, 32, \JSON_THROW_ON_ERROR);
        same([
            '.agent', '.bom', '.bom.bomFormat', '.bom.components', '.bom.components[].name', '.bom.components[].properties',
            '.bom.components[].properties[].name', '.bom.components[].properties[].value', '.bom.components[].purl',
            '.bom.components[].scope', '.bom.components[].type', '.bom.components[].version', '.bom.metadata',
            '.bom.metadata.component', '.bom.metadata.component.name', '.bom.metadata.component.type', '.bom.metadata.timestamp',
            '.bom.serialNumber', '.bom.specVersion', '.complete', '.sent_at', '.seq', '.site', '.skipped', '.type', '.v',
        ], key_paths($doc), 'clés de la liste blanche, et elles seules');
        same('1.7', $doc['bom']['specVersion'], 'specVersion');
        check(preg_match('/^urn:uuid:[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/', $doc['bom']['serialNumber']) === 1, 'UUID v4');
        same('2026-10-16T12:00:00Z', $doc['bom']['metadata']['timestamp'], 'timestamp');
        same(['type' => 'application', 'name' => 'site-a'], $doc['bom']['metadata']['component'], 'composant racine');
        $names = [];
        foreach ($doc['bom']['components'] as $c) {
            foreach ($c['properties'] as $p) {
                $names[$p['name']] = true;
            }
        }
        same(['vigie:config-version', 'vigie:path', 'vigie:scope'], array_keys($names) === [] ? [] : (static function (array $n): array {
            sort($n);

            return $n;
        })(array_keys($names)), 'propriétés vigie:*');
        same(\Vigie\Agent\inventory_digest($inventory['components']), \Vigie\Agent\inventory_digest(collect_inventory($config, hrtime(true) + 20_000_000_000)['components']), 'deux relevés, même digest');
        same(\Vigie\Agent\inventory_digest($inventory['components']), \Vigie\Agent\inventory_digest(array_reverse($inventory['components'])), 'digest indépendant de l\'ordre');
    },

    'inventaire : en-têtes bornés, versions piégées, longues ou à ~ vides, rien de tronqué' => function (): void {
        $root = tmp_inventory_site('wp-inventory');
        $plugins = "{$root}/wp-content/plugins";
        // En-tête précédé de <?php sur sa ligne, fins de ligne \r\n.
        file_put_contents("{$plugins}/exemple-cache/chargeur.php", "<?php /* Plugin Name: Exemple cache\r\n Version: 2.1.0\r\n*/\r\n");
        $make = static function (string $slug, string $content) use ($plugins): void {
            mkdir("{$plugins}/{$slug}");
            file_put_contents("{$plugins}/{$slug}/{$slug}.php", $content);
        };
        $make('version-loin', "<?php\n/* Plugin Name: Loin\n" . str_repeat("//\n", 3000) . " * Version: 1.0\n*/\n");
        $make('version-piegee', "<?php\n/*\nPlugin Name: Piège\nVersion: 1.0'; system('id'); \$x='\n*/\n");
        $make('version-tilde', "<?php\n/*\nPlugin Name: Tilde\nVersion: 1.0~beta\n*/\n");
        $make('version-longue', "<?php\n/*\nPlugin Name: Longue\nVersion: " . str_repeat('1', 129) . "\n*/\n");
        $make('version-128', "<?php\n/*\nPlugin Name: Juste\nVersion: " . str_repeat('1', 128) . "\n*/\n");
        $make('ligne-coupee', "<?php\n/*\nPlugin Name: Coupée\n" . str_repeat(' ', 150) . 'Version: 1.0.0' . str_repeat('x', 120) . "\n*/\n");
        // Fichier d'en-tête de 50 Mio : 8 Kio lus.
        mkdir("{$plugins}/geant");
        $big = fopen("{$plugins}/geant/geant.php", 'w');
        fwrite($big, "<?php\n/*\nPlugin Name: Géant\n");
        ftruncate($big, 50 * 1024 * 1024);
        fseek($big, 49 * 1024 * 1024);
        fwrite($big, "Version: 9.9.9\n*/\n");
        fclose($big);
        $start = hrtime(true);
        $inventory = inventory_of($root, 'wordpress');
        check(hrtime(true) - $start < 5_000_000_000, 'relevé borné dans le temps');
        $by = purls_by_base($inventory);
        same('pkg:wordpress/plugin/exemple-cache@2.1.0', $by['pkg:wordpress/plugin/exemple-cache'], 'en-tête <?php et \r\n');
        foreach (['version-loin', 'version-piegee', 'version-tilde', 'version-longue', 'geant', 'ligne-coupee'] as $slug) {
            same("pkg:wordpress/plugin/{$slug}", $by["pkg:wordpress/plugin/{$slug}"] ?? null, "{$slug} : version vide");
        }
        same('pkg:wordpress/plugin/version-128@' . str_repeat('1', 128), $by['pkg:wordpress/plugin/version-128'], 'version de 128 caractères gardée');
        check(!isset($by['pkg:wordpress/plugin/sans-entete']), 'dossier sans Plugin Name ignoré');
        same(true, $inventory['complete'], 'versions vides : relevé complet');
    },

    'inventaire : config.xml hostiles lus comme du texte, jamais développés' => function (): void {
        $root = tmp_inventory_site('ps-hostile');
        foreach (['doctype_mod', 'nul_mod', 'utf_mod', 'mal_forme'] as $module) {
            file_put_contents("{$root}/modules/{$module}/{$module}.php", "<?php\nclass M extends Module { public function __construct() { \$this->version = '1.0.0'; } }\n");
        }
        $inventory = inventory_of($root, 'prestashop');
        foreach ($inventory['components'] as $c) {
            same('1.0.0', $c['version'], "{$c['name']} : version du littéral");
            check(!isset($c['config_version']), "{$c['name']} : config.xml refusé, aucun écart signalé");
        }
        check(!str_contains(json_encode($inventory), '9.9.'), 'aucune entité développée');
    },

    'inventaire : liens symboliques refusés et comptés, même vers l\'intérieur' => function (): void {
        skip_unless(\DIRECTORY_SEPARATOR === '/', 'liens symboliques sous Unix');
        $root = tmp_inventory_site('wp-inventory');
        symlink("{$root}/wp-content/plugins/exemple-formulaire", "{$root}/wp-content/plugins/lien-interieur");
        $inventory = inventory_of($root, 'wordpress');
        check(!isset(purls_by_base($inventory)['pkg:wordpress/plugin/lien-interieur']), 'extension en lien non lue');
        same([false, 1], [$inventory['complete'], $inventory['skipped']], 'extension en lien');

        $root = tmp_inventory_site('wp-inventory');
        $outside = tmp_dir();
        file_put_contents("{$outside}/composer.lock", composer_lock(['exemple/dehors']));
        unlink("{$root}/composer.lock");
        symlink("{$outside}/composer.lock", "{$root}/composer.lock");
        rename("{$root}/wp-content/themes/exemple-theme-enfant", "{$outside}/enfant");
        symlink("{$outside}/enfant", "{$root}/wp-content/themes/exemple-theme-enfant");
        $inventory = inventory_of($root, 'wordpress');
        $by = purls_by_base($inventory);
        check(!isset($by['pkg:composer/exemple/dehors']) && !isset($by['pkg:wordpress/theme/exemple-theme-enfant']), 'cibles hors racine non lues');
        same([false, 2], [$inventory['complete'], $inventory['skipped']], 'lockfile et thème en lien');

        $root = tmp_inventory_site('ps8-inventory');
        rename("{$root}/modules", "{$root}/vrais-modules");
        symlink("{$root}/vrais-modules", "{$root}/modules");
        $inventory = inventory_of($root, 'prestashop');
        same([false, 1], [$inventory['complete'], $inventory['skipped']], 'dossier modules en lien');
    },

    'inventaire : noms hors grammaire écartés et comptés, jamais tronqués, sans regex lente' => function (): void {
        $root = tmp_inventory_site('ps8-inventory');
        mkdir("{$root}/modules/exemple.module");
        file_put_contents("{$root}/modules/exemple.module/exemple.module.php", "<?php\n");
        $long = str_repeat('m', 65);
        mkdir("{$root}/modules/{$long}");
        file_put_contents("{$root}/modules/{$long}/{$long}.php", "<?php\n");
        $pathological = 'a' . str_repeat('-a', 50) . '!';
        file_put_contents("{$root}/composer.lock", composer_lock([
            'exemple/' . str_repeat('b', 207),   // 215 octets
            'exemple/' . str_repeat('b', 206),   // 214 octets : gardé
            "exemple/{$pathological}",
            'pas-de-vendor',
        ]));
        $start = hrtime(true);
        $inventory = inventory_of($root, 'prestashop');
        check(hrtime(true) - $start < 2_000_000_000, 'relevé rapide');
        $by = purls_by_base($inventory);
        same([false, 5], [$inventory['complete'], $inventory['skipped']], 'module à point, module de 65, nom de 215, motif, sans vendor');
        same('pkg:composer/exemple/' . str_repeat('b', 206) . '@1.0.0', $by['pkg:composer/exemple/' . str_repeat('b', 206)] ?? null, 'nom de 214 octets gardé');
        foreach (array_keys($by) as $base) {
            check(!str_contains($base, str_repeat('b', 207)), 'nom de 215 octets jamais tronqué');
        }
        $start = hrtime(true);
        same(false, \Vigie\Agent\composer_part($pathological, false), 'motif pathologique');
        same(false, \Vigie\Agent\composer_part(str_repeat('a-', 100) . '!', false), 'motif pathologique long');
        check(hrtime(true) - $start < 50_000_000, 'rejet en moins de 50 ms');
        same(\PREG_NO_ERROR, preg_last_error(), 'aucune erreur PCRE ignorée');
    },

    'inventaire : lockfiles trop gros, illisibles, v1 ou hors registre : rien, relevé partiel' => function (): void {
        $root = tmp_inventory_site('ps8-inventory');
        file_put_contents("{$root}/composer.lock", '{"packages": [' . str_repeat(' ', 4 * 1024 * 1024) . ']}');
        $inventory = inventory_of($root, 'prestashop');
        same([false, 1], [$inventory['complete'], $inventory['skipped']], 'composer.lock de 4 Mio + 1');
        file_put_contents("{$root}/composer.lock", '{"packages": [');
        same([false, 1], array_values(array_intersect_key(inventory_of($root, 'prestashop'), ['complete' => 0, 'skipped' => 0])), 'JSON invalide');
        file_put_contents("{$root}/composer.lock", str_repeat('[', 40) . str_repeat(']', 40));
        same(1, inventory_of($root, 'prestashop')['skipped'], 'profondeur au-delà de 32');
        file_put_contents("{$root}/composer.lock", composer_lock([]));
        file_put_contents("{$root}/package-lock.json", json_encode(['lockfileVersion' => 1, 'dependencies' => ['a' => ['version' => '1.0.0']]]));
        $inventory = inventory_of($root, 'prestashop');
        same([false, 1], [$inventory['complete'], $inventory['skipped']], 'package-lock.json v1');
        // Hors registre : paquets path et vcs sans notification-url, npm git,
        // file: et archive hors registre ; membres du projet ni émis ni comptés.
        file_put_contents("{$root}/composer.lock", json_encode(['packages' => [
            ['name' => 'exemple/chemin', 'version' => 'dev-main', 'dist' => ['type' => 'path', 'url' => '../chemin']],
            ['name' => 'exemple/prive', 'version' => '1.0.0', 'source' => ['type' => 'git', 'url' => 'https://git.example.org/exemple/prive.git'], 'dist' => ['type' => 'zip', 'url' => 'https://git.example.org/archive.zip']],
            ['name' => 'exemple/public', 'version' => '1.0.0', 'notification-url' => 'https://packagist.org/downloads/'],
        ]]));
        file_put_contents("{$root}/package-lock.json", json_encode(['lockfileVersion' => 3, 'packages' => [
            '' => ['name' => 'app'],
            'node_modules/depuis-git' => ['version' => '1.0.0', 'resolved' => 'git+ssh://git@git.example.org/exemple/a.git#abc'],
            'node_modules/local' => ['version' => '1.0.0', 'resolved' => 'file:../local'],
            'node_modules/archive' => ['version' => '1.0.0', 'resolved' => 'https://example.org/archive.tgz'],
            'node_modules/lien' => ['resolved' => 'packages/lien', 'link' => true],
            'packages/lien' => ['name' => 'lien', 'version' => '0.0.1'],
            'node_modules/registre' => ['version' => '2.0.0', 'resolved' => 'https://registry.npmjs.org/registre/-/registre-2.0.0.tgz'],
        ]]));
        $inventory = inventory_of($root, 'prestashop');
        $by = purls_by_base($inventory);
        same([false, 5], [$inventory['complete'], $inventory['skipped']], 'deux Composer et trois npm hors registre');
        check(isset($by['pkg:composer/exemple/public'], $by['pkg:npm/registre']), 'paquets de registre gardés');
        check(!isset($by['pkg:npm/lien']), 'membre du projet ignoré');
    },

    'inventaire : WPackagist au format de Composer (svn, zip, sans notification-url) : paquet de registre' => function (): void {
        $root = tmp_inventory_site('wp-inventory');
        $lock = json_decode((string) file_get_contents("{$root}/composer.lock"), true);
        $entry = $lock['packages'][1];
        same('wpackagist-plugin/exemple-bedrock', $entry['name'], 'entrée WPackagist de la fixture');
        same([false, 'svn', 'zip'], [\array_key_exists('notification-url', $entry), $entry['source']['type'], $entry['dist']['type']], 'forme écrite par Composer');
        rename("{$root}/wp-content/plugins/exemple-bedrock", "{$root}/ailleurs");
        $inventory = inventory_of($root, 'wordpress');
        same('pkg:wordpress/plugin/exemple-bedrock@1.9.0', purls_by_base($inventory)['pkg:wordpress/plugin/exemple-bedrock'] ?? null, 'version du lockfile sans le disque');
        same([true, 0], [$inventory['complete'], $inventory['skipped']], 'rien de compté');
        // Sur un site generic : reste un paquet Composer.
        $by = purls_by_base(inventory_of($root, 'generic'));
        same('pkg:composer/wpackagist-plugin/exemple-bedrock@1.9.0', $by['pkg:composer/wpackagist-plugin/exemple-bedrock'] ?? null, 'generic : pkg:composer');
    },

    'inventaire : kind generic : Composer et npm seulement, prestashop-module en pkg:composer' => function (): void {
        $inventory = inventory_of(inventory_fixture('ps8-inventory'), 'generic');
        $purls = array_column($inventory['components'], 'purl');
        same([
            'pkg:composer/prestashop/decimal@1.5.0',
            'pkg:composer/prestashop/exemple-natif@1.0.0',
            'pkg:composer/prestashop/absent@4.0.0',
        ], $purls, 'aucun relevé de CMS');
        $inventory = inventory_of(inventory_fixture('wp-inventory'), 'generic');
        foreach ($inventory['components'] as $c) {
            check(str_starts_with($c['purl'], 'pkg:composer/') || str_starts_with($c['purl'], 'pkg:npm/'), $c['purl']);
        }
    },

    'inventaire : 501 entrées, 2 001 composants, corps au-delà de 512 Kio, délai dépassé' => function (): void {
        $root = tmp_inventory_site('wp-inventory');
        for ($i = 0; $i < 501; ++$i) {
            touch(sprintf('%s/wp-content/mu-plugins/f%03d.txt', $root, $i));
        }
        $inventory = inventory_of($root, 'wordpress');
        same(false, $inventory['complete'], '501 entrées : arrêt à 500');

        $root = tmp_inventory_site('ps16-inventory');
        $names = [];
        for ($i = 0; $i < 2001; ++$i) {
            $names[] = sprintf('exemple/paquet-%04d-%s', $i, str_repeat('x', 180));
        }
        file_put_contents("{$root}/composer.lock", composer_lock($names));
        $config = inventory_config_for($root, 'prestashop');
        $inventory = collect_inventory($config, hrtime(true) + 20_000_000_000);
        same(2000, \count($inventory['components']), '2 000 gardés');
        same([false, 5], [$inventory['complete'], $inventory['skipped']], 'noyau et modules d\'abord, puis 1 996 paquets : 5 comptés');
        $body = \Vigie\Agent\build_inventory_body($config, $inventory, 1, 1_792_152_000, \Vigie\Agent\uuid_v4(str_repeat("\0", 16)));
        check(\strlen($body) <= 524_288, 'corps de ' . \strlen($body) . ' octets');
        $doc = json_decode($body, true, 32, \JSON_THROW_ON_ERROR);
        $kept = \count($doc['bom']['components']);
        check($kept < 2000 && $kept > 500, "composants retirés depuis la fin ({$kept} gardés)");
        same(false, $doc['complete'], 'corps tronqué : partiel');
        same(5 + 2000 - $kept, $doc['skipped'], 'retirés comptés');
        same(array_slice(array_column($inventory['components'], 'purl'), 0, $kept), array_column($doc['bom']['components'], 'purl'), 'ordre du relevé gardé');

        $inventory = inventory_of(inventory_fixture('wp-inventory'), 'wordpress', [], -1);
        same(false, $inventory['complete'], 'délai dépassé');
    },

    'inventaire : configuration refusée, section absente ou désactivée sans relevé' => function (): void {
        $refused = static fn (mixed $inventory, string $expected) => refused_config(['inventory' => $inventory], $expected);
        $refused(['enabled' => true, 'autre' => 1], 'inventory');
        $refused([], 'inventory');
        $refused(['enabled' => 'oui'], 'inventory.enabled');
        $refused(['composer' => []], 'inventory.enabled');
        $refused(['enabled' => true, 'composer' => ['../composer.lock']], 'inventory.composer');
        $refused(['enabled' => true, 'npm' => ['a b/package-lock.json']], 'inventory.npm');
        $refused(['enabled' => true, 'npm' => array_map(static fn (int $i): string => "p{$i}/package-lock.json", range(1, 11))], 'inventory.npm');
        $refused(['enabled' => true, 'composer' => ['a/composer.lock', 'a/composer.lock']], 'inventory.composer');
        refused_config(['inventory' => ['enabled' => true], 'endpoint' => 'https://vigie.invalid/autre'], 'inventory');
        $cli = agent('--dry-run', '--config', write_config(fixture(), ['inventory' => ['enabled' => 1]]));
        same(2, $cli['code'], 'code de retour en CLI');
        check(str_contains($cli['stderr'], 'inventory'), $cli['stderr']);
        same(null, load_config(write_config(fixture()))->inventory, 'section absente : désactivé');
        same(null, load_config(write_config(fixture(), ['inventory' => ['enabled' => false]]))->inventory, 'désactivé');
        $config = load_config(write_config(fixture(), ['inventory' => ['enabled' => true]]));
        same('https://vigie.invalid/r/v1/inventory', $config->inventoryEndpoint, 'point d\'entrée dérivé');
        same('prestashop', load_config(write_config(fixture(), ['kind' => 'prestashop']))->kind, 'kind prestashop');
        same(null, load_config(write_config(fixture(), ['kind' => 'prestashop']))->uploads, 'pas de uploads par défaut');
    },

    'inventaire : ni include, ni eval, ni analyseur XML dans l\'agent' => function (): void {
        $source = (string) file_get_contents(\dirname(__DIR__) . '/vigie-agent.php');
        foreach (['/\b(?:include|require)(?:_once)?\s*\(?\s*\$/', '/\beval\s*\(/', '/simplexml|DOMDocument|XMLReader|LIBXML_|token_get_all|highlight_file|shell_exec|passthru|proc_open|\bexec\s*\(|\bsystem\s*\(/i'] as $pattern) {
            same(0, preg_match($pattern, $source, $m), "motif {$pattern} : " . ($m[0] ?? ''));
        }
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

    'logs : seules les lignes des hôtes du site partent, état 0600 dans le dossier de l\'agent' => function (): void {
        with_logs_server(static function (int $port, string $server, string $logs): void {
            [$config, $dir, $public] = logs_agent($port, $logs);
            same('http://127.0.0.1:' . $port . '/r/v1/logs', $config->logsEndpoint, 'point d\'entrée des lots');
            $content = log_line('site-a.example.org', LOG_NOW - 60, '/1')
                . log_line('site-b.example.org', LOG_NOW - 59, '/autre')
                . log_line('site-a.example.org:443', LOG_NOW - 58, '/2?token=x')
                . log_line('-', LOG_NOW - 57, '/sans-hote')
                . log_line('SITE-A.example.org', LOG_NOW - 56, '/3')
                . "[Fri Oct 16 11:59:00 2026] [error] ligne du journal d'erreurs\n";
            $path = write_log($logs, '2026-10-16', $content);
            $before = mtimes($logs);
            same(null, logs_pass_at($config, $dir, LOG_NOW), 'passage');
            $batches = batches_of($server);
            same(1, \count($batches), 'un lot');
            $batch = $batches[0];
            same(['v', 'type', 'site', 'seq', 'sent_at', 'agent', 'file', 'gen', 'start', 'end', 'skipped_files', 'chunk', 'raw', 'signature'], array_keys($batch), 'champs');
            same('logs', $batch['type'], 'type');
            same('http-2026-10-16.log', $batch['file'], 'fichier');
            same(0, $batch['start'], 'début');
            same(filesize($path), $batch['end'], 'fin');
            same(0, $batch['skipped_files'], 'aucun fichier sauté');
            same(log_line('site-a.example.org', LOG_NOW - 60, '/1') . log_line('site-a.example.org:443', LOG_NOW - 58, '/2?token=x')
                . log_line('SITE-A.example.org', LOG_NOW - 56, '/3'), $batch['chunk'], 'lignes gardées');
            check(sodium_crypto_sign_verify_detached(base64_decode($batch['signature']), \Vigie\Agent\DOMAIN_LOGS . $batch['raw'], $public), 'signature sur vigie-logs-v1');
            check(!sodium_crypto_sign_verify_detached(base64_decode($batch['signature']), $batch['raw'], $public), 'jamais une signature de rapport');
            // État : dans le dossier de l'agent seulement, illisible par d'autres.
            same($before, mtimes($logs), 'dossier des logs intact');
            if (\DIRECTORY_SEPARATOR === '/') {
                same(0600, fileperms("{$dir}/logs.json") & 0777, 'logs.json en 0600');
            }
            $names = scandir($dir);
            sort($names);
            same(['.', '..', 'config.json', 'logs.json', 'logs.lock', 'secret.key'], $names, 'fichiers du dossier de l\'agent');
            $state = json_decode((string) file_get_contents("{$dir}/logs.json"), true);
            same(null, $state['pending'], 'aucun lot en attente');
            same(filesize($path), $state['offset'], 'position');
            // Rien de neuf : aucun lot.
            same(null, logs_pass_at($config, $dir, LOG_NOW + 60), 'second passage');
            same(1, \count(batches_of($server)), 'toujours un lot');
        });
    },

    'logs : une ligne de 100 Kio part coupée à 16 Kio' => function (): void {
        with_logs_server(static function (int $port, string $server, string $logs): void {
            [$config, $dir] = logs_agent($port, $logs);
            $long = log_line('site-a.example.org', LOG_NOW - 60, '/long', str_repeat('A', 100 * 1024));
            $after = log_line('site-a.example.org', LOG_NOW - 59, '/apres');
            $path = write_log($logs, '2026-10-16', $long . $after);
            same(null, logs_pass_at($config, $dir, LOG_NOW), 'passage');
            $batch = batches_of($server)[0];
            same(substr($long, 0, 16384) . "\n" . $after, $batch['chunk'], 'ligne coupée, suivante intacte');
            same(filesize($path), $batch['end'], 'la suite jetée est comptée dans la plage');
        });
    },

    'logs : la fin du .gz de la veille part avant le jour, du 31 décembre au 1er janvier, même génération' => function (): void {
        with_logs_server(static function (int $port, string $server, string $logs): void {
            [$config, $dir] = logs_agent($port, $logs);
            $eve = gmmktime(23, 0, 0, 12, 31, 2026);
            $first = log_line('site-a.example.org', $eve, '/a') . log_line('site-a.example.org', $eve + 1, '/b');
            write_log($logs, '2026-12-31', $first);
            same(null, logs_pass_at($config, $dir, $eve + 60), 'passage du 31');
            $late = log_line('site-a.example.org', $eve + 3000, '/c');
            compress_log($logs, '2026-12-31', $late);
            $day = log_line('site-a.example.org', $eve + 4000, '/an');
            write_log($logs, '2027-01-01', $day);
            same(null, logs_pass_at($config, $dir, $eve + 11 * 3600), 'passage du 1er');
            $batches = batches_of($server);
            same(3, \count($batches), 'trois lots');
            same([$first, $late, $day], array_column($batches, 'chunk'), 'aucune ligne en double, dans l\'ordre');
            same(['http-2026-12-31.log', 'http-2026-12-31.log', 'http-2027-01-01.log'], array_column($batches, 'file'), 'fichiers');
            same($batches[0]['gen'], $batches[1]['gen'], 'même génération après la compression');
            same(\strlen($first), $batches[1]['start'], 'reprise à la position');
            same([0, 0], [$batches[2]['gen'], $batches[2]['start']], 'nouveau fichier depuis le début');
        });
    },

    'logs : trou de 3 jours et fichier de la position purgé' => function (): void {
        with_logs_server(static function (int $port, string $server, string $logs): void {
            [$config, $dir] = logs_agent($port, $logs);
            $day = static fn (int $d): int => gmmktime(12, 0, 0, 10, $d, 2026);
            $path = write_log($logs, '2026-10-10', log_line('site-a.example.org', $day(10), '/10'));
            same(null, logs_pass_at($config, $dir, $day(10)), 'passage du 10');
            unlink($path);
            write_log($logs, '2026-10-11', log_line('site-a.example.org', $day(11), '/11'), true);
            write_log($logs, '2026-10-12', log_line('site-a.example.org', $day(12), '/12'), true);
            write_log($logs, '2026-10-13', log_line('site-a.example.org', $day(13), '/13'));
            same(null, logs_pass_at($config, $dir, $day(13)), 'passage du 13');
            $batches = \array_slice(batches_of($server), 1);
            same(['http-2026-10-11.log', 'http-2026-10-12.log', 'http-2026-10-13.log'], array_column($batches, 'file'), 'les trois fichiers dans l\'ordre');
            same([1, 0, 0], array_column($batches, 'skipped_files'), 'fichier purgé compté une fois');
        });
    },

    'logs : un fichier qui grandit garde sa génération, un fichier remplacé prend la suivante' => function (): void {
        with_logs_server(static function (int $port, string $server, string $logs): void {
            [$config, $dir] = logs_agent($port, $logs);
            $one = log_line('site-a.example.org', LOG_NOW - 60, '/1');
            check(\strlen($one) < 256, 'petit fichier');
            $path = write_log($logs, '2026-10-16', $one);
            same(null, logs_pass_at($config, $dir, LOG_NOW), 'premier passage');
            $two = log_line('site-a.example.org', LOG_NOW - 30, '/2');
            file_put_contents($path, $two, \FILE_APPEND);
            same(null, logs_pass_at($config, $dir, LOG_NOW + 60), 'second passage');
            unlink($path);
            $other = log_line('site-a.example.org', LOG_NOW + 70, '/remplace');
            write_log($logs, '2026-10-16', $other . $other . $other);
            same(null, logs_pass_at($config, $dir, LOG_NOW + 120), 'troisième passage');
            [$a, $b, $c] = batches_of($server);
            same($a['gen'], $b['gen'], 'même génération en grandissant');
            same([\strlen($one), $two], [$b['start'], $b['chunk']], 'suite du fichier');
            same($a['gen'] + 1, $c['gen'], 'génération suivante');
            same([0, $other . $other . $other], [$c['start'], $c['chunk']], 'relu depuis le début');
        });
    },

    'logs : 5 Mio d\'un autre hôte font deux lots, le premier vide' => function (): void {
        with_logs_server(static function (int $port, string $server, string $logs): void {
            [$config, $dir] = logs_agent($port, $logs);
            $noise = log_line('site-b.example.org', LOG_NOW - 60, '/bruit');
            $own = log_line('site-a.example.org', LOG_NOW - 30, '/a');
            $path = write_log($logs, '2026-10-16', str_repeat($noise, intdiv(5 * 1024 * 1024, \strlen($noise)) + 1) . $own);
            same(null, logs_pass_at($config, $dir, LOG_NOW), 'passage');
            $batches = batches_of($server);
            same(2, \count($batches), 'deux lots');
            same('', $batches[0]['chunk'], 'premier lot vide');
            check($batches[0]['end'] <= 4 * 1024 * 1024 && $batches[0]['end'] > 4 * 1024 * 1024 - 16384 - \strlen($noise), 'plage de 4 Mio au plus');
            same([$batches[0]['end'], $own, filesize($path)], [$batches[1]['start'], $batches[1]['chunk'], $batches[1]['end']], 'second lot');
            check(\strlen($batches[1]['raw']) <= \Vigie\Agent\MAX_BODY, 'corps sous 64 Kio');
        });
    },

    'logs : 44 Kio gardés au plus par lot, corps sous 64 Kio' => function (): void {
        with_logs_server(static function (int $port, string $server, string $logs): void {
            [$config, $dir] = logs_agent($port, $logs);
            $content = '';
            for ($i = 0; \strlen($content) < 120 * 1024; ++$i) {
                $content .= log_line('site-a.example.org', LOG_NOW - 600 + $i % 500, "/page-{$i}");
            }
            $path = write_log($logs, '2026-10-16', $content);
            same(null, logs_pass_at($config, $dir, LOG_NOW), 'passage');
            $batches = batches_of($server);
            same(3, \count($batches), 'trois lots');
            same($content, implode('', array_column($batches, 'chunk')), 'tout part, une fois');
            foreach ($batches as $i => $batch) {
                check(\strlen($batch['chunk']) <= 44 * 1024, "lot {$i} : 44 Kio au plus");
                check(\strlen($batch['raw']) <= \Vigie\Agent\MAX_BODY, "lot {$i} : corps sous 64 Kio");
                same($i === 0 ? 0 : $batches[$i - 1]['end'], $batch['start'], "lot {$i} : plages contiguës");
            }
            same(filesize($path), $batches[2]['end'], 'fin');
        });
    },

    'logs : un fichier plus récent vu, la veille est close une heure plus tard' => function (): void {
        with_logs_server(static function (int $port, string $server, string $logs): void {
            [$config, $dir] = logs_agent($port, $logs);
            $eve = gmmktime(23, 50, 0, 10, 15, 2026);
            $complete = log_line('site-a.example.org', $eve, '/complete');
            $partial = rtrim(log_line('site-a.example.org', $eve + 1, '/partielle'), "\n");
            write_log($logs, '2026-10-15', $complete . $partial);
            same(null, logs_pass_at($config, $dir, $eve + 300), 'passage de la veille');
            $today = log_line('site-a.example.org', $eve + 700, '/jour');
            write_log($logs, '2026-10-16', $today);
            same(null, logs_pass_at($config, $dir, $eve + 600), 'fichier du jour vu');
            same([$complete], array_column(batches_of($server), 'chunk'), 'ligne incomplète gardée, veille encore ouverte');
            same(null, logs_pass_at($config, $dir, $eve + 600 + 3599), 'avant l\'heure');
            same(1, \count(batches_of($server)), 'toujours ouverte');
            same(null, logs_pass_at($config, $dir, $eve + 600 + 3600), 'une heure plus tard');
            $batches = batches_of($server);
            same([$complete, $partial, $today], array_column($batches, 'chunk'), 'dernière ligne telle quelle, puis le jour');
        });
    },

    'logs : réponse perdue puis fichier qui grandit, la plage en attente repart à l\'identique' => function (): void {
        with_logs_server(static function (int $port, string $server, string $logs): void {
            [$config, $dir] = logs_agent($port, $logs);
            $first = log_line('site-a.example.org', LOG_NOW - 60, '/1') . log_line('site-b.example.org', LOG_NOW - 59, '/b');
            $path = write_log($logs, '2026-10-16', $first);
            touch("{$server}/lose");
            check(logs_pass_at($config, $dir, LOG_NOW) !== null, 'échec signalé');
            $state = json_decode((string) file_get_contents("{$dir}/logs.json"), true);
            same(0, $state['offset'], 'position inchangée');
            same(['file' => 'http-2026-10-16.log', 'gen' => $state['gen'], 'start' => 0, 'end' => \strlen($first)], $state['pending'], 'lot en attente');
            unlink("{$server}/lose");
            $more = log_line('site-a.example.org', LOG_NOW - 10, '/2');
            file_put_contents($path, $more, \FILE_APPEND);
            same(null, logs_pass_at($config, $dir, LOG_NOW + 60), 'passage suivant');
            [$lost, $resent, $next] = batches_of($server);
            foreach (['file', 'gen', 'start', 'end', 'chunk'] as $field) {
                same($lost[$field], $resent[$field], "renvoi identique : {$field}");
            }
            check($resent['seq'] > $lost['seq'], 'seq croissant');
            same([\strlen($first), $more], [$next['start'], $next['chunk']], 'puis la suite');
            same(null, json_decode((string) file_get_contents("{$dir}/logs.json"), true)['pending'], 'plus rien en attente');
        });
    },

    'logs : configuration et état refusés' => function (): void {
        $logs = ['dir' => '/home/compte/admin/logs/http', 'hosts' => ['site-a.example.org']];
        refused_config(['logs' => $logs + ['x' => 1]], 'sans autre clé');
        refused_config(['logs' => ['dir' => 'admin/logs/http'] + $logs], 'logs.dir');
        refused_config(['logs' => ['hosts' => []] + $logs], 'logs.hosts');
        refused_config(['logs' => ['hosts' => ['Site-A.example.org']] + $logs], 'logs.hosts');
        refused_config(['logs' => ['hosts' => ['site-a.example.org:443']] + $logs], 'logs.hosts');
        refused_config(['logs' => ['hosts' => ['a.example.org', 'a.example.org']] + $logs], 'double');
        refused_config(['logs' => ['hosts' => array_map(static fn (int $i): string => "h{$i}.example.org", range(1, 21))] + $logs], 'logs.hosts');
        refused_config(['logs' => $logs, 'endpoint' => 'https://vigie.invalid/autre'], '/r/v1/report');
        same(null, load_config(write_config(fixture()))->logsDir, 'sans logs, rien ne change');
        skip_unless(\DIRECTORY_SEPARATOR === '/', 'droits Unix');
        with_logs_server(static function (int $port, string $server, string $logs): void {
            [$config, $dir] = logs_agent($port, $logs);
            write_log($logs, '2026-10-16', log_line('site-a.example.org', LOG_NOW - 60));
            file_put_contents("{$dir}/logs.json", json_encode(\Vigie\Agent\empty_logs_state() + ['autre' => 1]));
            chmod("{$dir}/logs.json", 0600);
            try {
                logs_pass_at($config, $dir, LOG_NOW);
                throw new Failure('état forgé accepté');
            } catch (UsageError $e) {
                check(str_contains($e->getMessage(), 'illisible'), $e->getMessage());
            }
            unlink("{$dir}/logs.json");
            same(null, logs_pass_at($config, $dir, LOG_NOW), 'état recréé');
            chmod("{$dir}/logs.json", 0644);
            try {
                logs_pass_at($config, $dir, LOG_NOW);
                throw new Failure('état ouvert accepté');
            } catch (UsageError $e) {
                check(str_contains($e->getMessage(), 'chmod 600'), $e->getMessage());
            }
            same([], glob("{$dir}/.state-*") ?: [], 'aucun fichier temporaire laissé');
        });
    },
    'htaccess : chaque vecteur et le fuzz différentiel reçoivent le verdict du validateur Rust' => function (): void {
        $v = htaccess_vectors();
        $tz = new \DateTimeZone($v['tz']);
        $verdict = static fn (string $block): string => \Vigie\Agent\htaccess_validate($block, $v['now'], $tz)[0];
        foreach ($v['vectors'] as $vector) {
            same($vector['verdict'], $verdict($vector['block']), $vector['name']);
        }
        foreach ($v['fuzz'] as $i => $f) {
            $block = $v['bases'][$f['base']];
            $byte = \chr($f['byte']);
            $block = match ($f['op']) {
                'replace' => substr_replace($block, $byte, $f['at'], 1),
                'insert' => substr_replace($block, $byte, $f['at'], 0),
                'delete' => substr_replace($block, '', $f['at'], 1),
            };
            same($f['verdict'], $verdict($block), "fuzz n° {$i} ({$f['op']} {$f['at']})");
        }
        foreach ($v['goldens'] as $name) {
            $golden = (string) file_get_contents(__DIR__ . "/../../../tests/fixtures/htaccess/{$name}");
            same('valid', $verdict($golden), $name);
        }
    },

    'htaccess : corpus d\'UA protégés égal à la fixture' => function (): void {
        $lines = file(__DIR__ . '/../../../tests/fixtures/htaccess/protected-uas.txt', \FILE_IGNORE_NEW_LINES | \FILE_SKIP_EMPTY_LINES);
        same($lines, \Vigie\Agent\PROTECTED_UAS, 'PROTECTED_UAS');
        foreach (\Vigie\Agent\SANDBOX_SAMPLE as $index) {
            check(isset(\Vigie\Agent\PROTECTED_UAS[$index]), "échantillon {$index}");
        }
        same(\Vigie\Agent\PROTECTED_UAS[0], \Vigie\Agent\GOOGLEBOT_UA, 'UA Googlebot');
        check(\in_array(\Vigie\Agent\BROWSER_UA, \Vigie\Agent\PROTECTED_UAS, true), 'UA de navigateur');
    },

    'htaccess : bloc vigie remplacé ou ajouté en tête, bloc sc_alwaysdata intact au-dessus ou au-dessous' => function (): void {
        $block = "# BEGIN vigie\nRewriteEngine On\n# END vigie\n";
        $other = "# BEGIN vigie\n# autre\nRewriteEngine On\n# END vigie\n";
        $wp = "# BEGIN WordPress\nRewriteEngine On\n# END WordPress\n";
        same([$block . SC_BLOCK . "\n" . $wp, null], \Vigie\Agent\htaccess_merge(SC_BLOCK . "\n" . $wp, $block), 'ajouté en tête');
        same([SC_BLOCK . "\n" . $other . $wp, null], \Vigie\Agent\htaccess_merge(SC_BLOCK . "\n" . $block . $wp, $other), 'sous le module');
        same([$other . SC_BLOCK . "\n", null], \Vigie\Agent\htaccess_merge($block . SC_BLOCK . "\n", $other), 'au-dessus du module');
        same([$other, null], \Vigie\Agent\htaccess_merge(rtrim($block, "\n"), $other), 'sans fin de ligne');
        check(\Vigie\Agent\htaccess_merge($block . $block, $other)[0] === null, 'deux paires refusées');
        check(\Vigie\Agent\htaccess_merge("# END vigie\n# BEGIN vigie\n", $other)[0] === null, 'ordre inversé refusé');
        check(\Vigie\Agent\htaccess_merge(str_replace("\n", "\r\n", $block), $other)[0] === null, 'CRLF refusé');
    },

    'htaccess : calcul seul, application, page bloquée, copie privée, puis retour arrière' => function (): void {
        with_htaccess_site([], static function (\Vigie\Agent\Config $config, string $dir, string $root): void {
            $before = (string) file_get_contents("{$root}/.htaccess");
            $snapshot = snapshot($root);
            $block = block_now(['Bytespider', 'archive.org_bot']);
            $previous = hash('sha256', $before);
            [$computed] = run_htaccess($config, $dir, 'htaccess-apply', ['block' => $block, 'previous_sha256' => $previous, 'new_sha256' => null]);
            same('ok', $computed['status'], $computed['detail']);
            same($previous, $computed['data']['current_sha256'], 'empreinte actuelle');
            same(hash('sha256', $block . $before), $computed['data']['new_sha256'], 'empreinte calculée');
            same($snapshot, snapshot($root), 'le calcul seul n\'écrit rien');

            [$result, $state] = run_htaccess($config, $dir, 'htaccess-apply', ['block' => $block, 'previous_sha256' => $previous, 'new_sha256' => $computed['data']['new_sha256']]);
            same('ok', $result['status'], $result['detail']);
            same($block . $before, file_get_contents("{$root}/.htaccess"), 'bloc en tête, reste intact');
            same($computed['data']['new_sha256'], $result['data']['current_sha256'], 'current_sha256');
            same($before, file_get_contents("{$dir}/" . \Vigie\Agent\HTACCESS_PREV), 'copie privée');
            same(0600, fileperms("{$dir}/" . \Vigie\Agent\HTACCESS_PREV) & 0777, 'copie privée en 0600');
            same(null, $state['htaccess_pending'], 'bascule close');
            no_sandbox_left($root);
            same([], glob("{$root}/.htaccess.vigie-*") ?: [], 'aucun fichier temporaire');
            $deadline = hrtime(true) + 10_000_000_000;
            same(403, \Vigie\Agent\http_get($config->siteUrl, 'Mozilla/5.0 (compatible; Bytespider)', $deadline)['status'], 'robot bloqué');
            same(200, \Vigie\Agent\http_get($config->siteUrl, \Vigie\Agent\BROWSER_UA, $deadline)['status'], 'navigateur servi');

            [$rollback] = run_htaccess($config, $dir, 'htaccess-rollback', ['expected_current_sha256' => $result['data']['current_sha256'], 'prev_sha256' => $previous]);
            same('ok', $rollback['status'], $rollback['detail']);
            same($before, file_get_contents("{$root}/.htaccess"), 'contenu d\'avant la dernière application');
            same($previous, $rollback['data']['current_sha256'], 'current_sha256 du retour arrière');
            [$again] = run_htaccess($config, $dir, 'htaccess-rollback', ['expected_current_sha256' => $result['data']['current_sha256'], 'prev_sha256' => $previous]);
            same('refused', $again['status'], 'le .htaccess n\'a plus l\'empreinte attendue');
        });
    },

    'htaccess : bloc refusé, paramètres ou empreinte différente : aucun fichier touché' => function (): void {
        with_htaccess_site([], static function (\Vigie\Agent\Config $config, string $dir, string $root): void {
            $snapshot = snapshot($root);
            $previous = hash_file('sha256', "{$root}/.htaccess");
            $evil = str_replace('RewriteEngine On', "RewriteEngine On\nphp_value auto_prepend_file /tmp/x", block_now());
            foreach ([
                'php_value' => ['block' => $evil, 'previous_sha256' => $previous, 'new_sha256' => null],
                'googlebot' => ['block' => block_now(['Googlebot']), 'previous_sha256' => $previous, 'new_sha256' => null],
                'empreinte' => ['block' => block_now(), 'previous_sha256' => str_repeat('0', 64), 'new_sha256' => null],
                'paramètre en trop' => ['block' => block_now(), 'previous_sha256' => $previous, 'new_sha256' => null, 'shell' => 'id'],
                'new_sha256 faux' => ['block' => block_now(), 'previous_sha256' => $previous, 'new_sha256' => str_repeat('a', 64)],
            ] as $case => $params) {
                [$result] = run_htaccess($config, $dir, 'htaccess-apply', $params);
                same('refused', $result['status'], "{$case} : {$result['detail']}");
            }
            [$result] = run_htaccess($config, $dir, 'htaccess-rollback', ['expected_current_sha256' => $previous, 'prev_sha256' => $previous]);
            same('refused', $result['status'], "rollback sans copie : {$result['detail']}");
            same($snapshot, snapshot($root), 'mtime et contenu identiques');
            same([], glob("{$dir}/htaccess.prev*") ?: [], 'aucune copie privée');
        });
    },

    'htaccess : bac à sable en 500, 200 sans la page témoin, horloge décalée : refus, dossiers supprimés' => function (): void {
        foreach ([
            '500' => [['sandbox_500' => true], 'non représentatif'],
            'sans nonce' => [['no_nonce' => true], 'non représentatif'],
            'horloge' => [['clock_offset' => 3600], 'horloge Apache'],
        ] as $case => [$scenario, $expected]) {
            with_htaccess_site($scenario, static function (\Vigie\Agent\Config $config, string $dir, string $root) use ($case, $expected): void {
                $before = file_get_contents("{$root}/.htaccess");
                [$result] = apply_block($config, $dir, $root, block_now());
                same('refused', $result['status'], "{$case} : statut");
                check(str_contains($result['detail'], $expected), "{$case} : {$result['detail']}");
                same($before, file_get_contents("{$root}/.htaccess"), "{$case} : aucune bascule");
                check(!is_file("{$dir}/" . \Vigie\Agent\HTACCESS_PREV), "{$case} : aucune copie");
                no_sandbox_left($root);
            });
        }
    },

    'htaccess : smoke-test en échec après la bascule : .htaccess remis à l\'identique' => function (): void {
        with_htaccess_site(['home_500_with_vigie' => true], static function (\Vigie\Agent\Config $config, string $dir, string $root): void {
            $before = file_get_contents("{$root}/.htaccess");
            [$result, $previous] = apply_block($config, $dir, $root, block_now());
            same('failed', $result['status'], $result['detail']);
            check(str_contains($result['detail'], 'remis à l\'identique'), $result['detail']);
            same($before, file_get_contents("{$root}/.htaccess"), 'contenu d\'avant');
            same($previous, $result['data']['current_sha256'], 'current_sha256');
        });
    },

    'htaccess : modifié par un tiers pendant le bac à sable ou pendant le smoke-test : rien n\'est écrasé' => function (): void {
        with_htaccess_site(['tamper_in_sandbox' => true], static function (\Vigie\Agent\Config $config, string $dir, string $root): void {
            $before = file_get_contents("{$root}/.htaccess");
            [$result] = apply_block($config, $dir, $root, block_now());
            same('failed', $result['status'], $result['detail']);
            check(str_contains($result['detail'], 'modifié pendant l\'application'), $result['detail']);
            same($before . "# tiers\n", file_get_contents("{$root}/.htaccess"), 'modification du tiers gardée');
            check(!is_file("{$dir}/" . \Vigie\Agent\HTACCESS_PREV), 'aucune copie');
        });
        with_htaccess_site(['home_500_with_vigie' => true, 'tamper_after_swap' => true], static function (\Vigie\Agent\Config $config, string $dir, string $root): void {
            $block = block_now();
            $before = file_get_contents("{$root}/.htaccess");
            [$result] = apply_block($config, $dir, $root, $block);
            same('failed', $result['status'], $result['detail']);
            check(str_contains($result['detail'], 'rien n\'est écrasé'), $result['detail']);
            check(str_starts_with((string) file_get_contents("{$root}/.htaccess"), $block . $before . "# tiers\n"), 'pas de retour arrière qui écrase');
        });
    },

    'htaccess : reprise d\'une bascule interrompue, avant tout retrait' => function (): void {
        with_htaccess_site(['home_500_with_vigie' => true], static function (\Vigie\Agent\Config $config, string $dir, string $root): void {
            $before = (string) file_get_contents("{$root}/.htaccess");
            $new = block_now() . $before;
            $pending = ['command_id' => 'c1', 'kind' => 'apply', 'prev_sha256' => hash('sha256', $before),
                'new_sha256' => hash('sha256', $new), 'statuts_avant' => ['browser' => 200, 'googlebot' => 200]];
            // Bascule non faite : rien n'est écrit.
            $state = ['running' => ['id' => 'c1', 'seq' => 4, 'name' => 'htaccess-apply']] + ['htaccess_pending' => $pending] + \Vigie\Agent\empty_state();
            \Vigie\Agent\resume_htaccess($config, $dir, $state);
            same('failed', $state['result']['status'], 'bascule non faite');
            check(str_contains($state['result']['detail'], 'bascule non faite'), $state['result']['detail']);
            same([null, null, 4], [$state['running'], $state['htaccess_pending'], $state['last_command_seq']], 'état clos');
            same($before, file_get_contents("{$root}/.htaccess"), 'rien écrit');
            // Empreinte tierce : rien n'est écrit.
            file_put_contents("{$root}/.htaccess", $before . "# tiers\n");
            $state = ['htaccess_pending' => $pending] + \Vigie\Agent\empty_state();
            \Vigie\Agent\resume_htaccess($config, $dir, $state);
            check(str_contains($state['result']['detail'], 'modifié pendant l\'application'), $state['result']['detail']);
            same($before . "# tiers\n", file_get_contents("{$root}/.htaccess"), 'rien écrit');
            // Bascule faite, site en 500 : la copie privée revient.
            \Vigie\Agent\write_private_copy($dir, $before);
            \Vigie\Agent\settle_private_copy($dir, true);
            file_put_contents("{$root}/.htaccess", $new);
            $state = ['htaccess_pending' => $pending] + \Vigie\Agent\empty_state();
            \Vigie\Agent\resume_htaccess($config, $dir, $state);
            same('failed', $state['result']['status'], $state['result']['detail']);
            same($before, file_get_contents("{$root}/.htaccess"), 'copie privée remise');
            same(hash('sha256', $before), $state['result']['data']['current_sha256'], 'current_sha256');
        });
    },

    'htaccess : la reprise passe avant le retrait, son résultat part au premier retrait' => function (): void {
        $veilleur = tmp_dir();
        [$commandsPort, $stopVeilleur] = php_server(veilleur_router($veilleur, []), $veilleur);
        try {
            with_htaccess_site(['home_500_with_vigie' => true], static function (\Vigie\Agent\Config $unused, string $dir, string $root, string $server, int $port) use ($commandsPort, $veilleur): void {
                [$config, $agentDir] = commands_agent($commandsPort, ['root' => $root, 'url' => "http://127.0.0.1:{$port}/", 'tz' => 'Europe/Paris']);
                $before = (string) file_get_contents("{$root}/.htaccess");
                $new = block_now() . $before;
                \Vigie\Agent\write_private_copy($agentDir, $before);
                \Vigie\Agent\settle_private_copy($agentDir, true);
                file_put_contents("{$root}/.htaccess", $new);
                $state = \Vigie\Agent\empty_state();
                $state['htaccess_pending'] = ['command_id' => 'c9', 'kind' => 'apply', 'prev_sha256' => hash('sha256', $before),
                    'new_sha256' => hash('sha256', $new), 'statuts_avant' => ['browser' => 200, 'googlebot' => 200]];
                file_put_contents("{$agentDir}/state.json", json_encode($state));
                chmod("{$agentDir}/state.json", 0600);
                $run = agent('--config', $config);
                same(0, $run['code'], $run['stderr']);
                same($before, file_get_contents("{$root}/.htaccess"), 'copie privée remise');
                $pulls = pulls_of($veilleur);
                same('c9', $pulls[0]['result']['command_id'] ?? null, 'résultat au premier retrait');
                same('failed', $pulls[0]['result']['status'], 'échec déclaré');
                same(null, state_of($agentDir)['htaccess_pending'], 'bascule close');
            });
        } finally {
            $stopVeilleur();
        }
    },

    'htaccess : état d\'un agent 0.2.0 ou 0.3.0 chargé et migré' => function (): void {
        $dir = tmp_dir();
        file_put_contents("{$dir}/state.json", json_encode(['pull_seq' => 12, 'last_command_seq' => 3, 'running' => null,
            'result' => ['command_id' => 'x', 'status' => 'ok', 'detail' => 'pong'], 'rotation' => null]));
        chmod("{$dir}/state.json", 0600);
        $state = \Vigie\Agent\load_state($dir);
        same(null, $state['htaccess_pending'], 'htaccess_pending ajouté');
        same(12, $state['pull_seq'], 'séquence gardée');
        \Vigie\Agent\save_state($dir, $state);
        same(array_keys(\Vigie\Agent\empty_state()), array_keys(state_of($dir)), 'réécrit au format 0.4.0');
        file_put_contents("{$dir}/state.json", json_encode(['htaccess_pending' => ['command_id' => 'x']] + \Vigie\Agent\empty_state()));
        try {
            \Vigie\Agent\load_state($dir);
            throw new Failure('htaccess_pending forgé accepté');
        } catch (UsageError $e) {
            check(str_contains($e->getMessage(), 'État illisible'), $e->getMessage());
        }
    },

    'htaccess : configuration url et tz' => function (): void {
        refused_config(['url' => 'http://site-a.example.org/'], 'url');
        refused_config(['url' => 'https://site-a.example.org/?x=1'], 'url');
        refused_config(['tz' => 'Mars/Olympus'], 'tz');
        $config = load_config(write_config(fixture(), ['url' => 'https://site-a.example.org', 'tz' => 'Europe/Paris']));
        same('https://site-a.example.org/', $config->siteUrl, 'url finie par /');
        $dir = tmp_dir();
        $state = \Vigie\Agent\empty_state();
        $bare = load_config(write_config(fixture()));
        $result = \Vigie\Agent\execute_command($bare, $dir, ['id' => 'c', 'seq' => 1, 'name' => 'htaccess-apply',
            'params' => ['block' => '', 'previous_sha256' => null, 'new_sha256' => null], 'expires_at' => time() + 60], $state);
        same('refused', $result['status'], 'sans url ni tz');
    },
    'htaccess : Apache réel, bac à sable, bascule, blocage et horloge (opt-in VIGIE_APACHE)' => function (): void {
        $apache = getenv('VIGIE_APACHE');
        skip_unless(\is_string($apache) && $apache !== '', 'VIGIE_APACHE absent (chemin du binaire apache2)');
        with_apache($apache, 'Europe/Paris', 'Europe/Paris', static function (\Vigie\Agent\Config $config, string $dir, string $root): void {
            $before = (string) file_get_contents("{$root}/.htaccess");
            [$result, $previous] = apply_block($config, $dir, $root, block_now(['Bytespider', 'archive.org_bot']));
            same('ok', $result['status'], $result['detail']);
            no_sandbox_left($root);
            $deadline = hrtime(true) + 10_000_000_000;
            same(403, \Vigie\Agent\http_get($config->siteUrl, 'Mozilla/5.0 (compatible; Bytespider/1.0)', $deadline)['status'], 'robot bloqué par Apache');
            same(403, \Vigie\Agent\http_get($config->siteUrl . 'wp-config.php', 'archive.org_bot', $deadline)['status'], 'littéral avec un point');
            same(200, \Vigie\Agent\http_get($config->siteUrl, \Vigie\Agent\BROWSER_UA, $deadline)['status'], 'navigateur servi');
            same(200, \Vigie\Agent\http_get($config->siteUrl, 'Mozilla/5.0 (compatible; archiveXorg_bot)', $deadline)['status'], 'point échappé : pas de joker');
            [$rollback] = run_htaccess($config, $dir, 'htaccess-rollback', ['expected_current_sha256' => $result['data']['current_sha256'], 'prev_sha256' => $previous]);
            same('ok', $rollback['status'], $rollback['detail']);
            same($before, file_get_contents("{$root}/.htaccess"), 'retour arrière');
        });
        // Apache à l'heure UTC, agent à l'heure de Paris : les sondes le voient.
        with_apache($apache, 'UTC', 'Europe/Paris', static function (\Vigie\Agent\Config $config, string $dir, string $root): void {
            [$result] = apply_block($config, $dir, $root, block_now());
            same('refused', $result['status'], $result['detail']);
            check(str_contains($result['detail'], 'horloge Apache'), $result['detail']);
            no_sandbox_left($root);
        });
    },
];

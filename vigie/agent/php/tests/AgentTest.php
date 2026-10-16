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
];

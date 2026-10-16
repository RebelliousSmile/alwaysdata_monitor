<?php

declare(strict_types=1);

// Exécuteur minimal des tests de l'agent, sans Composer :
//   php vigie/agent/php/tests/run.php [filtre]
// Code 0 si tout passe, 1 sinon. Les tests sont dans AgentTest.php.

namespace Vigie\Agent\Tests;

require_once __DIR__ . '/../vigie-agent.php';
require_once __DIR__ . '/make-interop-fixture.php';

final class Failure extends \RuntimeException
{
}

final class Skipped extends \RuntimeException
{
}

function check(bool $condition, string $message): void
{
    if (!$condition) {
        throw new Failure($message);
    }
}

function same(mixed $expected, mixed $actual, string $message): void
{
    if ($expected !== $actual) {
        throw new Failure($message . "\n      attendu : " . var_export($expected, true) . "\n      obtenu  : " . var_export($actual, true));
    }
}

/** Exécute le test seulement si la condition est remplie. */
function skip_unless(bool $condition, string $reason): void
{
    if (!$condition) {
        throw new Skipped($reason);
    }
}

function fixture(): string
{
    return __DIR__ . '/fixtures/wp-healthy';
}

/** @var list<string> dossiers temporaires à supprimer en fin de test */
$GLOBALS['vigie_tmp'] = [];

function tmp_dir(): string
{
    $dir = sys_get_temp_dir() . \DIRECTORY_SEPARATOR . 'vigie-agent-test-' . bin2hex(random_bytes(6));
    mkdir($dir, 0700);
    $GLOBALS['vigie_tmp'][] = $dir;

    return $dir;
}

/** Copie de la fixture dans un dossier temporaire, modifiable par le test. */
function tmp_site(): string
{
    $dir = tmp_dir() . \DIRECTORY_SEPARATOR . 'www';
    copy_tree(fixture(), $dir);

    return $dir;
}

function copy_tree(string $from, string $to): void
{
    mkdir($to, 0755, true);
    foreach (scandir($from) as $name) {
        if ($name === '.' || $name === '..') {
            continue;
        }
        $source = $from . \DIRECTORY_SEPARATOR . $name;
        is_dir($source) ? copy_tree($source, $to . \DIRECTORY_SEPARATOR . $name) : copy($source, $to . \DIRECTORY_SEPARATOR . $name);
    }
}

function remove_tree(string $path): void
{
    if (is_link($path) || is_file($path)) {
        // Un lien vers un dossier se retire par rmdir sous Windows.
        @unlink($path) || @rmdir($path);

        return;
    }
    if (!is_dir($path)) {
        return;
    }
    foreach (scandir($path) as $name) {
        if ($name !== '.' && $name !== '..') {
            remove_tree($path . \DIRECTORY_SEPARATOR . $name);
        }
    }
    @chmod($path, 0700);
    rmdir($path);
}

/** Configuration du site A sur la racine donnée, écrite dans un dossier temporaire. */
function write_config(string $root, array $override = []): string
{
    $config = array_replace([
        'site' => 'site-a',
        'endpoint' => 'https://vigie.invalid/r/v1/report',
        'root' => $root,
        'kind' => 'wordpress',
        'critical' => ['wp-config.php', '.htaccess', '.user.ini', 'wordfence-waf.php', 'index.php'],
        'must_contain' => [['file' => '.htaccess', 'text' => '# BEGIN site-a installer lock']],
    ], $override);
    $path = tmp_dir() . \DIRECTORY_SEPARATOR . 'config.json';
    file_put_contents($path, json_encode($config, \JSON_UNESCAPED_SLASHES | \JSON_PRETTY_PRINT));

    return $path;
}

/** Arguments à ajouter pour qu'un PHP enfant charge sodium, comme le parent. */
function php_command(): array
{
    static $command = null;
    if ($command === null) {
        $command = [\PHP_BINARY];
        $probe = run_process([\PHP_BINARY, '-r', 'echo extension_loaded("sodium") ? 1 : 0;']);
        if (trim($probe['stdout']) !== '1') {
            $command = [\PHP_BINARY, '-d', 'extension=sodium'];
        }
    }

    return $command;
}

/** @return array{code: int, stdout: string, stderr: string} */
function run_process(array $command, ?array $env = null): array
{
    $process = proc_open($command, [1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes, null, $env);
    if (!\is_resource($process)) {
        throw new Failure('proc_open impossible');
    }
    $stdout = stream_get_contents($pipes[1]);
    $stderr = stream_get_contents($pipes[2]);
    fclose($pipes[1]);
    fclose($pipes[2]);

    return ['code' => proc_close($process), 'stdout' => (string) $stdout, 'stderr' => (string) $stderr];
}

/** Lance l'agent comme la tâche planifiée, dans un processus séparé. */
function agent(string ...$args): array
{
    return run_process([...php_command(), \dirname(__DIR__) . '/vigie-agent.php', ...$args]);
}

/** Port local libre au moment de l'appel. */
function free_port(): int
{
    $server = stream_socket_server('tcp://127.0.0.1:0');
    $name = stream_socket_get_name($server, false);
    fclose($server);

    return (int) substr((string) strrchr((string) $name, ':'), 1);
}

/**
 * Serveur `php -S` local, arrêté par la fonction rendue.
 *
 * @return array{0: int, 1: \Closure} port et fonction d'arrêt
 */
function php_server(string $router, string $docroot): array
{
    $port = free_port();
    $null = \DIRECTORY_SEPARATOR === '\\' ? 'NUL' : '/dev/null';
    $process = proc_open(
        [...php_command(), '-S', "127.0.0.1:{$port}", '-t', $docroot, $router],
        [0 => ['file', $null, 'r'], 1 => ['file', $null, 'w'], 2 => ['file', $null, 'w']],
        $pipes,
    );
    $deadline = microtime(true) + 10;
    while (microtime(true) < $deadline) {
        $socket = @fsockopen('127.0.0.1', $port, $errno, $errstr, 0.2);
        if ($socket !== false) {
            fclose($socket);

            return [$port, static function () use ($process): void {
                proc_terminate($process);
                proc_close($process);
            }];
        }
        usleep(50_000);
    }
    proc_terminate($process);
    throw new Failure("php -S n'a pas démarré sur le port {$port}");
}

function main(array $argv): int
{
    $filter = $argv[1] ?? '';
    $tests = require __DIR__ . '/AgentTest.php';
    $failed = 0;
    $skipped = 0;
    $passed = 0;
    foreach ($tests as $name => $test) {
        if ($filter !== '' && !str_contains($name, $filter)) {
            continue;
        }
        try {
            $test();
            ++$passed;
            echo "ok    {$name}\n";
        } catch (Skipped $e) {
            ++$skipped;
            echo "saut  {$name} : {$e->getMessage()}\n";
        } catch (\Throwable $e) {
            ++$failed;
            $where = $e instanceof Failure ? '' : ' (' . \get_class($e) . ' ' . basename($e->getFile()) . ':' . $e->getLine() . ')';
            echo "ÉCHEC {$name}{$where}\n      {$e->getMessage()}\n";
        } finally {
            foreach ($GLOBALS['vigie_tmp'] as $dir) {
                remove_tree($dir);
            }
            $GLOBALS['vigie_tmp'] = [];
        }
    }
    echo "\n{$passed} réussis, {$failed} échoués, {$skipped} sautés (PHP " . \PHP_VERSION . ")\n";

    return $failed === 0 && $passed > 0 ? 0 : 1;
}

exit(main($_SERVER['argv'] ?? []));

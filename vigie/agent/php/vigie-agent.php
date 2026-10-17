<?php

declare(strict_types=1);

namespace Vigie\Agent;

// Appelé par le web (le fichier n'a rien à faire sous ~/www) : rien n'est lu,
// rien n'est envoyé, aucune sortie.
if (\PHP_SAPI !== 'cli') {
    exit;
}

// Agent Vigie, protocole v1 (vigie/docs/protocole-agent.md, vigie/docs/agent-php.md).
//
//   php vigie-agent.php              contrôles, rapport signé, envoi au veilleur
//                                    (puis commandes et logs, s'ils sont configurés)
//   php vigie-agent.php --dry-run    affiche le rapport sans le signer ni l'envoyer
//   php vigie-agent.php --init       crée la paire de clés, affiche la clé publique
//   --config <fichier>               sinon ~/.vigie-agent/config.json
//
// Lecture seule pour le site : l'agent n'écrit que dans son propre dossier, à
// côté de la configuration (sa clé, à --init ; avec `commands`, l'état du canal
// de commandes et une nouvelle clé en rotation ; avec `logs`, la position de
// lecture des logs). Le `seq` d'un rapport est l'heure en ms.
// Codes de retour : 0 succès, 1 envoi échoué, 2 configuration ou usage,
// 3 extension sodium absente.
// Compatible PHP 8.1 (version du site A) : ni classes readonly, ni constantes
// typées, ni json_validate.

const VERSION = '0.4.0';
const AGENT = 'vigie-agent-php/' . VERSION;
const KEY_FILE = 'secret.key';
const MAX_BODY = 65536;
const SEND_TIMEOUT = 15;
const MAX_CRITICAL = 30;
const MAX_MUST_CONTAIN = 10;
const UPLOADS_MAX_PHP = 500;
const UPLOADS_MAX_SECONDS = 20;
// Constats `uploads-php` envoyés au plus ; le reste est résumé en un constat.
const UPLOADS_MAX_FINDINGS = 50;
const SILENCE_MAX_BYTES = 64;
// Au-delà, l'empreinte d'un fichier PHP de uploads n'est pas calculée.
const HASH_MAX_BYTES = 16 * 1024 * 1024;
const READ_MAX_BYTES = 1024 * 1024;
const PHP_NAME = '/\.(php\d?|phtml|phar|pht)$/i';

final class UsageError extends \RuntimeException
{
}

final class SendError extends \RuntimeException
{
}

final class Config
{
    /**
     * @param list<string> $critical
     * @param list<array{file: string, text: string}> $mustContain
     */
    public function __construct(
        public readonly string $site,
        public readonly string $endpoint,
        public readonly string $root,
        public readonly string $kind,
        public readonly array $critical,
        public readonly array $mustContain,
        public readonly ?string $uploads,
        public readonly ?string $commandsEndpoint = null,
        public readonly ?string $commandsKey = null,
        public readonly ?string $logsDir = null,
        /** @var list<string> */
        public readonly array $logsHosts = [],
        public readonly ?string $logsEndpoint = null,
        /** Adresse publique de la racine du site, finie par « / » (htaccess-*). */
        public readonly ?string $siteUrl = null,
        /** Fuseau IANA du serveur web, celui de %{TIME} (htaccess-*). */
        public readonly ?string $tz = null,
    ) {
    }
}

function main(array $argv): int
{
    try {
        [$mode, $configPath] = parse_args(\array_slice($argv, 1));
    } catch (UsageError $e) {
        fwrite(\STDERR, $e->getMessage() . "\n");

        return 2;
    }
    if (!\extension_loaded('sodium')) {
        fwrite(\STDERR, "Extension sodium absente : l'agent ne peut pas signer.\n");

        return 3;
    }
    try {
        if ($mode === 'init') {
            $public = init_key(\dirname($configPath));
            echo "Clé publique (à enregistrer sur le veilleur) :\n{$public}\n";
            echo "  ~/vigie/bin/vigie site add <site> --pubkey {$public}\n";

            return 0;
        }
        $config = load_config($configPath);
        $now = time();
        $body = build_body($config, collect($config), (int) floor(microtime(true) * 1000), $now);
        if ($mode === 'dry-run') {
            echo json_encode(json_decode($body), \JSON_PRETTY_PRINT | \JSON_UNESCAPED_SLASHES | \JSON_UNESCAPED_UNICODE), "\n";

            return 0;
        }
        $dir = \dirname($configPath);
        $code = 0;
        try {
            send_report($config, $dir, $body);
        } catch (SendError $e) {
            fwrite(\STDERR, 'Envoi échoué : ' . $e->getMessage() . "\n");
            $code = 1;
        }
        if ($config->commandsEndpoint !== null) {
            try {
                pull_commands($config, $dir, $now);
            } catch (SendError|UsageError $e) {
                fwrite(\STDERR, 'Commandes : ' . $e->getMessage() . "\n");
                $code = $e instanceof UsageError ? 2 : 1;
            }
        }
        if ($config->logsDir !== null) {
            try {
                // Heure relue : le rapport et le retrait ont pris du temps.
                send_logs($config, $dir, time());
            } catch (SendError|UsageError $e) {
                fwrite(\STDERR, 'Logs : ' . $e->getMessage() . "\n");
                $code = $e instanceof UsageError ? 2 : 1;
            }
        }

        return $code;
    } catch (UsageError $e) {
        fwrite(\STDERR, $e->getMessage() . "\n");

        return 2;
    } catch (SendError $e) {
        fwrite(\STDERR, 'Envoi échoué : ' . $e->getMessage() . "\n");

        return 1;
    }
}

/** @return array{0: string, 1: string} mode (run, dry-run, init) et chemin de la configuration */
function parse_args(array $args): array
{
    $mode = 'run';
    $config = null;
    for ($i = 0; $i < \count($args); ++$i) {
        $arg = $args[$i];
        if ($arg === '--dry-run' || $arg === '--init') {
            if ($mode !== 'run') {
                throw new UsageError('--dry-run et --init sont exclusifs.');
            }
            $mode = substr($arg, 2);
        } elseif ($arg === '--config' && isset($args[$i + 1])) {
            $config = $args[++$i];
        } else {
            throw new UsageError('Usage : php vigie-agent.php [--dry-run | --init] [--config <fichier>]');
        }
    }
    if ($config === null) {
        $home = getenv('HOME');
        if (!\is_string($home) || $home === '') {
            throw new UsageError('HOME absent : préciser --config.');
        }
        $config = $home . '/.vigie-agent/config.json';
    }

    return [$mode, $config];
}

function load_config(string $path): Config
{
    $raw = @file_get_contents($path, false, null, 0, READ_MAX_BYTES);
    if ($raw === false) {
        throw new UsageError("Configuration illisible : {$path}");
    }
    try {
        $data = json_decode($raw, true, 8, \JSON_THROW_ON_ERROR);
    } catch (\JsonException $e) {
        throw new UsageError("Configuration : JSON invalide ({$e->getMessage()}).");
    }
    if (!\is_array($data) || array_is_list($data) && $data !== []) {
        throw new UsageError('Configuration : un objet JSON est attendu.');
    }
    $known = ['site', 'endpoint', 'root', 'kind', 'critical', 'must_contain', 'uploads', 'commands', 'logs', 'url', 'tz'];
    foreach (array_keys($data) as $key) {
        if (!\in_array($key, $known, true)) {
            throw new UsageError("Configuration : clé inconnue « {$key} ».");
        }
    }
    $site = $data['site'] ?? null;
    if (!\is_string($site) || !preg_match('/^[a-z0-9-]{1,64}$/', $site)) {
        throw new UsageError('Configuration : site attendu, [a-z0-9-], 64 caractères au plus.');
    }
    $endpoint = $data['endpoint'] ?? null;
    if (!\is_string($endpoint) || !valid_endpoint($endpoint)) {
        throw new UsageError('Configuration : endpoint attendu, en https:// (http:// seulement vers 127.0.0.1 ou localhost).');
    }
    $root = $data['root'] ?? null;
    if (!\is_string($root) || !is_absolute($root)) {
        throw new UsageError('Configuration : root attendu, chemin absolu.');
    }
    $kind = $data['kind'] ?? 'generic';
    if (!\in_array($kind, ['wordpress', 'generic'], true)) {
        throw new UsageError('Configuration : kind vaut wordpress ou generic.');
    }
    $critical = $data['critical'] ?? [];
    if (!\is_array($critical) || !array_is_list($critical) || \count($critical) > MAX_CRITICAL) {
        throw new UsageError('Configuration : critical est une liste de ' . MAX_CRITICAL . ' chemins au plus.');
    }
    foreach ($critical as $file) {
        relative_path($file, 'critical');
    }
    if (\count(array_unique($critical)) !== \count($critical)) {
        throw new UsageError('Configuration : chemin en double dans critical.');
    }
    $mustContain = $data['must_contain'] ?? [];
    if (!\is_array($mustContain) || !array_is_list($mustContain) || \count($mustContain) > MAX_MUST_CONTAIN) {
        throw new UsageError('Configuration : must_contain est une liste de ' . MAX_MUST_CONTAIN . ' entrées au plus.');
    }
    foreach ($mustContain as $rule) {
        if (!\is_array($rule) || array_keys($rule) !== ['file', 'text'] && array_keys($rule) !== ['text', 'file']) {
            throw new UsageError('Configuration : chaque must_contain est {"file": …, "text": …}, sans autre clé.');
        }
        relative_path($rule['file'], 'must_contain');
        if (!\is_string($rule['text']) || $rule['text'] === '' || \strlen($rule['text']) > 200) {
            throw new UsageError('Configuration : must_contain.text attendu, 200 octets au plus.');
        }
    }
    $uploads = \array_key_exists('uploads', $data) ? $data['uploads'] : ($kind === 'wordpress' ? 'wp-content/uploads' : null);
    if ($uploads !== null) {
        relative_path($uploads, 'uploads');
    }

    [$commandsEndpoint, $commandsKey] = commands_config($data['commands'] ?? null, $path);
    [$logsDir, $logsHosts, $logsEndpoint] = logs_config($data['logs'] ?? null, $endpoint);
    $siteUrl = $data['url'] ?? null;
    if ($siteUrl !== null) {
        if (!\is_string($siteUrl) || !valid_endpoint($siteUrl) || parse_url($siteUrl, \PHP_URL_QUERY) !== null || parse_url($siteUrl, \PHP_URL_FRAGMENT) !== null) {
            throw new UsageError('Configuration : url attendue, adresse https:// de la racine du site, sans requête.');
        }
        $siteUrl = rtrim($siteUrl, '/') . '/';
    }
    $tz = $data['tz'] ?? null;
    if ($tz !== null && (!\is_string($tz) || !\in_array($tz, \DateTimeZone::listIdentifiers(), true))) {
        throw new UsageError('Configuration : tz attendu, fuseau IANA du serveur web (Europe/Paris).');
    }

    return new Config(
        $site, $endpoint, rtrim($root, '/\\'), $kind, $critical, $mustContain, $uploads, $commandsEndpoint, $commandsKey,
        $logsDir, $logsHosts, $logsEndpoint, $siteUrl, $tz,
    );
}

function valid_endpoint(string $url): bool
{
    $parts = parse_url($url);
    if (!\is_array($parts) || !isset($parts['scheme'], $parts['host']) || isset($parts['user']) || isset($parts['pass'])) {
        return false;
    }
    if ($parts['scheme'] === 'https') {
        return true;
    }

    return $parts['scheme'] === 'http' && \in_array($parts['host'], ['127.0.0.1', 'localhost', '[::1]'], true);
}

function is_absolute(string $path): bool
{
    return str_starts_with($path, '/') || preg_match('#^[A-Za-z]:[\\\\/]#', $path) === 1;
}

/** Chemin relatif à la racine, séparé par « / », sans « . », « .. » ni segment vide. */
function relative_path(mixed $path, string $field): string
{
    if (!\is_string($path) || $path === '' || \strlen($path) > 200 || preg_match('/[\x00-\x1F\x7F\\\\]/', $path)) {
        throw new UsageError("Configuration : {$field} contient un chemin invalide.");
    }
    foreach (explode('/', $path) as $segment) {
        if ($segment === '' || $segment === '.' || $segment === '..' || str_contains($segment, ':')) {
            throw new UsageError("Configuration : {$field} contient un chemin hors de la racine ou mal formé.");
        }
    }

    return $path;
}

// --- Clé ---------------------------------------------------------------

function init_key(string $dir): string
{
    if (!is_dir($dir)) {
        if (!@mkdir($dir, 0700, true)) {
            throw new UsageError("Impossible de créer {$dir}.");
        }
        @chmod($dir, 0700);
    }
    $path = $dir . '/' . KEY_FILE;
    if (file_exists($path) || is_link($path)) {
        throw new UsageError("Une clé existe déjà ({$path}) : elle n'est pas écrasée. La supprimer à la main pour en créer une autre, puis `vigie site rotate-key`.");
    }
    $old = umask(0077);
    // « x » : création exclusive, refusée si le fichier apparaît entre-temps.
    $handle = @fopen($path, 'x');
    umask($old);
    if ($handle === false) {
        throw new UsageError("Impossible de créer la clé {$path}.");
    }
    $pair = sodium_crypto_sign_keypair();
    $secret = sodium_crypto_sign_secretkey($pair);
    $public = base64_encode(sodium_crypto_sign_publickey($pair));
    $written = fwrite($handle, base64_encode($secret) . "\n");
    fclose($handle);
    sodium_memzero($secret);
    sodium_memzero($pair);
    @chmod($path, 0600);
    if ($written === false) {
        @unlink($path);
        throw new UsageError("Écriture de la clé impossible : {$path}.");
    }

    return $public;
}

function load_secret(string $dir): string
{
    $path = $dir . '/' . KEY_FILE;
    clearstatcache(true, $path);
    if (!is_file($path)) {
        throw new UsageError("Clé absente ({$path}) : lancer d'abord --init.");
    }
    if (\DIRECTORY_SEPARATOR === '/' && (fileperms($path) & 0077) !== 0) {
        throw new UsageError("Clé lisible par d'autres utilisateurs ({$path}) : chmod 600.");
    }
    $secret = base64_decode(trim((string) file_get_contents($path)), true);
    if ($secret === false || \strlen($secret) !== \SODIUM_CRYPTO_SIGN_SECRETKEYBYTES) {
        throw new UsageError("Clé illisible ({$path}).");
    }

    return $secret;
}

function sign(string $body, string $secret): string
{
    return base64_encode(sodium_crypto_sign_detached($body, $secret));
}

// --- Contrôles (lecture seule) ------------------------------------------

/**
 * Inspecte un chemin relatif sans suivre de lien hors de la racine.
 *
 * @return array{state: string, real?: string} state : ok, missing, outside, not-file
 */
function locate(string $rootReal, string $relative): array
{
    $path = $rootReal . \DIRECTORY_SEPARATOR . str_replace('/', \DIRECTORY_SEPARATOR, $relative);
    if (!file_exists($path) && !is_link($path)) {
        return ['state' => 'missing'];
    }
    $real = realpath($path);
    if ($real === false) {
        // Lien cassé : la cible n'existe pas.
        return ['state' => 'missing'];
    }
    if (!inside($rootReal, $real)) {
        return ['state' => 'outside'];
    }
    if (!is_file($real)) {
        return ['state' => 'not-file'];
    }

    return ['state' => 'ok', 'real' => $real];
}

function inside(string $rootReal, string $real): bool
{
    return $real === $rootReal || str_starts_with($real, rtrim($rootReal, '/\\') . \DIRECTORY_SEPARATOR);
}

/**
 * Tous les contrôles : constats, empreintes des fichiers critiques, faits.
 *
 * @return array{findings: list<array{check: string, severity: string, key: string, detail: string}>, files: array<string, ?string>, facts: array<string, scalar|null>, uploads: list<array{path: string, size: ?int, sha256: ?string, link: bool}>}
 */
function collect(Config $config): array
{
    $findings = [];
    $files = [];
    $facts = [
        'agent_version' => VERSION,
        'php_version' => \PHP_VERSION,
        'kind' => $config->kind,
    ];
    $rootReal = realpath($config->root);
    if ($rootReal === false || !is_dir($rootReal)) {
        $findings[] = finding('root', 'critical', 'root', "Racine du site introuvable : {$config->root}");
        foreach ($config->critical as $relative) {
            $files[$relative] = null;
        }

        return ['findings' => $findings, 'files' => $files, 'facts' => $facts, 'uploads' => []];
    }

    foreach ($config->critical as $relative) {
        $found = locate($rootReal, $relative);
        $hash = $found['state'] === 'ok' ? @hash_file('sha256', $found['real']) : false;
        $files[$relative] = $hash === false ? null : $hash;
        $problem = match (true) {
            $found['state'] === 'missing' => 'Fichier critique absent',
            $found['state'] === 'outside' => 'Fichier critique hors de la racine (lien symbolique), non lu',
            $found['state'] === 'not-file' => "Fichier critique qui n'est pas un fichier",
            $hash === false => 'Fichier critique illisible',
            default => null,
        };
        if ($problem !== null) {
            $findings[] = finding('critical-file', 'critical', $relative, "{$problem} : {$relative}");
        }
    }

    foreach ($config->mustContain as $rule) {
        $found = locate($rootReal, $rule['file']);
        $content = $found['state'] === 'ok' ? @file_get_contents($found['real'], false, null, 0, READ_MAX_BYTES) : false;
        if ($content === false) {
            $findings[] = finding('must-contain', 'critical', $rule['file'], "Fichier à contrôler absent ou illisible : {$rule['file']}");
        } elseif (!str_contains($content, $rule['text'])) {
            $findings[] = finding('must-contain', 'critical', $rule['file'], "{$rule['file']} ne contient plus « {$rule['text']} »");
        }
    }

    if ($config->kind === 'wordpress') {
        $facts['wp_version'] = wordpress_version($rootReal);
    }

    $uploads = [];
    if ($config->uploads !== null) {
        $scan = scan_uploads($rootReal, $config->uploads);
        $uploads = $scan['php'];
        $facts['uploads_entries'] = $scan['entries'];
        $facts['uploads_php'] = \count($uploads);
        foreach (\array_slice($uploads, 0, UPLOADS_MAX_FINDINGS) as $file) {
            $what = $file['link'] ? 'lien symbolique, non suivi' : (
                $file['size'] . ' octets, sha256 ' . ($file['sha256'] === null ? 'non calculée' : substr($file['sha256'], 0, 16) . '…')
            );
            $findings[] = finding('uploads-php', 'critical', $file['path'], "Fichier PHP dans uploads : {$file['path']} ({$what})");
        }
        $rest = \count($uploads) - UPLOADS_MAX_FINDINGS;
        if ($rest > 0) {
            $findings[] = finding('uploads-php', 'critical', '_autres', "{$rest} autres fichiers PHP dans uploads, non listés (" . UPLOADS_MAX_FINDINGS . ' constats au plus)');
        }
        if ($scan['problem'] !== null) {
            $findings[] = finding('uploads-php', 'warning', '_parcours', $scan['problem']);
        }
    }

    return ['findings' => $findings, 'files' => $files, 'facts' => $facts, 'uploads' => $uploads];
}

/** Version lue dans wp-includes/version.php, sans jamais l'exécuter. */
function wordpress_version(string $rootReal): ?string
{
    $found = locate($rootReal, 'wp-includes/version.php');
    if ($found['state'] !== 'ok') {
        return null;
    }
    $content = @file_get_contents($found['real'], false, null, 0, 65536);
    if ($content !== false && preg_match('/^\s*\$wp_version\s*=\s*[\'"]([0-9A-Za-z.+-]{1,32})[\'"]\s*;/m', $content, $m)) {
        return $m[1];
    }

    return null;
}

/**
 * Fichiers PHP sous uploads, sans suivre aucun lien symbolique.
 *
 * @return array{php: list<array{path: string, size: ?int, sha256: ?string, link: bool}>, entries: int, problem: ?string}
 */
function scan_uploads(string $rootReal, string $relative): array
{
    $result = ['php' => [], 'entries' => 0, 'problem' => null];
    $start = locate_dir($rootReal, $relative);
    if ($start === null) {
        return $result;
    }
    if ($start === false) {
        $result['problem'] = "Dossier {$relative} hors de la racine (lien symbolique) : non parcouru";

        return $result;
    }
    $deadline = hrtime(true) + UPLOADS_MAX_SECONDS * 1_000_000_000;
    $stack = [[$start, $relative]];
    while ($stack !== [] && $result['problem'] === null) {
        [$dir, $rel] = array_pop($stack);
        $handle = @opendir($dir);
        if ($handle === false) {
            continue;
        }
        while (($name = readdir($handle)) !== false) {
            if ($name === '.' || $name === '..') {
                continue;
            }
            if (hrtime(true) > $deadline) {
                $result['problem'] = 'Parcours de uploads interrompu après ' . UPLOADS_MAX_SECONDS . ' s : liste des fichiers PHP incomplète';
                break;
            }
            ++$result['entries'];
            $path = $dir . \DIRECTORY_SEPARATOR . $name;
            $childRel = $rel . '/' . $name;
            $isPhp = preg_match(PHP_NAME, $name) === 1;
            if (is_link($path)) {
                if ($isPhp) {
                    $result['php'][] = ['path' => $childRel, 'size' => null, 'sha256' => null, 'link' => true];
                }
            } elseif (is_dir($path)) {
                $stack[] = [$path, $childRel];
            } elseif ($isPhp && is_file($path)) {
                $size = @filesize($path);
                $size = $size === false ? null : $size;
                if (strtolower($name) === 'index.php' && $size !== null && is_silence($path, $size)) {
                    continue;
                }
                $hash = $size !== null && $size <= HASH_MAX_BYTES ? @hash_file('sha256', $path) : false;
                $result['php'][] = ['path' => $childRel, 'size' => $size, 'sha256' => $hash === false ? null : $hash, 'link' => false];
            }
            if (\count($result['php']) >= UPLOADS_MAX_PHP) {
                $result['problem'] = 'Parcours de uploads arrêté à ' . UPLOADS_MAX_PHP . ' fichiers PHP : liste incomplète';
                break;
            }
        }
        closedir($handle);
    }

    return $result;
}

/** @return string|false|null dossier réel, false s'il sort de la racine, null s'il n'existe pas */
function locate_dir(string $rootReal, string $relative): string|false|null
{
    $path = $rootReal . \DIRECTORY_SEPARATOR . str_replace('/', \DIRECTORY_SEPARATOR, $relative);
    $real = realpath($path);
    if ($real === false || !is_dir($real)) {
        return null;
    }

    return inside($rootReal, $real) && !is_link($path) ? $real : false;
}

/** `index.php` de silence : moins de 64 octets, rien d'autre que des commentaires. */
function is_silence(string $path, int $size): bool
{
    if ($size >= SILENCE_MAX_BYTES) {
        return false;
    }
    $content = @file_get_contents($path, false, null, 0, SILENCE_MAX_BYTES);
    if ($content === false) {
        return false;
    }
    $code = preg_replace(['#/\*.*?\*/#s', '#(//|\#)[^\n]*#', '#<\?php|\?>#i'], '', $content);

    return \is_string($code) && trim($code) === '';
}

/** @return array{check: string, severity: string, key: string, detail: string} */
function finding(string $check, string $severity, string $key, string $detail): array
{
    return ['check' => $check, 'severity' => $severity, 'key' => printable($key, 200), 'detail' => printable($detail, 300)];
}

/** Sans caractère de contrôle (C0, DEL, C1), UTF-8 valide, `max` caractères au plus. */
function printable(string $value, int $max): string
{
    if (preg_match('//u', $value) !== 1) {
        $value = (string) preg_replace('/[\x80-\xFF]/', '?', $value);
    }
    $value = (string) preg_replace('/[\x{00}-\x{1F}\x{7F}-\x{9F}]/u', '?', $value);
    // Compte en caractères, sans dépendre de mbstring.
    if (preg_match('/^.{' . ($max + 1) . '}/us', $value) === 1) {
        preg_match('/^.{' . ($max - 1) . '}/us', $value, $m);
        $value = $m[0] . '…';
    }

    return $value === '' ? '?' : $value;
}

// --- Rapport ------------------------------------------------------------

/** Corps exact du rapport, tel qu'il sera signé et envoyé. */
function build_body(Config $config, array $collected, int $seq, int $now): string
{
    $body = json_encode([
        'v' => 1,
        'site' => $config->site,
        'seq' => $seq,
        'sent_at' => $now,
        'agent' => AGENT,
        'findings' => $collected['findings'],
        'facts' => (object) $collected['facts'],
        'files' => (object) $collected['files'],
    ], \JSON_UNESCAPED_SLASHES | \JSON_UNESCAPED_UNICODE | \JSON_THROW_ON_ERROR);
    if (\strlen($body) > MAX_BODY) {
        throw new SendError('rapport de ' . \strlen($body) . ' octets, plus que les ' . MAX_BODY . ' acceptés par le veilleur');
    }

    return $body;
}

/**
 * POST du rapport. fopen plutôt que file_get_contents : même enveloppe HTTP et
 * même contexte, mais le statut se lit dans les métadonnées du flux, sans la
 * variable $http_response_header, dépréciée en PHP 8.5.
 */
function send(Config $config, string $body, string $signature): void
{
    $context = stream_context_create([
        'http' => [
            'method' => 'POST',
            'header' => implode("\r\n", [
                'Content-Type: application/json',
                'User-Agent: ' . AGENT,
                'X-Vigie-Site: ' . $config->site,
                'X-Vigie-Signature: ' . $signature,
            ]),
            'content' => $body,
            'timeout' => SEND_TIMEOUT,
            'follow_location' => 0,
            'ignore_errors' => true,
        ],
        'ssl' => [
            'verify_peer' => true,
            'verify_peer_name' => true,
            'allow_self_signed' => false,
        ],
    ]);
    $previous = ini_set('default_socket_timeout', (string) SEND_TIMEOUT);
    $stream = @fopen($config->endpoint, 'r', false, $context);
    if ($previous !== false) {
        ini_set('default_socket_timeout', $previous);
    }
    if ($stream === false) {
        $error = error_get_last();
        throw new SendError('veilleur injoignable (' . ($error['message'] ?? 'raison inconnue') . ')');
    }
    $meta = stream_get_meta_data($stream);
    fclose($stream);
    $status = $meta['wrapper_data'][0] ?? '';
    if (!\is_string($status) || preg_match('#^HTTP/\S+\s+(\d{3})#', $status, $m) !== 1) {
        throw new SendError('réponse illisible');
    }
    if ($m[1] !== '204') {
        throw new SendError("statut {$m[1]} (204 attendu ; un 404 est un refus, raison dans journalctl -u vigie-serve)");
    }
}

// --- Commandes (vigie/docs/protocole-commandes.md) ----------------------
//
// L'agent retire sa commande à chaque passage. Rien ne s'exécute sans une
// réponse signée par la clé de commandes épinglée dans config.json, et rien
// d'autre que la liste fermée ci-dessous. L'état (séquences, commande en
// cours, résultat en attente d'accusé) vit à côté de la clé, sous flock.

const DOMAIN_PULL = "vigie-pull-v1\n";
const DOMAIN_COMMANDS = "vigie-commands-v1\n";
const DOMAIN_ROTATE = "vigie-rotate-v1\n";
const STATE_FILE = 'state.json';
const STATE_LOCK = 'state.lock';
const KEY_FILE_NEW = 'secret.key.new';
const MAX_CLOCK_SKEW = 300;
const MAX_RESPONSE = 65536;
const MAX_DETAIL = 1000;
/** Liste fermée de l'agent : nom → exécutable dans ce fichier. */
const COMMANDS = ['ping', 'rotate-key', 'htaccess-apply', 'htaccess-rollback'];

/** @return array{0: ?string, 1: ?string} endpoint et clé publique épinglée (32 octets) */
function commands_config(mixed $commands, string $configPath): array
{
    if ($commands === null) {
        return [null, null];
    }
    if (!\is_array($commands) || array_is_list($commands) || array_diff(array_keys($commands), ['endpoint', 'pubkey']) !== [] || \count($commands) !== 2) {
        throw new UsageError('Configuration : commands est {"endpoint": …, "pubkey": …}, sans autre clé.');
    }
    if (!\is_string($commands['endpoint']) || !valid_endpoint($commands['endpoint'])) {
        throw new UsageError('Configuration : commands.endpoint attendu, en https:// (http:// seulement vers 127.0.0.1 ou localhost).');
    }
    $key = \is_string($commands['pubkey']) ? base64_decode($commands['pubkey'], true) : false;
    if ($key === false || \strlen($key) !== \SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES) {
        throw new UsageError('Configuration : commands.pubkey attendu, 32 octets en base64.');
    }
    if (\DIRECTORY_SEPARATOR !== '/') {
        throw new UsageError('Configuration : commands exige un système Unix, où les droits de config.json se vérifient.');
    }
    // Une clé épinglée ne vaut que si personne d'autre ne peut la changer.
    private_file($configPath, 'config.json');
    private_dir(\dirname($configPath));

    return [$commands['endpoint'], $key];
}

/** Fichier ordinaire, sans lien, en 0600 au plus (contrôle Unix seulement). */
function private_file(string $path, string $what): void
{
    clearstatcache(true, $path);
    if (is_link($path) || !is_file($path)) {
        throw new UsageError("{$what} : fichier ordinaire attendu, jamais un lien ({$path}).");
    }
    if (\DIRECTORY_SEPARATOR === '/' && (fileperms($path) & 0077) !== 0) {
        throw new UsageError("{$what} lisible ou modifiable par d'autres ({$path}) : chmod 600.");
    }
}

/** Dossier réel (sans lien), en 0700 (contrôle Unix seulement). */
function private_dir(string $dir): void
{
    clearstatcache(true, $dir);
    $real = realpath($dir);
    if ($real === false || is_link($dir) || !is_dir($real)) {
        throw new UsageError("Dossier de l'agent introuvable ou lien symbolique ({$dir}).");
    }
    if (\DIRECTORY_SEPARATOR === '/' && (fileperms($real) & 0077) !== 0) {
        throw new UsageError("Dossier de l'agent ouvert à d'autres ({$real}) : chmod 700.");
    }
    if (\function_exists('posix_geteuid') && fileowner($real) !== posix_geteuid()) {
        throw new UsageError("Dossier de l'agent à un autre utilisateur ({$real}).");
    }
}

/** État par défaut : rien d'envoyé, rien d'exécuté. */
function empty_state(): array
{
    return ['pull_seq' => 0, 'last_command_seq' => 0, 'running' => null, 'result' => null, 'rotation' => null, 'htaccess_pending' => null];
}

/** Clés de l'état des agents 0.2.0 et 0.3.0, avant htaccess_pending. */
const STATE_KEYS_0_3 = ['pull_seq', 'last_command_seq', 'running', 'result', 'rotation'];

function load_state(string $dir): array
{
    $path = $dir . '/' . STATE_FILE;
    clearstatcache(true, $path);
    if (!file_exists($path) && !is_link($path)) {
        return empty_state();
    }
    private_file($path, STATE_FILE);
    $raw = @file_get_contents($path, false, null, 0, READ_MAX_BYTES);
    try {
        $state = \is_string($raw) ? json_decode($raw, true, 8, \JSON_THROW_ON_ERROR) : null;
    } catch (\JsonException) {
        $state = null;
    }
    if (\is_array($state) && array_keys($state) === STATE_KEYS_0_3) {
        // État d'un agent 0.2.0 ou 0.3.0 : migré, réécrit au prochain save_state.
        $state['htaccess_pending'] = null;
    }
    if (!\is_array($state) || array_keys($state) !== array_keys(empty_state())
        || !\is_int($state['pull_seq']) || !\is_int($state['last_command_seq'])
        || ($state['htaccess_pending'] !== null && !valid_htaccess_pending($state['htaccess_pending']))) {
        throw new UsageError("État illisible ({$path}) : le supprimer remet les séquences à zéro.");
    }

    return $state;
}

function save_state(string $dir, array $state): void
{
    save_private_json($dir, STATE_FILE, $state);
}

/** Écriture atomique : fichier temporaire du même dossier, 0600, puis rename. */
function save_private_json(string $dir, string $name, array $data): void
{
    $path = $dir . '/' . $name;
    $tmp = @tempnam($dir, '.state-');
    if ($tmp === false) {
        throw new UsageError("Écriture de l'état impossible dans {$dir}.");
    }
    @chmod($tmp, 0600);
    $json = json_encode($data, \JSON_UNESCAPED_SLASHES | \JSON_UNESCAPED_UNICODE | \JSON_THROW_ON_ERROR);
    if (@file_put_contents($tmp, $json) !== \strlen($json) || !@rename($tmp, $path)) {
        @unlink($tmp);
        throw new UsageError("Écriture de l'état impossible : {$path}.");
    }
}

/** Exécute $fn sous verrou exclusif de l'état ; rend son résultat. */
function with_state(string $dir, callable $fn): mixed
{
    return with_lock($dir, STATE_LOCK, $fn, 'un autre passage de l\'agent tient le verrou : ce passage saute les commandes');
}

/** Exécute $fn sous verrou exclusif non bloquant ; $busy : message si déjà tenu. */
function with_lock(string $dir, string $name, callable $fn, string $busy): mixed
{
    private_dir($dir);
    $lock = $dir . '/' . $name;
    if (is_link($lock)) {
        throw new UsageError("Verrou de l'état : lien symbolique refusé ({$lock}).");
    }
    $old = umask(0077);
    $handle = @fopen($lock, 'c');
    umask($old);
    if ($handle === false) {
        throw new UsageError("Verrou de l'état impossible : {$lock}.");
    }
    if (!flock($handle, \LOCK_EX | \LOCK_NB)) {
        fclose($handle);
        throw new SendError($busy);
    }
    try {
        return $fn();
    } finally {
        flock($handle, \LOCK_UN);
        fclose($handle);
    }
}

function base64url(string $bytes): string
{
    return rtrim(strtr(base64_encode($bytes), '+/', '-_'), '=');
}

/**
 * POST signé ; rend statut, en-têtes en minuscules et corps (64 Ko au plus).
 *
 * @return array{status: int, headers: array<string, string>, body: string}
 */
function post_signed(Config $config, string $url, string $body, string $signature): array
{
    $context = stream_context_create([
        'http' => [
            'method' => 'POST',
            'header' => implode("\r\n", [
                'Content-Type: application/json',
                'User-Agent: ' . AGENT,
                'X-Vigie-Site: ' . $config->site,
                'X-Vigie-Signature: ' . $signature,
            ]),
            'content' => $body,
            'timeout' => SEND_TIMEOUT,
            'follow_location' => 0,
            'ignore_errors' => true,
        ],
        'ssl' => ['verify_peer' => true, 'verify_peer_name' => true, 'allow_self_signed' => false],
    ]);
    $previous = ini_set('default_socket_timeout', (string) SEND_TIMEOUT);
    $stream = @fopen($url, 'r', false, $context);
    if ($previous !== false) {
        ini_set('default_socket_timeout', $previous);
    }
    if ($stream === false) {
        $error = error_get_last();
        throw new SendError('veilleur injoignable (' . ($error['message'] ?? 'raison inconnue') . ')');
    }
    $content = stream_get_contents($stream, MAX_RESPONSE + 1);
    $meta = stream_get_meta_data($stream);
    fclose($stream);
    $lines = $meta['wrapper_data'] ?? [];
    $status = 0;
    $headers = [];
    foreach (\is_array($lines) ? $lines : [] as $line) {
        if (!\is_string($line)) {
            continue;
        }
        if (preg_match('#^HTTP/\S+\s+(\d{3})#', $line, $m) === 1) {
            // Une nouvelle ligne de statut remet les en-têtes à zéro.
            $status = (int) $m[1];
            $headers = [];
        } elseif (str_contains($line, ':')) {
            [$name, $value] = explode(':', $line, 2);
            $headers[strtolower(trim($name))] = trim($value);
        }
    }

    return ['status' => $status, 'headers' => $headers, 'body' => \is_string($content) ? $content : ''];
}

/** Rapport signé, avec repli sur la nouvelle clé d'une rotation non accusée. */
function send_report(Config $config, string $dir, string $body): void
{
    $secret = load_secret($dir);
    try {
        send($config, $body, sign($body, $secret));
    } catch (SendError $e) {
        $new = pending_new_secret($dir);
        if ($new === null) {
            throw $e;
        }
        // Le veilleur a peut-être déjà basculé (accusé perdu) : essayer la
        // nouvelle clé. Un 204 n'est pas signé : il ne fait jamais basculer,
        // seule une réponse signée de /r/v1/commands le peut.
        send($config, $body, sign($body, $new));
        sodium_memzero($new);
    } finally {
        sodium_memzero($secret);
    }
}

function pending_new_secret(string $dir): ?string
{
    $path = $dir . '/' . KEY_FILE_NEW;
    clearstatcache(true, $path);
    if (!is_file($path) || is_link($path)) {
        return null;
    }
    private_file($path, KEY_FILE_NEW);
    $secret = base64_decode(trim((string) file_get_contents($path)), true);

    return $secret !== false && \strlen($secret) === \SODIUM_CRYPTO_SIGN_SECRETKEYBYTES ? $secret : null;
}

/**
 * La nouvelle clé devient la clé, l'ancienne est gardée en secret.key.old.
 * Appelée seulement sous le verrou de l'état, sur une réponse signée.
 */
function promote_new_key(string $dir): void
{
    @copy($dir . '/' . KEY_FILE, $dir . '/' . KEY_FILE . '.old');
    @chmod($dir . '/' . KEY_FILE . '.old', 0600);
    if (!@rename($dir . '/' . KEY_FILE_NEW, $dir . '/' . KEY_FILE)) {
        throw new UsageError("Bascule de la clé impossible dans {$dir}.");
    }
}

/**
 * Vérifie une réponse de /r/v1/commands, dans l'ordre du contrat ; rend le
 * verdict (noms des vecteurs de test) et, si valide, le corps décodé.
 *
 * @return array{0: string, 1: ?array}
 */
function verify_response(int $status, array $headers, string $body, string $commandsKey, string $site, string $nonce, int $now): array
{
    if ($status !== 200) {
        return ['status', null];
    }
    if ($body === '' || \strlen($body) > MAX_RESPONSE) {
        return ['empty', null];
    }
    // Signature sur les octets bruts, avant toute lecture du JSON.
    $ts = $headers['x-vigie-timestamp'] ?? '';
    $sig = base64_decode($headers['x-vigie-signature'] ?? '', true);
    if (preg_match('/^[0-9]{1,19}$/', $ts) !== 1 || $sig === false || \strlen($sig) !== \SODIUM_CRYPTO_SIGN_BYTES) {
        return ['bad-signature', null];
    }
    try {
        $ok = sodium_crypto_sign_verify_detached($sig, DOMAIN_COMMANDS . $ts . "\n" . $body, $commandsKey);
    } catch (\SodiumException) {
        $ok = false;
    }
    if (!$ok) {
        return ['bad-signature', null];
    }
    try {
        // En objets : {} et [] ne se confondent pas.
        $data = json_decode($body, false, 8, \JSON_THROW_ON_ERROR);
    } catch (\JsonException) {
        return ['schema', null];
    }
    $keys = ['accepted', 'acked', 'command', 'nonce', 'server_time', 'site', 'v'];
    if (!$data instanceof \stdClass || !same_keys($data, $keys) || $data->v !== 1 || !\is_int($data->server_time)) {
        return ['schema', null];
    }
    if ($data->server_time !== (int) $ts) {
        return ['timestamp-mismatch', null];
    }
    if (abs($data->server_time - $now) > MAX_CLOCK_SKEW) {
        return ['clock', null];
    }
    $command = $data->command;
    if ($command !== null && !$command instanceof \stdClass) {
        return ['schema', null];
    }
    if ($data->site !== $site || ($command !== null && ($command->site ?? null) !== $site)) {
        return ['site', null];
    }
    if (!\is_string($data->nonce) || !hash_equals($nonce, $data->nonce)) {
        return ['nonce', null];
    }
    if (!($data->acked === null || \is_string($data->acked)) || !($data->accepted === null || \is_bool($data->accepted))) {
        return ['schema', null];
    }
    $out = ['acked' => $data->acked, 'accepted' => $data->accepted, 'command' => null];
    if ($command !== null) {
        $commandKeys = ['expires_at', 'id', 'issued_at', 'name', 'params', 'runtime', 'seq', 'site', 'v'];
        if (!same_keys($command, $commandKeys) || $command->v !== 1 || !\is_string($command->id) || \strlen($command->id) > 64
            || !\is_int($command->seq) || !\is_int($command->expires_at) || !$command->params instanceof \stdClass) {
            return ['schema', null];
        }
        if ($command->expires_at <= $data->server_time) {
            return ['expired', null];
        }
        if ($command->runtime !== 'php' || !\in_array($command->name, COMMANDS, true)) {
            return ['schema', null];
        }
        $out['command'] = [
            'id' => $command->id, 'seq' => $command->seq, 'name' => $command->name,
            'params' => (array) $command->params, 'expires_at' => $command->expires_at,
        ];
    }

    return ['valid', $out];
}

/** Mêmes clés, quel que soit leur ordre. */
function same_keys(\stdClass $object, array $expected): bool
{
    $keys = array_keys(get_object_vars($object));
    sort($keys);

    return $keys === $expected;
}

/** Retrait : résultat en attente renvoyé, commande vérifiée puis exécutée une fois. */
function pull_commands(Config $config, string $dir, int $now): void
{
    with_state($dir, static function () use ($config, $dir, $now): void {
        $state = load_state($dir);
        $usedNewKey = false;
        $nonce = '';
        if ($state['htaccess_pending'] !== null) {
            // Application interrompue entre la bascule et son résultat :
            // décidée d'après l'empreinte actuelle, avant tout retrait.
            resume_htaccess($config, $dir, $state);
        }
        if ($state['running'] !== null) {
            // Passage précédent interrompu pendant l'exécution ; une nouvelle
            // paire à moitié créée bloquerait toute rotation future.
            if ($state['running']['name'] === 'rotate-key') {
                @unlink($dir . '/' . KEY_FILE_NEW);
            }
            $state['result'] = ['command_id' => $state['running']['id'], 'status' => 'failed', 'detail' => 'exécution interrompue'];
            $state['running'] = null;
            save_state($dir, $state);
        }
        $response = null;
        foreach ([load_secret($dir), pending_new_secret($dir)] as $attempt => $secret) {
            if ($secret === null) {
                continue;
            }
            $state['pull_seq'] = max($state['pull_seq'] + 1, (int) floor(microtime(true) * 1000));
            save_state($dir, $state);
            $nonce = base64url(random_bytes(24));
            $request = ['v' => 1, 'type' => 'pull', 'site' => $config->site, 'seq' => $state['pull_seq'],
                'sent_at' => $now, 'nonce' => $nonce, 'agent' => AGENT];
            if ($state['result'] !== null) {
                $request['result'] = $state['result'];
            }
            $body = json_encode($request, \JSON_UNESCAPED_SLASHES | \JSON_UNESCAPED_UNICODE | \JSON_THROW_ON_ERROR);
            $signature = base64_encode(sodium_crypto_sign_detached(DOMAIN_PULL . $body, $secret));
            sodium_memzero($secret);
            $response = post_signed($config, $config->commandsEndpoint, $body, $signature);
            $usedNewKey = $attempt === 1;
            if ($response['status'] !== 404) {
                break;
            }
        }
        if ($response === null || $response['status'] === 404) {
            throw new SendError('retrait refusé (404 ; raison dans journalctl -u vigie-serve)');
        }
        [$verdict, $data] = verify_response($response['status'], $response['headers'], $response['body'], $config->commandsKey, $config->site, $nonce, time());
        if ($verdict !== 'valid') {
            throw new SendError("réponse rejetée ({$verdict}) : rien n'est exécuté");
        }
        if ($usedNewKey) {
            // Réponse signée à un retrait signé par la nouvelle clé : le
            // veilleur l'a enregistrée (accusé perdu). Bascule.
            promote_new_key($dir);
            $state['rotation'] = null;
            save_state($dir, $state);
        }
        if ($state['result'] !== null && $data['acked'] === $state['result']['command_id']) {
            settle_rotation($dir, $state, $data['acked'], $data['accepted'] === true);
            $state['result'] = null;
            save_state($dir, $state);
        }
        $command = $data['command'];
        if ($command === null || $command['seq'] <= $state['last_command_seq']) {
            return; // Rien à faire, ou déjà exécutée : son résultat repartira.
        }
        if ($state['result'] !== null) {
            return; // Un résultat attend encore son accusé : une commande à la fois.
        }
        $state['running'] = ['id' => $command['id'], 'seq' => $command['seq'], 'name' => $command['name']];
        save_state($dir, $state);
        $result = execute_command($config, $dir, $command, $state);
        $state['running'] = null;
        $state['result'] = $result;
        $state['last_command_seq'] = $command['seq'];
        if ($command['name'] === 'rotate-key' && $result['status'] === 'ok') {
            $state['rotation'] = ['command_id' => $command['id']];
        }
        save_state($dir, $state);
    });
}

/** Accusé d'une rotation : bascule si acceptée, sinon la nouvelle paire est détruite. */
function settle_rotation(string $dir, array &$state, string $acked, bool $accepted): void
{
    if ($state['rotation'] === null || $state['rotation']['command_id'] !== $acked) {
        return;
    }
    if ($accepted) {
        promote_new_key($dir);
    } else {
        @unlink($dir . '/' . KEY_FILE_NEW);
    }
    $state['rotation'] = null;
}

/** Liste fermée : match sur des constantes, aucun dispatch dynamique. */
function execute_command(Config $config, string $dir, array $command, array &$state): array
{
    $id = $command['id'];
    $result = static fn (string $status, string $detail, array $data = []): array => $data === []
        ? ['command_id' => $id, 'status' => $status, 'detail' => printable($detail, MAX_DETAIL)]
        : ['command_id' => $id, 'status' => $status, 'detail' => printable($detail, MAX_DETAIL), 'data' => $data];

    return match ($command['name']) {
        'ping' => $command['params'] === [] ? $result('ok', 'pong') : $result('refused', 'paramètres inattendus'),
        'rotate-key' => $command['params'] === [] ? rotate_key($config, $dir, $id, $result) : $result('refused', 'paramètres inattendus'),
        'htaccess-apply' => htaccess_apply($config, $dir, $command, $state, $result),
        'htaccess-rollback' => htaccess_rollback($config, $dir, $command, $state, $result),
    };
}

/** Nouvelle paire dans secret.key.new et preuve de possession ; l'ancienne reste. */
function rotate_key(Config $config, string $dir, string $id, callable $result): array
{
    $path = $dir . '/' . KEY_FILE_NEW;
    if (file_exists($path) || is_link($path)) {
        return $result('refused', 'une rotation précédente attend encore son accusé');
    }
    $old = umask(0077);
    $handle = @fopen($path, 'x');
    umask($old);
    if ($handle === false) {
        return $result('failed', 'création de la nouvelle clé impossible');
    }
    $pair = sodium_crypto_sign_keypair();
    $secret = sodium_crypto_sign_secretkey($pair);
    $public = base64_encode(sodium_crypto_sign_publickey($pair));
    $written = fwrite($handle, base64_encode($secret) . "\n");
    fclose($handle);
    @chmod($path, 0600);
    if ($written === false) {
        @unlink($path);
        sodium_memzero($secret);

        return $result('failed', 'écriture de la nouvelle clé impossible');
    }
    $proof = base64_encode(sodium_crypto_sign_detached(DOMAIN_ROTATE . $config->site . "\n" . $id . "\n" . $public, $secret));
    sodium_memzero($secret);
    sodium_memzero($pair);

    return $result('ok', 'nouvelle clé créée', ['new_pubkey' => $public, 'proof' => $proof]);
}

// --- .htaccess (vigie/docs/htaccess.md) -----------------------------------
//
// htaccess-apply remplace le bloc `# BEGIN vigie` du .htaccess de la racine,
// htaccess-rollback remet la copie précédente. Le bloc est revalidé ici par
// la même grammaire fermée que le veilleur (`recommend/htaccess.rs`), au code
// de refus près (vecteurs partagés : tests/fixtures/htaccess/vectors.json) :
// la validation tient même si le veilleur est compromis. Puis bac à sable
// différentiel, compare-and-swap, copie privée dans le dossier de l'agent,
// bascule par rename, smoke-test de l'accueil et retour automatique.

const HTACCESS_BEGIN = '# BEGIN vigie';
const HTACCESS_END = '# END vigie';
const HTACCESS_ENGINE = 'RewriteEngine On';
const HTACCESS_RULE = 'RewriteRule ^ - [F,L]';
const HTACCESS_UA = 'RewriteCond %{HTTP_USER_AGENT} ';
const HTACCESS_IP = 'RewriteCond %{REMOTE_ADDR} ';
const HTACCESS_TIME = 'RewriteCond %{TIME} <';
const HTACCESS_MAX_BYTES = 16384;
const HTACCESS_MAX_LINES = 200;
const HTACCESS_IP_MAX_TTL = 25 * 3600;
const HTACCESS_UA_MAX_TTL = 31 * 86400;
/** Copie privée du .htaccess d'avant la dernière bascule, dans le dossier de l'agent. */
const HTACCESS_PREV = 'htaccess.prev';
/** Marque d'un .htaccess absent avant la bascule : le retour arrière le supprime. */
const HTACCESS_PREV_ABSENT = 'htaccess.prev.absent';
/** 5 s par requête, 30 s en tout pour une commande. */
const HTACCESS_HTTP_TIMEOUT = 5;
const HTACCESS_HTTP_BUDGET = 30;
const HTACCESS_SANDBOX = 'vigie-essai-';
const BROWSER_UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) Gecko/20100101 Firefox/128.0';
const GOOGLEBOT_UA = 'Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; Googlebot/2.1) Chrome/126.0.6478.126 Safari/537.36';
/** Échantillon du corpus essayé dans le bac à sable (indices de PROTECTED_UAS). */
const SANDBOX_SAMPLE = [3, 11, 20, 31, 36, 42];

/**
 * Corpus d'UA protégés : une condition d'UA qui en touche un fait refuser le
 * bloc. Égal à tests/fixtures/htaccess/protected-uas.txt (test).
 */
const PROTECTED_UAS = [
    'Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; Googlebot/2.1) Chrome/126.0.6478.126 Safari/537.36',
    'Mozilla/5.0 (Linux; Android 6.0.1; Nexus 5X Build/MMB29P) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.6478.126 Mobile Safari/537.36 (compatible; Googlebot/2.1)',
    'Googlebot-Image/1.0',
    'Mozilla/5.0 (compatible; bingbot/2.0)',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/13.1.1 Safari/605.1.15 (Applebot/0.1)',
    'DuckDuckBot/1.1',
    'Mozilla/5.0 (compatible; YandexBot/3.0)',
    'Mozilla/5.0 (compatible; Baiduspider/2.0)',
    'Mozilla/5.0 (compatible; SeznamBot/4.0)',
    'Mozilla/5.0 (Linux; Android 7.0;) AppleWebKit/537.36 (KHTML, like Gecko) Mobile Safari/537.36 (compatible; PetalBot)',
    'Mozilla/5.0 (compatible; Qwantify/2.4w)',
    'facebookexternalhit/1.1',
    'Facebot',
    'Twitterbot/1.0',
    'LinkedInBot/1.0 (compatible; Mozilla/5.0; Apache-HttpClient)',
    'Pinterestbot/1.0',
    'Slackbot-LinkExpanding 1.0',
    'TelegramBot (like TwitterBot)',
    'WhatsApp/2.23.20.0',
    'Mozilla/5.0 (compatible; Discordbot/2.0)',
    'Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; ChatGPT-User/1.0)',
    'Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; Claude-User/1.0)',
    'Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; Perplexity-User/1.0)',
    'meta-externalfetcher/1.1',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36 Edg/126.0.0.0',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) Gecko/20100101 Firefox/128.0',
    'Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1',
    'Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Mobile Safari/537.36',
    'Mozilla/5.0 (Linux; Android 14; SM-S911B) AppleWebKit/537.36 (KHTML, like Gecko) SamsungBrowser/25.0 Chrome/121.0.0.0 Mobile Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36 OPR/111.0.0.0',
    'Opera/9.80 (Windows NT 6.1) Presto/2.12.388 Version/12.18',
    'vigie/0.3.0',
    'vigie-agent-php/0.4.0',
    'Stripe/1.0 (+webhooks)',
    'PayPal IPN',
    'Mollie HTTP Client/2.0',
    'GuzzleHttp/7',
    'WordPress/6.6.2; https://site-a.example.org',
    'PrestaShop/8.1.7',
    'curl/8.5.0',
    'Wget/1.21.4',
    'python-requests/2.31.0',
    'Java/17.0.10',
    'Go-http-client/1.1',
];

/**
 * Valide un bloc, dans l'ordre exact du validateur Rust. Rend ['valid',
 * groupes] ou [code, ligne] (ligne 0 : le bloc entier).
 *
 * @return array{0: string, 1: mixed}
 */
function htaccess_validate(string $block, int $now, \DateTimeZone $tz, bool $bounds = true): array
{
    if (\strlen($block) > HTACCESS_MAX_BYTES) {
        return ['too-large', 0];
    }
    foreach (["\r" => 'cr', "\t" => 'tab', "\0" => 'nul'] as $byte => $code) {
        if (str_contains($block, (string) $byte)) {
            return [$code, 0];
        }
    }
    if (preg_match('/[^\x20-\x7E\n]/', $block) === 1) {
        return ['byte', 0];
    }
    if ($block === '' || $block[\strlen($block) - 1] !== "\n") {
        return ['final-newline', 0];
    }
    $lines = explode("\n", substr($block, 0, -1));
    if (\count($lines) > HTACCESS_MAX_LINES) {
        return ['too-many-lines', 0];
    }
    foreach ($lines as $i => $line) {
        if (str_ends_with($line, '\\')) {
            return ['continuation', $i + 1];
        }
    }
    if ($lines[0] !== HTACCESS_BEGIN) {
        return ['begin', 1];
    }
    $last = \count($lines) - 1;
    if ($last === 0 || $lines[$last] !== HTACCESS_END) {
        return ['end', \count($lines)];
    }
    $groups = [];
    $state = 'start';
    $kind = null;
    $literals = [];
    $ip = null;
    $until = null;
    for ($i = 1; $i < $last; ++$i) {
        $raw = $lines[$i];
        $number = $i + 1;
        if (str_starts_with($raw, '#')) {
            if (!str_starts_with($raw, '# ') || str_contains($raw, 'BEGIN') || str_contains($raw, 'END') || str_contains($raw, '\\')) {
                return ['comment', $number];
            }
            continue;
        }
        [$type, $value] = htaccess_classify($raw, $tz);
        if ($type === 'error') {
            return [$value, $number];
        }
        if ($state === 'start') {
            if ($type !== 'engine') {
                return ['engine', $number];
            }
            $state = 'group-start';
            continue;
        }
        if ($type === 'engine') {
            return ['engine', $number];
        }
        switch ($state) {
            case 'group-start':
                if ($type === 'ua') {
                    $literals = [$value['literal']];
                    [$state, $kind] = $value['or'] ? ['ua-conds', 'ua'] : ['need-time', 'ua'];
                } elseif ($type === 'ip') {
                    $ip = $value;
                    [$state, $kind] = ['need-time', 'ip'];
                } else {
                    return ['group', $number];
                }
                break;
            case 'ua-conds':
                if ($type === 'ua') {
                    $literals[] = $value['literal'];
                    $state = $value['or'] ? 'ua-conds' : 'need-time';
                } elseif ($type === 'time') {
                    return ['or-last', $number];
                } else {
                    return ['group', $number];
                }
                break;
            case 'need-time':
                if ($type === 'time') {
                    if ($bounds) {
                        if ($value['ts'] <= $now) {
                            return ['time-past', $number];
                        }
                        if ($value['ts'] > $now + ($kind === 'ua' ? HTACCESS_UA_MAX_TTL : HTACCESS_IP_MAX_TTL)) {
                            return ['time-bound', $number];
                        }
                    }
                    $until = $value;
                    $state = 'need-rule';
                } elseif ($type === 'ua' && $kind === 'ua') {
                    return ['or-chain', $number];
                } elseif ($type === 'rule') {
                    return ['no-time', $number];
                } else {
                    return ['group', $number];
                }
                break;
            case 'need-rule':
                if ($type !== 'rule') {
                    return ['group', $number];
                }
                $groups[] = ['kind' => $kind, 'literals' => $kind === 'ua' ? $literals : [], 'ip' => $kind === 'ip' ? $ip : null,
                    'until' => $until['digits'], 'until_ts' => $until['ts']];
                [$state, $kind, $literals, $ip, $until] = ['group-start', null, [], null, null];
                break;
        }
    }
    if ($state === 'group-start') {
        return ['valid', $groups];
    }

    return [$state === 'start' ? 'engine' : 'group', \count($lines)];
}

/**
 * Reconnaît une ligne non commentée.
 *
 * @return array{0: string, 1: mixed} type (engine, rule, ua, ip, time, error) et valeur
 */
function htaccess_classify(string $raw, \DateTimeZone $tz): array
{
    if ($raw === HTACCESS_ENGINE) {
        return ['engine', null];
    }
    if ($raw === HTACCESS_RULE) {
        return ['rule', null];
    }
    if (str_starts_with($raw, HTACCESS_UA)) {
        $rest = substr($raw, \strlen(HTACCESS_UA));
        if (!str_starts_with($rest, '"')) {
            return ['error', 'quote'];
        }
        $rest = substr($rest, 1);
        $close = strpos($rest, '"');
        if ($close === false) {
            return ['error', 'quote'];
        }
        $pattern = substr($rest, 0, $close);
        $suffix = substr($rest, $close + 1);
        if ($suffix === ' [NC,OR]') {
            $or = true;
        } elseif ($suffix === ' [NC]') {
            $or = false;
        } else {
            return ['error', 'flags'];
        }
        $literal = htaccess_unescape($pattern, 'A-Za-z0-9 _\/-', ['.', '+']);
        if ($literal === null) {
            return ['error', 'ua-pattern'];
        }
        if (preg_match('/^[A-Za-z0-9][A-Za-z0-9 _\/.+-]{2,63}\z/', $literal) !== 1) {
            return ['error', 'ua-literal'];
        }
        if (htaccess_touches_protected($literal)) {
            return ['error', 'protected-ua'];
        }

        return ['ua', ['literal' => $literal, 'or' => $or]];
    }
    if (str_starts_with($raw, HTACCESS_IP)) {
        $rest = substr($raw, \strlen(HTACCESS_IP));
        if (\strlen($rest) < 2 || !str_starts_with($rest, '"') || !str_ends_with($rest, '"')) {
            return ['error', 'quote'];
        }
        $inner = substr($rest, 1, -1);
        if (!str_starts_with($inner, '^')) {
            return ['error', 'ip-pattern'];
        }
        $inner = substr($inner, 1);
        if (!str_ends_with($inner, '$')) {
            return ['error', 'ip-pattern'];
        }
        $text = htaccess_unescape(substr($inner, 0, -1), '0-9a-f', ['.', ':']);
        if ($text === null) {
            return ['error', 'ip-pattern'];
        }
        $ip = htaccess_canonical_ip($text);

        return $ip === null ? ['error', 'ip'] : ['ip', $ip];
    }
    if (str_starts_with($raw, HTACCESS_TIME)) {
        $digits = substr($raw, \strlen(HTACCESS_TIME));
        $ts = htaccess_to_unix($digits, $tz);

        return $ts === null ? ['error', 'time-format'] : ['time', ['digits' => $digits, 'ts' => $ts]];
    }

    return ['error', 'directive'];
}

/** Motif → texte : caractères de $class, ou « \ » suivi d'un de $escaped ; null sinon. */
function htaccess_unescape(string $pattern, string $class, array $escaped): ?string
{
    $out = '';
    $length = \strlen($pattern);
    for ($i = 0; $i < $length; ++$i) {
        $c = $pattern[$i];
        if ($c === '\\') {
            $next = $pattern[$i + 1] ?? '';
            if (!\in_array($next, $escaped, true)) {
                return null;
            }
            $out .= $next;
            ++$i;
        } elseif (preg_match('/^[' . $class . ']\z/', $c) === 1) {
            $out .= $c;
        } else {
            return null;
        }
    }

    return $out;
}

/** Une condition d'UA vaut « contient, sans casse ». */
function htaccess_touches_protected(string $literal): bool
{
    $needle = strtolower($literal);
    foreach (PROTECTED_UAS as $ua) {
        if (str_contains(strtolower($ua), $needle)) {
            return true;
        }
    }

    return false;
}

/** IP canonique (inet_pton puis inet_ntop), hors IPv4 mappée et hors ::/96. */
function htaccess_canonical_ip(string $text): ?string
{
    if (str_contains($text, ':')) {
        if (str_contains($text, '.')) {
            return null;
        }
        $bin = @inet_pton($text);
        if ($bin === false || \strlen($bin) !== 16) {
            return null;
        }
        $mapped = substr($bin, 0, 10) === str_repeat("\0", 10) && substr($bin, 10, 2) === "\xff\xff";
        if ($mapped || substr($bin, 0, 12) === str_repeat("\0", 12)) {
            return null;
        }
    } else {
        $bin = @inet_pton($text);
        if ($bin === false || \strlen($bin) !== 4) {
            return null;
        }
    }

    return inet_ntop($bin) === $text ? $text : null;
}

/** AAAAMMJJhhmmss → secondes Unix dans $tz, années 2000 à 2999. */
function htaccess_to_unix(string $digits, \DateTimeZone $tz): ?int
{
    if (preg_match('/^[0-9]{14}\z/', $digits) !== 1) {
        return null;
    }
    [$y, $m, $d, $h, $i, $s] = array_map('intval', [substr($digits, 0, 4), substr($digits, 4, 2), substr($digits, 6, 2),
        substr($digits, 8, 2), substr($digits, 10, 2), substr($digits, 12, 2)]);
    if ($y < 2000 || $y > 2999 || !checkdate($m, $d, $y) || $h > 23 || $i > 59 || $s > 59) {
        return null;
    }

    return (new \DateTimeImmutable(sprintf('%04d-%02d-%02d %02d:%02d:%02d', $y, $m, $d, $h, $i, $s), $tz))->getTimestamp();
}

/**
 * Nouveau contenu : le bloc vigie remplacé (lignes exactes, au plus une
 * paire), ou ajouté en tête. Le reste, dont le bloc sc_alwaysdata du
 * module, est gardé à l'octet.
 *
 * @return array{0: ?string, 1: ?string} contenu, ou raison du refus
 */
function htaccess_merge(string $current, string $block): array
{
    $begins = [];
    $ends = [];
    $offset = 0;
    foreach (explode("\n", $current) as $line) {
        $length = \strlen($line);
        $trimmed = rtrim($line, " \t\r");
        if ($trimmed === HTACCESS_BEGIN || $trimmed === HTACCESS_END) {
            if ($line !== $trimmed) {
                return [null, 'bloc vigie mal délimité (espace ou CR en fin de ligne)'];
            }
            if ($line === HTACCESS_BEGIN) {
                $begins[] = $offset;
            } else {
                $ends[] = $offset + $length;
            }
        }
        $offset += $length + 1;
    }
    if ($begins === [] && $ends === []) {
        return [$block . $current, null];
    }
    if (\count($begins) !== 1 || \count($ends) !== 1 || $begins[0] > $ends[0]) {
        return [null, 'bloc vigie mal délimité (plusieurs paires ou ordre inversé)'];
    }
    $after = $ends[0] < \strlen($current) ? $ends[0] + 1 : $ends[0];

    return [substr($current, 0, $begins[0]) . $block . substr($current, $after), null];
}

/** Paramètres exacts d'une commande htaccess-* : clés attendues, chaînes ou empreintes. */
function htaccess_params(array $params, array $hashes, bool $withBlock): bool
{
    $expected = $withBlock ? array_merge(['block'], $hashes) : $hashes;
    sort($expected);
    if (sorted_keys($params) !== $expected) {
        return false;
    }
    if ($withBlock && !\is_string($params['block'])) {
        return false;
    }
    foreach ($hashes as $key) {
        if ($params[$key] !== null && (!\is_string($params[$key]) || preg_match('/^[0-9a-f]{64}\z/', $params[$key]) !== 1)) {
            return false;
        }
    }

    return true;
}

/** État d'une application interrompue. */
function valid_htaccess_pending(mixed $pending): bool
{
    $hash = static fn (mixed $h): bool => $h === null || (\is_string($h) && preg_match('/^[0-9a-f]{64}\z/', $h) === 1);

    return \is_array($pending) && sorted_keys($pending) === ['command_id', 'kind', 'new_sha256', 'prev_sha256', 'statuts_avant']
        && \is_string($pending['command_id']) && \in_array($pending['kind'], ['apply', 'rollback'], true)
        && $hash($pending['new_sha256']) && $hash($pending['prev_sha256'])
        && \is_array($pending['statuts_avant']) && sorted_keys($pending['statuts_avant']) === ['browser', 'googlebot']
        && \is_int($pending['statuts_avant']['browser']) && \is_int($pending['statuts_avant']['googlebot']);
}

/**
 * Le .htaccess de la racine : chemin, existence, octets et empreinte. null
 * si la racine est introuvable ou si le fichier n'est pas un fichier
 * ordinaire (lien symbolique, dossier).
 *
 * @return ?array{path: string, root: string, exists: bool, bytes: ?string, sha: ?string, mode: int}
 */
function read_htaccess(Config $config): ?array
{
    $root = realpath($config->root);
    if ($root === false || !is_dir($root)) {
        return null;
    }
    $path = $root . '/.htaccess';
    clearstatcache(true, $path);
    if (is_link($path)) {
        return null;
    }
    if (!file_exists($path)) {
        return ['path' => $path, 'root' => $root, 'exists' => false, 'bytes' => null, 'sha' => null, 'mode' => 0644];
    }
    if (!is_file($path)) {
        return null;
    }
    $bytes = @file_get_contents($path);
    if ($bytes === false) {
        return null;
    }

    return ['path' => $path, 'root' => $root, 'exists' => true, 'bytes' => $bytes, 'sha' => hash('sha256', $bytes),
        'mode' => fileperms($path) & 0777];
}

/** Empreinte actuelle du .htaccess (null : absent ou illisible). */
function current_htaccess_sha(Config $config): ?string
{
    return read_htaccess($config)['sha'] ?? null;
}

/** Écrit le .htaccess par fichier temporaire du même dossier (nom en .ht*, refusé par Apache) et rename ; null : contenu absent, suppression. */
function write_htaccess(string $root, ?string $bytes, int $mode): bool
{
    $path = $root . '/.htaccess';
    if ($bytes === null) {
        return !file_exists($path) || @unlink($path);
    }
    $tmp = $root . '/.htaccess.vigie-' . bin2hex(random_bytes(6)) . '.tmp';
    $handle = @fopen($tmp, 'x');
    if ($handle === false) {
        return false;
    }
    $written = fwrite($handle, $bytes);
    fclose($handle);
    @chmod($tmp, $mode);
    if ($written !== \strlen($bytes) || !@rename($tmp, $path)) {
        @unlink($tmp);

        return false;
    }

    return true;
}

/**
 * Copie privée d'avant la bascule : ['sha' => …, 'bytes' => …] (sha null :
 * le fichier n'existait pas), ou null s'il n'y en a pas.
 */
function read_private_copy(string $dir): ?array
{
    $path = $dir . '/' . HTACCESS_PREV;
    clearstatcache();
    if (is_file($path) && !is_link($path)) {
        $bytes = @file_get_contents($path);

        return $bytes === false ? null : ['sha' => hash('sha256', $bytes), 'bytes' => $bytes];
    }
    if (is_file($dir . '/' . HTACCESS_PREV_ABSENT)) {
        return ['sha' => null, 'bytes' => null];
    }

    return null;
}

/**
 * Écrit la copie privée depuis les octets vérifiés ; l'ancienne copie reste
 * en .old jusqu'à la réussite de la bascule (commit_private_copy).
 */
function write_private_copy(string $dir, ?string $bytes): bool
{
    foreach ([HTACCESS_PREV, HTACCESS_PREV_ABSENT] as $name) {
        @unlink("{$dir}/{$name}.old");
        if (file_exists("{$dir}/{$name}") && !@rename("{$dir}/{$name}", "{$dir}/{$name}.old")) {
            return false;
        }
    }
    if ($bytes === null) {
        $handle = @fopen($dir . '/' . HTACCESS_PREV_ABSENT, 'x');
        if ($handle === false) {
            return false;
        }
        fclose($handle);
        @chmod($dir . '/' . HTACCESS_PREV_ABSENT, 0600);

        return true;
    }
    $tmp = @tempnam($dir, '.prev-');
    if ($tmp === false) {
        return false;
    }
    @chmod($tmp, 0600);
    if (@file_put_contents($tmp, $bytes) !== \strlen($bytes) || !@rename($tmp, $dir . '/' . HTACCESS_PREV)) {
        @unlink($tmp);

        return false;
    }

    return true;
}

/** Bascule réussie : l'ancienne copie part. Échec : elle revient. */
function settle_private_copy(string $dir, bool $switched): void
{
    foreach ([HTACCESS_PREV, HTACCESS_PREV_ABSENT] as $name) {
        if ($switched) {
            @unlink("{$dir}/{$name}.old");
        } elseif (file_exists("{$dir}/{$name}.old")) {
            @unlink("{$dir}/{$name}");
            @rename("{$dir}/{$name}.old", "{$dir}/{$name}");
        }
    }
}

/**
 * GET sans redirection suivie, 5 s au plus et dans le budget. null si le
 * serveur ne répond pas.
 *
 * @return ?array{status: int, body: string}
 */
function http_get(string $url, string $ua, int $deadline): ?array
{
    $left = ($deadline - hrtime(true)) / 1e9;
    if ($left <= 0.1) {
        return null;
    }
    $timeout = min((float) HTACCESS_HTTP_TIMEOUT, $left);
    $context = stream_context_create([
        'http' => [
            'method' => 'GET',
            'header' => implode("\r\n", ['User-Agent: ' . $ua, 'Cache-Control: no-cache', 'Accept: */*']),
            'timeout' => $timeout,
            'follow_location' => 0,
            'max_redirects' => 0,
            'ignore_errors' => true,
        ],
        'ssl' => ['verify_peer' => true, 'verify_peer_name' => true, 'allow_self_signed' => false],
    ]);
    $previous = ini_set('default_socket_timeout', (string) (int) ceil($timeout));
    $stream = @fopen($url, 'r', false, $context);
    if ($previous !== false) {
        ini_set('default_socket_timeout', $previous);
    }
    if ($stream === false) {
        return null;
    }
    $body = stream_get_contents($stream, 65536);
    $meta = stream_get_meta_data($stream);
    fclose($stream);
    $line = $meta['wrapper_data'][0] ?? '';
    if (!\is_string($line) || preg_match('#^HTTP/\S+\s+(\d{3})#', $line, $m) !== 1) {
        return null;
    }

    return ['status' => (int) $m[1], 'body' => \is_string($body) ? $body : ''];
}

/**
 * Smoke-test de l'accueil, anti-cache, UA de navigateur et Googlebot.
 *
 * @return ?array{browser: int, googlebot: int}
 */
function smoke_test(Config $config, int $deadline): ?array
{
    $url = $config->siteUrl . '?vigie-essai=' . bin2hex(random_bytes(6));
    $out = [];
    foreach (['browser' => BROWSER_UA, 'googlebot' => GOOGLEBOT_UA] as $name => $ua) {
        $response = http_get($url, $ua, $deadline);
        if ($response === null) {
            return null;
        }
        $out[$name] = $response['status'];
    }

    return $out;
}

/** Lignes du bloc vigie d'un contenu, sans les bornes (vide s'il n'y en a pas). */
function vigie_block_lines(string $content): array
{
    $lines = explode("\n", $content);
    $begin = array_search(HTACCESS_BEGIN, $lines, true);
    $end = array_search(HTACCESS_END, $lines, true);

    return $begin === false || $end === false || $end < $begin ? [] : \array_slice($lines, $begin + 1, $end - $begin - 1);
}

/**
 * Bac à sable différentiel : vigie-essai-<hex>-a (ancien contenu) et -b
 * (nouveau, plus deux sondes d'horloge), chacun avec une page témoin à
 * nonce. Rend null si tout concorde, sinon la raison du refus. Dossiers
 * supprimés dans tous les cas.
 *
 * @param list<array{kind: string, literals: list<string>}> $groups
 */
function sandbox(Config $config, string $root, ?string $old, string $new, array $groups, int $now, int $deadline): ?string
{
    $hex = bin2hex(random_bytes(8));
    $dirs = ['a' => "{$root}/" . HTACCESS_SANDBOX . "{$hex}-a", 'b' => "{$root}/" . HTACCESS_SANDBOX . "{$hex}-b"];
    $nonces = ['a' => bin2hex(random_bytes(16)), 'b' => bin2hex(random_bytes(16))];
    $probe = static fn (string $which, int $at): array => [
        '# sonde d\'horloge', HTACCESS_UA . '"vigie-probe-' . $hex . $which . '" [NC]', HTACCESS_TIME . date('YmdHis', $at), HTACCESS_RULE,
    ];
    $lines = explode("\n", $new);
    $end = array_search(HTACCESS_END, $lines, true);
    array_splice($lines, (int) $end, 0, [...$probe('a', $now + 1800), ...$probe('b', $now - 1800)]);
    $contents = ['a' => $old, 'b' => implode("\n", $lines)];
    try {
        foreach ($dirs as $side => $path) {
            if (!@mkdir($path, 0755)) {
                return 'bac à sable impossible à créer';
            }
            if ($contents[$side] !== null && @file_put_contents("{$path}/.htaccess", $contents[$side]) !== \strlen($contents[$side])) {
                return 'bac à sable impossible à écrire';
            }
            if (@file_put_contents("{$path}/temoin.txt", $nonces[$side]) !== \strlen($nonces[$side])) {
                return 'bac à sable impossible à écrire';
            }
        }
        $get = static function (string $side, string $ua) use ($config, $hex, $nonces, $deadline): array {
            $response = http_get($config->siteUrl . HTACCESS_SANDBOX . "{$hex}-{$side}/temoin.txt", $ua, $deadline);
            if ($response === null) {
                return [null, 'bac à sable injoignable (délai)'];
            }
            if ($response['status'] === 200 && !str_contains($response['body'], $nonces[$side])) {
                return [null, 'bac à sable non représentatif : 200 sans la page témoin'];
            }

            return [$response['status'], null];
        };
        [$status, $error] = $get('a', BROWSER_UA);
        if ($error !== null || $status !== 200) {
            return $error ?? "bac à sable non représentatif : statut {$status} pour un navigateur avant le changement";
        }
        $uas = [BROWSER_UA, GOOGLEBOT_UA];
        foreach (SANDBOX_SAMPLE as $index) {
            $uas[] = PROTECTED_UAS[$index];
        }
        foreach ($uas as $ua) {
            [$a, $error] = $get('a', $ua);
            [$b, $errorB] = $error === null ? $get('b', $ua) : [null, null];
            if ($error !== null || $errorB !== null) {
                return $error ?? $errorB;
            }
            if ($a !== $b) {
                return "bac à sable : statut {$a} puis {$b} pour un UA protégé (" . printable($ua, 60) . ')';
            }
        }
        $oldLines = $old === null ? [] : vigie_block_lines($old);
        foreach ($groups as $group) {
            if ($group['kind'] !== 'ua') {
                continue;
            }
            $ua = $group['literals'][0];
            [$b, $error] = $get('b', $ua);
            if ($error !== null) {
                return $error;
            }
            if ($b !== 403) {
                return "bac à sable : la règle d'UA {$ua} rend {$b} au lieu de 403";
            }
            // Un groupe repris du bloc en place est déjà actif dans -a.
            $line = HTACCESS_UA . '"' . str_replace(['.', '+'], ['\\.', '\\+'], $ua) . '"';
            $kept = array_filter($oldLines, static fn (string $l): bool => str_starts_with($l, $line));
            if ($kept === []) {
                [$a, $error] = $get('a', $ua);
                if ($error !== null || $a === 403) {
                    return $error ?? "bac à sable : {$ua} déjà refusé avant le changement";
                }
            }
        }
        [$early, $error] = $get('b', "vigie-probe-{$hex}a");
        [$late, $errorLate] = $error === null ? $get('b', "vigie-probe-{$hex}b") : [null, null];
        if ($error !== null || $errorLate !== null) {
            return $error ?? $errorLate;
        }
        if ($early !== 403 || $late !== 200) {
            return "horloge Apache ≠ horloge agent (sondes : {$early} et {$late}, attendus 403 et 200 ; tz {$config->tz})";
        }

        return null;
    } finally {
        foreach ($dirs as $path) {
            @unlink("{$path}/.htaccess");
            @unlink("{$path}/temoin.txt");
            @rmdir($path);
        }
    }
}

/** htaccess-apply : calcul seul (new_sha256 nul), ou application complète. */
function htaccess_apply(Config $config, string $dir, array $command, array &$state, callable $result): array
{
    $params = $command['params'];
    if (!htaccess_params($params, ['new_sha256', 'previous_sha256'], true)) {
        return $result('refused', 'paramètres inattendus');
    }
    if ($config->siteUrl === null || $config->tz === null) {
        return $result('refused', 'configuration htaccess incomplète : url et tz dans config.json');
    }
    date_default_timezone_set($config->tz);
    $tz = new \DateTimeZone($config->tz);
    $current = read_htaccess($config);
    if ($current === null) {
        return $result('refused', 'racine introuvable, ou .htaccess qui n\'est pas un fichier ordinaire');
    }
    $data = ['current_sha256' => $current['sha']];
    if ($current['sha'] !== $params['previous_sha256']) {
        return $result('refused', 'le .htaccess a changé depuis la proposition (empreinte différente de previous_sha256)', $data);
    }
    $now = time();
    [$verdict, $groups] = htaccess_validate($params['block'], $now, $tz);
    if ($verdict !== 'valid') {
        return $result('refused', "bloc refusé par l'agent : {$verdict}, ligne {$groups}", $data);
    }
    [$content, $why] = htaccess_merge($current['bytes'] ?? '', $params['block']);
    if ($content === null) {
        return $result('refused', $why, $data);
    }
    $newSha = hash('sha256', $content);
    if ($params['new_sha256'] === null) {
        return $result('ok', 'calcul seul : rien n\'est écrit', $data + ['new_sha256' => $newSha]);
    }
    if ($newSha !== $params['new_sha256']) {
        return $result('refused', 'contenu calculé différent de new_sha256', $data);
    }
    $deadline = hrtime(true) + HTACCESS_HTTP_BUDGET * 1_000_000_000;
    $before = smoke_test($config, $deadline);
    if ($before === null) {
        return $result('failed', 'accueil injoignable avant l\'application : rien n\'est écrit', $data);
    }
    $refusal = sandbox($config, $current['root'], $current['bytes'], $content, $groups, $now, $deadline);
    if ($refusal !== null) {
        return $result('refused', $refusal . ' : rien n\'est écrit', $data);
    }
    // Compare-and-swap : relecture juste avant la bascule.
    $again = read_htaccess($config);
    if ($again === null || $again['sha'] !== $params['previous_sha256']) {
        return $result('failed', 'modifié pendant l\'application : rien n\'est écrit', ['current_sha256' => $again['sha'] ?? null]);
    }
    if (!write_private_copy($dir, $again['bytes'])) {
        settle_private_copy($dir, false);

        return $result('failed', 'copie privée impossible dans le dossier de l\'agent : rien n\'est écrit', $data);
    }
    $state['htaccess_pending'] = ['command_id' => $command['id'], 'kind' => 'apply', 'prev_sha256' => $params['previous_sha256'],
        'new_sha256' => $newSha, 'statuts_avant' => $before];
    save_state($dir, $state);
    if (!write_htaccess($again['root'], $content, $again['mode'])) {
        settle_private_copy($dir, false);
        $state['htaccess_pending'] = null;

        return $result('failed', 'écriture du .htaccess impossible : rien n\'est écrit', $data);
    }
    settle_private_copy($dir, true);
    $outcome = htaccess_check_after($config, $dir, $state['htaccess_pending'], smoke_test($config, max($deadline, hrtime(true) + 2 * HTACCESS_HTTP_TIMEOUT * 1_000_000_000)), 'bloc appliqué');
    $state['htaccess_pending'] = null;

    return $result(...$outcome);
}

/**
 * Après une bascule : statuts d'après identiques à ceux d'avant, sinon
 * retour à la copie privée seulement si le .htaccess a encore la nouvelle
 * empreinte (une application, pas un retour arrière).
 *
 * @return array{0: string, 1: string, 2: array}
 */
function htaccess_check_after(Config $config, string $dir, array $pending, ?array $after, string $done): array
{
    $before = $pending['statuts_avant'];
    if ($after === $before) {
        return ['ok', $done, ['current_sha256' => $pending['new_sha256']]];
    }
    $shown = $after === null ? 'accueil injoignable' : "accueil {$after['browser']}/{$after['googlebot']} au lieu de {$before['browser']}/{$before['googlebot']}";
    $current = read_htaccess($config);
    if ($current === null || $current['sha'] !== $pending['new_sha256']) {
        return ['failed', "{$shown} ; .htaccess modifié pendant l'application : rien n'est écrasé", ['current_sha256' => $current['sha'] ?? null]];
    }
    if ($pending['kind'] === 'rollback') {
        return ['failed', "copie précédente remise, mais {$shown}", ['current_sha256' => $current['sha']]];
    }
    $copy = read_private_copy($dir);
    if ($copy === null || $copy['sha'] !== $pending['prev_sha256'] || !write_htaccess($current['root'], $copy['bytes'], $current['mode'])) {
        return ['failed', "{$shown} ; copie privée absente ou différente : .htaccess laissé tel quel", ['current_sha256' => $current['sha']]];
    }

    return ['failed', "{$shown} : .htaccess remis à l'identique", ['current_sha256' => current_htaccess_sha($config)]];
}

/** htaccess-rollback : la copie privée revient si elle et le .htaccess ont les empreintes attendues. */
function htaccess_rollback(Config $config, string $dir, array $command, array &$state, callable $result): array
{
    $params = $command['params'];
    if (!htaccess_params($params, ['expected_current_sha256', 'prev_sha256'], false)) {
        return $result('refused', 'paramètres inattendus');
    }
    if ($config->siteUrl === null || $config->tz === null) {
        return $result('refused', 'configuration htaccess incomplète : url et tz dans config.json');
    }
    $current = read_htaccess($config);
    if ($current === null) {
        return $result('refused', 'racine introuvable, ou .htaccess qui n\'est pas un fichier ordinaire');
    }
    $data = ['current_sha256' => $current['sha']];
    $copy = read_private_copy($dir);
    if ($copy === null || $copy['sha'] !== $params['prev_sha256']) {
        return $result('refused', 'copie précédente absente ou différente de prev_sha256', $data);
    }
    if ($current['sha'] !== $params['expected_current_sha256']) {
        return $result('refused', 'le .htaccess a changé depuis la dernière application', $data);
    }
    $deadline = hrtime(true) + HTACCESS_HTTP_BUDGET * 1_000_000_000;
    $before = smoke_test($config, $deadline);
    if ($before === null) {
        return $result('failed', 'accueil injoignable avant le retour arrière : rien n\'est écrit', $data);
    }
    $again = read_htaccess($config);
    if ($again === null || $again['sha'] !== $params['expected_current_sha256']) {
        return $result('failed', 'modifié pendant le retour arrière : rien n\'est écrit', ['current_sha256' => $again['sha'] ?? null]);
    }
    $state['htaccess_pending'] = ['command_id' => $command['id'], 'kind' => 'rollback', 'prev_sha256' => $params['expected_current_sha256'],
        'new_sha256' => $params['prev_sha256'], 'statuts_avant' => $before];
    save_state($dir, $state);
    if (!write_htaccess($again['root'], $copy['bytes'], $again['mode'])) {
        $state['htaccess_pending'] = null;

        return $result('failed', 'écriture du .htaccess impossible : rien n\'est écrit', $data);
    }
    $outcome = htaccess_check_after($config, $dir, $state['htaccess_pending'], smoke_test($config, max($deadline, hrtime(true) + 2 * HTACCESS_HTTP_TIMEOUT * 1_000_000_000)), 'copie précédente remise');
    $state['htaccess_pending'] = null;

    return $result(...$outcome);
}

/**
 * Reprise d'une bascule interrompue (htaccess_pending trouvé en tête du
 * passage), d'après l'empreinte actuelle : nouvelle → smoke-test contre les
 * statuts d'avant, puis ok ou retour arrière ; ancienne → bascule non
 * faite ; autre → modifié pendant l'application. Le résultat remplace celui
 * de la commande interrompue.
 */
function resume_htaccess(Config $config, string $dir, array &$state): void
{
    $pending = $state['htaccess_pending'];
    $id = $pending['command_id'];
    $make = static fn (string $status, string $detail, array $data): array => [
        'command_id' => $id, 'status' => $status, 'detail' => printable('reprise : ' . $detail, MAX_DETAIL), 'data' => $data,
    ];
    $current = read_htaccess($config);
    $sha = $current['sha'] ?? null;
    if ($current !== null && $sha === $pending['new_sha256']) {
        $after = $config->siteUrl === null ? null : smoke_test($config, hrtime(true) + HTACCESS_HTTP_BUDGET * 1_000_000_000);
        $state['result'] = $make(...htaccess_check_after($config, $dir, $pending, $after, 'bascule faite et contrôlée'));
    } elseif ($current !== null && $sha === $pending['prev_sha256']) {
        $state['result'] = $make('failed', 'bascule non faite : rien n\'est écrit', ['current_sha256' => $sha]);
    } else {
        $state['result'] = $make('failed', 'modifié pendant l\'application : rien n\'est écrit', ['current_sha256' => $sha]);
    }
    if ($state['running'] !== null && $state['running']['id'] === $id) {
        $state['last_command_seq'] = max($state['last_command_seq'], $state['running']['seq']);
        $state['running'] = null;
    }
    $state['htaccess_pending'] = null;
    save_state($dir, $state);
}

// --- Logs (vigie/docs/logs.md) -----------------------------------------
//
// Facultatif. Avec une section `logs`, l'agent pousse après le rapport et le
// retrait les lignes nouvelles du log HTTP d'Alwaysdata
// (`<logs.dir>/<année>/http-<date>.log`, compressé en `.log.gz` par
// l'hébergeur), par lots signés sur `vigie-logs-v1\n`. Seules les lignes de
// `logs.hosts` partent. La position d'octet vit dans `logs.json`, à côté de
// la clé, sous `flock` de `logs.lock` : un passage lent des logs ne fait pas
// sauter les commandes. Elle n'avance qu'après un 204 ; un lot envoyé est
// d'abord écrit `pending`, et renvoyé à l'identique au passage suivant : le
// veilleur le déduplique par sa plage.

const DOMAIN_LOGS = "vigie-logs-v1\n";
const LOGS_STATE = 'logs.json';
const LOGS_LOCK = 'logs.lock';
/** Une ligne est coupée à 16 Kio ; la suite est jetée jusqu'au \n. */
const MAX_LOG_LINE = 16384;
/** Octets gardés par lot, au plus : 44 Kio font 60 076 octets en base64. */
const MAX_LOG_CHUNK = 45056;
/** Plage lue par lot, au plus : même constante que le veilleur (MAX_RANGE). */
const MAX_LOG_RANGE = 4 * 1024 * 1024;
const MAX_LOG_BATCHES = 20;
const MAX_LOG_SECONDS = 20;
const MAX_LOG_HOSTS = 20;
/** Les fichiers datés de plus de 30 jours (date du nom) sont ignorés. */
const LOG_MAX_AGE = 30 * 86400;
/** Un fichier est clos une heure après la première vue d'un fichier plus récent. */
const LOG_CLOSE_AFTER = 3600;
/** Empreinte de tête : 256 premiers octets (décompressés pour un .gz). */
const LOG_HEAD = 256;
const LOG_NAME = '/^http-(\d{4})-(\d{2})-(\d{2})\.log(\.gz)?$/';

/** Lecteur d'un fichier de logs ouvert pour un passage ; $carry : ligne lue, pas encore prise. */
final class LogReader
{
    public ?array $carry = null;

    /** @param resource $handle */
    public function __construct(public $handle, public int $pos, public string $form)
    {
    }
}

/** @return array{0: ?string, 1: list<string>, 2: ?string} dossier, hôtes, point d'entrée des lots */
function logs_config(mixed $logs, string $endpoint): array
{
    if ($logs === null) {
        return [null, [], null];
    }
    if (!\is_array($logs) || array_is_list($logs) || array_diff(array_keys($logs), ['dir', 'hosts']) !== [] || \count($logs) !== 2) {
        throw new UsageError('Configuration : logs est {"dir": …, "hosts": […]}, sans autre clé.');
    }
    if (!\is_string($logs['dir']) || !is_absolute($logs['dir'])) {
        throw new UsageError('Configuration : logs.dir attendu, chemin absolu du dossier admin/logs/http.');
    }
    $hosts = $logs['hosts'];
    if (!\is_array($hosts) || !array_is_list($hosts) || $hosts === [] || \count($hosts) > MAX_LOG_HOSTS) {
        throw new UsageError('Configuration : logs.hosts est une liste de 1 à ' . MAX_LOG_HOSTS . ' hôtes.');
    }
    foreach ($hosts as $host) {
        if (!\is_string($host) || preg_match('/^[a-z0-9.-]{1,253}$/', $host) !== 1) {
            throw new UsageError('Configuration : logs.hosts contient un hôte invalide (minuscules, sans port).');
        }
    }
    if (\count(array_unique($hosts)) !== \count($hosts)) {
        throw new UsageError('Configuration : hôte en double dans logs.hosts.');
    }
    if (preg_match('#/r/v1/report$#', $endpoint) !== 1) {
        throw new UsageError('Configuration : avec logs, endpoint doit finir par /r/v1/report.');
    }

    return [rtrim($logs['dir'], '/\\'), $hosts, substr($endpoint, 0, -\strlen('report')) . 'logs'];
}

/** État vide : aucun fichier suivi. */
function empty_logs_state(): array
{
    return ['seq' => 0, 'file' => null, 'form' => null, 'gen' => 0, 'offset' => 0, 'inode' => 0,
        'head_len' => 0, 'head_sha256' => '', 'next_seen_at' => null, 'pending' => null];
}

/** null : pas d'état (premier passage, ou état perdu). */
function load_logs_state(string $dir): ?array
{
    $path = $dir . '/' . LOGS_STATE;
    clearstatcache(true, $path);
    if (!file_exists($path) && !is_link($path)) {
        return null;
    }
    private_file($path, LOGS_STATE);
    $raw = @file_get_contents($path, false, null, 0, READ_MAX_BYTES);
    try {
        $state = \is_string($raw) ? json_decode($raw, true, 8, \JSON_THROW_ON_ERROR) : null;
    } catch (\JsonException) {
        $state = null;
    }
    $valid = \is_array($state) && sorted_keys($state) === sorted_keys(empty_logs_state())
        && \is_int($state['seq']) && \is_string($state['file']) && preg_match(LOG_NAME, $state['file'], $m) === 1 && !isset($m[4])
        && \in_array($state['form'], [null, 'log', 'gz'], true) && \is_int($state['gen']) && $state['gen'] >= 0
        && \is_int($state['offset']) && $state['offset'] >= 0 && \is_int($state['inode'])
        && \is_int($state['head_len']) && $state['head_len'] >= 0 && $state['head_len'] <= LOG_HEAD && \is_string($state['head_sha256'])
        && ($state['next_seen_at'] === null || \is_int($state['next_seen_at']))
        && ($state['pending'] === null || valid_pending($state['pending'], $state));
    if (!$valid) {
        throw new UsageError("État des logs illisible ({$path}) : le supprimer fait repartir du fichier le plus récent.");
    }

    return array_replace(empty_logs_state(), $state);
}

function valid_pending(mixed $pending, array $state): bool
{
    return \is_array($pending) && sorted_keys($pending) === ['end', 'file', 'gen', 'start']
        && $pending['file'] === $state['file'] && $pending['gen'] === $state['gen'] && $pending['start'] === $state['offset']
        && \is_int($pending['end']) && $pending['end'] > $pending['start'] && $pending['end'] - $pending['start'] <= MAX_LOG_RANGE;
}

/** Clés d'un tableau, triées : l'ordre d'écriture ne compte pas. */
function sorted_keys(array $data): array
{
    $keys = array_keys($data);
    sort($keys);

    return $keys;
}

function save_logs_state(string $dir, array $state): void
{
    save_private_json($dir, LOGS_STATE, $state);
}

/**
 * Fichiers de logs de l'année courante et de la précédente, de 30 jours au
 * plus, par nom (`http-AAAA-MM-JJ.log`) : chemin du `.log` et du `.log.gz`.
 * Ni lien symbolique, ni fichier hors du dossier.
 *
 * @return array<string, array{log: ?string, gz: ?string}>
 */
function list_log_files(string $dirReal, int $now): array
{
    $year = (int) gmdate('Y', $now);
    $oldest = gmdate('Y-m-d', $now - LOG_MAX_AGE);
    $files = [];
    foreach ([$year - 1, $year] as $y) {
        $sub = $dirReal . '/' . $y;
        if (is_link($sub) || !is_dir($sub)) {
            continue;
        }
        foreach (scandir($sub) ?: [] as $name) {
            if (preg_match(LOG_NAME, $name, $m) !== 1 || (int) $m[1] !== $y || "{$m[1]}-{$m[2]}-{$m[3]}" < $oldest) {
                continue;
            }
            $path = $sub . '/' . $name;
            $real = realpath($path);
            if (is_link($path) || !is_file($path) || $real === false || !inside($dirReal, $real)) {
                continue;
            }
            $base = "http-{$m[1]}-{$m[2]}-{$m[3]}.log";
            $files[$base] ??= ['log' => null, 'gz' => null];
            $files[$base][isset($m[4]) ? 'gz' : 'log'] = $path;
        }
    }
    ksort($files, \SORT_STRING);

    return $files;
}

/** Premier fichier de la liste après $name, par ordre de nom. */
function next_log_file(array $files, string $name): ?string
{
    foreach (array_keys($files) as $candidate) {
        if (strcmp($candidate, $name) > 0) {
            return $candidate;
        }
    }

    return null;
}

/** Position au début d'un autre fichier, génération 0, empreinte à relever. */
function move_to_file(array &$state, string $name): void
{
    $state = ['seq' => $state['seq']] + array_replace(empty_logs_state(), ['file' => $name]);
}

/** Fichier remplacé : génération suivante, depuis le début, lot en attente abandonné. */
function restart_file(array &$state): void
{
    ++$state['gen'];
    $state['offset'] = 0;
    $state['pending'] = null;
    $state['head_len'] = 0;
    $state['head_sha256'] = '';
}

/**
 * Ouvre le fichier de la position et s'y place. Vérifie qu'il n'a pas été
 * remplacé (empreinte de tête, inode entre deux lectures de même forme, .log
 * raccourci), relève ou élargit l'empreinte. Un .gz s'ouvre une fois par
 * passage, l'avance décompressée comptant dans le délai du passage.
 *
 * @return array{0: ?LogReader, 1: string} lecteur et issue : ok, missing, truncated, timeout
 */
function open_log_position(array &$state, string $path, string $form, int $deadline): array
{
    clearstatcache(true, $path);
    $inode = (int) @fileinode($path);
    $handle = @fopen(($form === 'gz' ? 'compress.zlib://' : '') . $path, 'rb');
    if ($handle === false) {
        return [null, 'missing'];
    }
    $head = '';
    while (\strlen($head) < LOG_HEAD && ($bytes = fread($handle, LOG_HEAD - \strlen($head))) !== false && $bytes !== '') {
        $head .= $bytes;
    }
    if ($state['head_len'] > 0) {
        $short = \strlen($head) < $state['head_len'];
        if ($form === 'gz' && $short && \strlen($head) < $state['offset']) {
            fclose($handle);

            return [null, 'truncated'];
        }
        $replaced = ($state['form'] === $form && $state['inode'] !== $inode)
            || $short
            || !hash_equals($state['head_sha256'], hash('sha256', substr($head, 0, $state['head_len'])))
            || ($form === 'log' && (int) @filesize($path) < $state['offset']);
        if ($replaced) {
            restart_file($state);
        }
    }
    // Relevé, ou élargissement jusqu'à 256 octets d'une tête déjà vérifiée.
    $state['form'] = $form;
    $state['inode'] = $inode;
    $state['head_len'] = \strlen($head);
    $state['head_sha256'] = hash('sha256', $head);
    $offset = $state['offset'];
    if ($form === 'log' || $offset <= \strlen($head)) {
        if (fseek($handle, $offset) !== 0) {
            fclose($handle);

            return [null, 'missing'];
        }
    } else {
        $left = $offset - \strlen($head);
        while ($left > 0) {
            if (hrtime(true) > $deadline) {
                fclose($handle);

                return [null, 'timeout'];
            }
            $bytes = fread($handle, min($left, 1 << 20));
            if ($bytes === false || $bytes === '') {
                fclose($handle);

                return [null, 'truncated'];
            }
            $left -= \strlen($bytes);
        }
    }

    return [new LogReader($handle, $offset, $form), 'ok'];
}

/** Hôte d'une ligne : premier jeton, minuscules, sans port ; null s'il est illisible. */
function log_host(string $line): ?string
{
    $space = strpos($line, ' ');
    if ($space === false || $space === 0) {
        return null;
    }
    $host = (string) preg_replace('/:\d+$/', '', strtolower(substr($line, 0, $space)));
    $host = rtrim($host, '.');

    return preg_match('/^[a-z0-9.-]{1,253}$/', $host) === 1 ? $host : null;
}

/**
 * Ligne suivante, sans lire au-delà de $limit : état (line, eof, incomplete,
 * limit), octets lus du fichier, octets gardés (16 Kio au plus, suivis de
 * \n si la ligne a été coupée). Une ligne sans fin de ligne n'est prise que
 * dans un fichier clos.
 *
 * @return array{0: string, 1: int, 2: ?string}
 */
function next_log_line(LogReader $reader, int $limit, bool $closed): array
{
    if ($reader->carry !== null) {
        $line = $reader->carry;
        $reader->carry = null;

        return $line;
    }
    $room = $limit - $reader->pos;
    if ($room <= 0) {
        return ['limit', 0, null];
    }
    $want = min(MAX_LOG_LINE, $room);
    $line = fgets($reader->handle, $want + 1);
    if ($line === false || $line === '') {
        return ['eof', 0, null];
    }
    $read = \strlen($line);
    if ($line[$read - 1] === "\n") {
        return ['line', $read, $line];
    }
    if ($read < $want) {
        return $closed ? ['line', $read, $line] : ['incomplete', $read, null];
    }
    // Ligne trop longue : le début part, la suite est jetée jusqu'au \n.
    $kept = $line . "\n";
    while (($room = $limit - $reader->pos - $read) > 0) {
        $rest = fgets($reader->handle, min(65536, $room) + 1);
        if ($rest === false || $rest === '') {
            return $closed ? ['line', $read, $kept] : ['incomplete', $read, null];
        }
        $read += \strlen($rest);
        if ($rest[\strlen($rest) - 1] === "\n") {
            return ['line', $read, $kept];
        }
    }

    return ['line', $read, $kept];
}

/**
 * Lit un lot depuis la position du lecteur : exactement jusqu'à $end (renvoi
 * d'un lot en attente), ou jusqu'aux bornes ($chunkMax octets gardés, 4 Mio
 * lus). Rend les octets gardés, la fin de la plage lue, et si les données
 * disponibles sont épuisées.
 *
 * @param list<string> $hosts
 * @return array{0: string, 1: int, 2: bool}
 */
function read_log_batch(LogReader $reader, ?int $end, bool $closed, array $hosts, int $chunkMax): array
{
    $start = $reader->pos;
    $limit = $end ?? $start + MAX_LOG_RANGE;
    $chunk = '';
    while ($end === null || $reader->pos < $end) {
        // Place pour une ligne entière, sinon le lot se ferme avant elle.
        if ($end === null && $reader->carry === null && $reader->pos - $start > MAX_LOG_RANGE - MAX_LOG_LINE) {
            break;
        }
        [$what, $read, $kept] = next_log_line($reader, $limit, $closed);
        if ($what === 'limit') {
            break;
        }
        if ($what !== 'line') {
            if ($what === 'incomplete') {
                // Ligne en cours d'écriture : relue au passage suivant.
                fseek($reader->handle, $reader->pos);
            }

            return [$chunk, $reader->pos, true];
        }
        $keep = $kept !== null && \in_array(log_host($kept), $hosts, true);
        if ($keep && $end === null && \strlen($chunk) + \strlen($kept) > $chunkMax) {
            $reader->carry = [$what, $read, $kept];
            break;
        }
        $reader->pos += $read;
        if ($keep) {
            $chunk .= $kept;
        }
    }

    return [$chunk, $reader->pos, false];
}

/** Corps exact d'un lot, tel qu'il sera signé et envoyé. */
function log_batch_body(Config $config, int $seq, int $now, array $range, int $skipped, string $chunk): string
{
    return json_encode([
        'v' => 1,
        'type' => 'logs',
        'site' => $config->site,
        'seq' => $seq,
        'sent_at' => $now,
        'agent' => AGENT,
        'file' => $range['file'],
        'gen' => $range['gen'],
        'start' => $range['start'],
        'end' => $range['end'],
        'skipped_files' => min($skipped, 1000),
        'chunk' => base64_encode($chunk),
    ], \JSON_UNESCAPED_SLASHES | \JSON_UNESCAPED_UNICODE | \JSON_THROW_ON_ERROR);
}

/** Octets gardés par lot pour que le corps signé tienne dans 64 Kio, même avec les plus grands nombres. */
function log_chunk_max(Config $config): int
{
    $big = \PHP_INT_MAX;
    $envelope = \strlen(log_batch_body($config, $big, $big, ['file' => 'http-0000-00-00.log', 'gen' => $big, 'start' => $big, 'end' => $big], 1000, ''));

    return min(MAX_LOG_CHUNK, intdiv(MAX_BODY - $envelope, 4) * 3);
}

/**
 * Envoie un lot : `pending` et `seq` écrits d'abord, puis POST signé, avec
 * repli sur la nouvelle clé d'une rotation non accusée. Vrai sur un 204.
 */
function send_log_batch(Config $config, string $dir, array &$state, array $range, string $chunk, int $skipped, int $now): bool
{
    $state['pending'] = $range;
    foreach ([load_secret($dir), pending_new_secret($dir)] as $secret) {
        if ($secret === null) {
            continue;
        }
        $state['seq'] = max($state['seq'] + 1, (int) floor(microtime(true) * 1000));
        save_logs_state($dir, $state);
        $body = log_batch_body($config, $state['seq'], $now, $range, $skipped, $chunk);
        $signature = base64_encode(sodium_crypto_sign_detached(DOMAIN_LOGS . $body, $secret));
        sodium_memzero($secret);
        if (post_signed($config, (string) $config->logsEndpoint, $body, $signature)['status'] === 204) {
            return true;
        }
    }

    return false;
}

/** Un passage des logs, sous le verrou `logs.lock`. */
function send_logs(Config $config, string $dir, int $now): void
{
    with_lock($dir, LOGS_LOCK, static function () use ($config, $dir, $now): void {
        logs_pass($config, $dir, $now);
    }, 'un autre passage lit les logs : ce passage les saute');
}

function logs_pass(Config $config, string $dir, int $now): void
{
    $dirReal = realpath((string) $config->logsDir);
    if ($dirReal === false || !is_dir($dirReal)) {
        throw new UsageError("Dossier des logs introuvable : {$config->logsDir}.");
    }
    $deadline = hrtime(true) + MAX_LOG_SECONDS * 1_000_000_000;
    $chunkMax = log_chunk_max($config);
    $files = list_log_files($dirReal, $now);
    $state = load_logs_state($dir);
    if ($state === null) {
        if ($files === []) {
            return;
        }
        // Sans état : début du fichier le plus récent, génération plus grande
        // que toute génération antérieure.
        $state = array_replace(empty_logs_state(), [
            'file' => array_key_last($files),
            'gen' => max($now * 1000, (int) floor(microtime(true) * 1000)),
        ]);
        save_logs_state($dir, $state);
    }
    $skipped = 0;
    $sent = 0;
    $reader = null;
    try {
        while ($sent < MAX_LOG_BATCHES && hrtime(true) < $deadline) {
            $name = $state['file'];
            $next = next_log_file($files, $name);
            if ($next !== null && $state['next_seen_at'] === null) {
                $state['next_seen_at'] = $now;
                save_logs_state($dir, $state);
            }
            if ($reader === null) {
                $paths = $files[$name] ?? ['log' => null, 'gz' => null];
                $form = $paths['log'] !== null ? 'log' : 'gz';
                [$reader, $outcome] = $paths[$form] === null ? [null, 'missing'] : open_log_position($state, $paths[$form], $form, $deadline);
                if ($outcome === 'timeout') {
                    return;
                }
                if ($reader === null) {
                    // Introuvable (purgé, trop ancien) ou archive tronquée : fichier suivant.
                    if ($next === null) {
                        return;
                    }
                    ++$skipped;
                    move_to_file($state, $next);
                    save_logs_state($dir, $state);
                    continue;
                }
                save_logs_state($dir, $state);
            }
            $closed = $reader->form === 'gz' || ($state['next_seen_at'] !== null && $now - $state['next_seen_at'] >= LOG_CLOSE_AFTER);
            $pending = $state['pending'];
            [$chunk, $end, $exhausted] = read_log_batch($reader, $pending['end'] ?? null, $closed, $config->logsHosts, $chunkMax);
            if ($pending !== null && $end !== $pending['end']) {
                // La plage en attente ne se relit plus à l'identique : fichier remplacé.
                restart_file($state);
                save_logs_state($dir, $state);
                fclose($reader->handle);
                $reader = null;
                continue;
            }
            if ($end === $state['offset']) {
                // Rien de neuf : fichier ouvert, ou clos et fini.
                if (!$closed || !$exhausted || $next === null) {
                    return;
                }
                move_to_file($state, $next);
                save_logs_state($dir, $state);
                fclose($reader->handle);
                $reader = null;
                continue;
            }
            $range = ['file' => $name, 'gen' => $state['gen'], 'start' => $state['offset'], 'end' => $end];
            if (!send_log_batch($config, $dir, $state, $range, $chunk, $skipped, $now)) {
                throw new SendError('lot de logs refusé (raison dans journalctl -u vigie-serve) : renvoyé au prochain passage');
            }
            $state['offset'] = $end;
            $state['pending'] = null;
            save_logs_state($dir, $state);
            $skipped = 0;
            ++$sent;
        }
    } finally {
        if ($reader !== null) {
            fclose($reader->handle);
        }
    }
}

if (get_included_files()[0] === __FILE__) {
    exit(main($_SERVER['argv'] ?? []));
}

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
//   php vigie-agent.php --dry-run    affiche le rapport sans le signer ni l'envoyer
//   php vigie-agent.php --init       crée la paire de clés, affiche la clé publique
//   --config <fichier>               sinon ~/.vigie-agent/config.json
//
// Lecture seule : l'agent n'écrit que sa clé, à --init, à côté de la
// configuration. Aucun état entre deux passages : `seq` est l'heure en ms.
// Codes de retour : 0 succès, 1 envoi échoué, 2 configuration ou usage,
// 3 extension sodium absente.
// Compatible PHP 8.1 (version du site A) : ni classes readonly, ni constantes
// typées, ni json_validate.

const VERSION = '0.1.0';
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
        $secret = load_secret(\dirname($configPath));
        $signature = sign($body, $secret);
        sodium_memzero($secret);
        send($config, $body, $signature);

        return 0;
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
    $known = ['site', 'endpoint', 'root', 'kind', 'critical', 'must_contain', 'uploads'];
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

    return new Config($site, $endpoint, rtrim($root, '/\\'), $kind, $critical, $mustContain, $uploads);
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

if (get_included_files()[0] === __FILE__) {
    exit(main($_SERVER['argv'] ?? []));
}

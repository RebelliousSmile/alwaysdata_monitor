<?php
/**
 * SC Alwaysdata - PrestaShop 8 Module
 *
 * @author    Scriptami
 * @copyright Scriptami
 * @license   Academic Free License version 3.0
 */

declare(strict_types=1);

namespace ScAlwaysdata\Service;

class HtaccessService
{
    public const FACET_MAX_FILTERS_LIMIT = 10;

    private HtaccessDoctor $doctor;

    private const PROTECTION_BEGIN = '# BEGIN sc_alwaysdata protection';
    private const PROTECTION_END = '# END sc_alwaysdata protection';
    private const PROTECTION_OPTIONS = '# sc_alwaysdata options:';
    private const PROTECTION_PATTERN = '/^# BEGIN sc_alwaysdata protection\n.*?^# END sc_alwaysdata protection\n?/ms';

    public function __construct(?HtaccessDoctor $doctor = null)
    {
        $this->doctor = $doctor ?? new HtaccessDoctor();
    }

    public function readBlockedIps(): array
    {
        try {
            $content = file_get_contents($this->getHtaccessPath());
            if ($content === false) {
                return [];
            }
        } catch (\Throwable $e) {
            return [];
        }

        $ips = [];

        // Apache 2.4: Require not ip X.X.X.X
        preg_match_all('/Require not ip\s+(\S+)/i', $content, $m1);
        $ips = array_merge($ips, $m1[1] ?? []);

        // Apache 2.2: deny from X.X.X.X
        preg_match_all('/deny\s+from\s+(\d[\d.:a-fA-F]+)/i', $content, $m2);
        $ips = array_merge($ips, $m2[1] ?? []);

        return array_values(array_unique($ips));
    }

    public function readBlockedUAs(): array
    {
        try {
            $content = file_get_contents($this->getHtaccessPath());
            if ($content === false) {
                return [];
            }
        } catch (\Throwable $e) {
            return [];
        }

        $uas = [];

        // With quotes: RewriteCond %{HTTP_USER_AGENT} "BotName" [NC]
        // Accept any non-empty value — the quotes delimit exactly what was blocked
        preg_match_all('/RewriteCond\s+%\{HTTP_USER_AGENT\}\s+"([^"]+)"\s+\[NC\]/i', $content, $m1);
        $uas = array_merge($uas, $m1[1] ?? []);

        // Without quotes: RewriteCond %{HTTP_USER_AGENT} BotName [NC]
        // Only capture simple bot-name tokens (letters, digits, dots, hyphens, underscores).
        // This intentionally excludes negative patterns like !(Mozilla...) or anchored regexes.
        preg_match_all('/RewriteCond\s+%\{HTTP_USER_AGENT\}\s+([A-Za-z0-9][A-Za-z0-9._-]*)\s+\[NC\]/i', $content, $m2);
        $uas = array_merge($uas, $m2[1] ?? []);

        // Alternative: SetEnvIfNoCase User-Agent "BotName" bad_bot
        preg_match_all('/SetEnvIfNoCase\s+User-Agent\s+"([^"]+)"/i', $content, $m3);
        $uas = array_merge($uas, $m3[1] ?? []);

        // Without quotes: SetEnvIfNoCase User-Agent BotName bad_bot
        preg_match_all('/SetEnvIfNoCase\s+User-Agent\s+([A-Za-z0-9][A-Za-z0-9._-]*)/i', $content, $m4);
        $uas = array_merge($uas, $m4[1] ?? []);

        return array_values(array_unique($uas));
    }

    public function unblockIp(string $ip): void
    {
        if (!filter_var($ip, FILTER_VALIDATE_IP)) {
            throw new \InvalidArgumentException(sprintf('Invalid IP address: %s', $ip));
        }

        $htaccessPath = $this->getHtaccessPath();
        $current = @file_get_contents($htaccessPath);
        if ($current === false) {
            throw new \RuntimeException(sprintf('Cannot read .htaccess at %s', $htaccessPath));
        }

        $q = preg_quote($ip, '/');

        // Remove module-written block (comment + <RequireAll>)
        $content = preg_replace(
            '/\n?# sc_alwaysdata block: ' . $q . '\n<RequireAll>\nRequire all granted\nRequire not ip ' . $q . '\n<\/RequireAll>\n?/',
            "\n",
            $current
        );

        // Remove loose "Require not ip X.X.X.X" lines
        $content = preg_replace('/\nRequire not ip ' . $q . '\n/', "\n", $content ?? $current);

        // Remove loose "deny from X.X.X.X" lines
        $content = preg_replace('/\ndeny from ' . $q . '\n/i', "\n", $content ?? $current);

        $this->writeAtomic($content ?? $current);
    }

    public function unblockUserAgent(string $ua): void
    {
        $htaccessPath = $this->getHtaccessPath();
        $current = @file_get_contents($htaccessPath);
        if ($current === false) {
            throw new \RuntimeException(sprintf('Cannot read .htaccess at %s', $htaccessPath));
        }

        $current = str_replace("\r\n", "\n", $current);
        $content = $this->doctor->removeUaRules($current, $ua);
        if ($content === $current) {
            throw new \RuntimeException(sprintf(
                'Aucune règle simple ne bloque « %s » : règle combinée (OR) à retirer à la main.',
                $ua
            ));
        }

        $this->writeAtomic($content);
    }

    public function blockIp(string $ip): void
    {
        if (!filter_var($ip, FILTER_VALIDATE_IP)) {
            throw new \InvalidArgumentException(sprintf('Invalid IP address: %s', $ip));
        }

        $htaccessPath = $this->getHtaccessPath();
        $current = @file_get_contents($htaccessPath);
        if ($current === false) {
            throw new \RuntimeException(sprintf('Cannot read .htaccess at %s', $htaccessPath));
        }

        $block = "\n# sc_alwaysdata block: {$ip}\n"
            . "<RequireAll>\n"
            . "Require all granted\n"
            . "Require not ip {$ip}\n"
            . "</RequireAll>\n";

        $this->writeAtomic($current . $block);
    }

    public function blockUserAgent(string $ua): void
    {
        $ua = trim(str_replace(['"', '\\', "\n", "\r"], '', $ua));
        if ($ua === '') {
            throw new \InvalidArgumentException('Empty user-agent');
        }

        $htaccessPath = $this->getHtaccessPath();
        $current = @file_get_contents($htaccessPath);
        if ($current === false) {
            throw new \RuntimeException(sprintf('Cannot read .htaccess at %s', $htaccessPath));
        }

        // Managed section before PrestaShop's rules: anything after its [L] rewrite is never read
        $this->writeAtomic($this->doctor->addUaRules($current, [$ua]));
    }

    /**
     * Blocks several user-agents in one write (one backup instead of one per bot).
     * Already-blocked tokens are skipped by the doctor.
     *
     * @param string[] $uas
     */
    public function blockUserAgents(array $uas): void
    {
        $uas = array_values(array_filter(array_map(
            static fn ($ua): string => trim(str_replace(['"', '\\', "\n", "\r"], '', (string) $ua)),
            $uas
        ), static fn (string $ua): bool => $ua !== ''));
        if ($uas === []) {
            return;
        }

        $htaccessPath = $this->getHtaccessPath();
        $current = @file_get_contents($htaccessPath);
        if ($current === false) {
            throw new \RuntimeException(sprintf('Cannot read .htaccess at %s', $htaccessPath));
        }

        $content = $this->doctor->addUaRules($current, $uas);
        if ($content !== str_replace("\r\n", "\n", $current)) {
            $this->writeAtomic($content);
        }
    }

    /**
     * @return array<int, array{code: string, severity: string, title: string, detail: string, lines: int[], items: string[], fixable: bool}>
     */
    public function diagnose(): array
    {
        $content = @file_get_contents($this->getHtaccessPath());
        if ($content === false) {
            return [];
        }

        return $this->doctor->analyse($content, $this->readProtection());
    }

    public function repair(string $code): void
    {
        $htaccessPath = $this->getHtaccessPath();
        $current = @file_get_contents($htaccessPath);
        if ($current === false) {
            throw new \RuntimeException(sprintf('Cannot read .htaccess at %s', $htaccessPath));
        }

        $this->writeAtomic($this->doctor->repair($current, $code, $this->readProtection()));
    }

    /**
     * Dated copies written before each modification, newest first, with what a restore would change.
     *
     * @return array<int, array{name: string, date: string, size: int, removed: string[], restored: string[]}>
     */
    public function listBackups(int $limit = 20): array
    {
        $htaccessPath = $this->getHtaccessPath();
        $files = $this->backupFiles();

        $currentLines = $this->significantLines((string) @file_get_contents($htaccessPath));
        $result = [];
        foreach (array_slice($files, 0, $limit) as $file) {
            $lines = $this->significantLines((string) @file_get_contents($file));
            preg_match('/\.(\d{4}-\d{2}-\d{2})_(\d{2})-(\d{2})-(\d{2})(?:-\d+)?\.bak$/', $file, $m);
            $result[] = [
                'name' => basename($file),
                'date' => sprintf('%s %s:%s:%s', $m[1], $m[2], $m[3], $m[4]),
                'size' => (int) filesize($file),
                // Lines a restore would take out of the current file / put back
                'removed' => array_values(array_diff($currentLines, $lines)),
                'restored' => array_values(array_diff($lines, $currentLines)),
            ];
        }

        return $result;
    }

    public function countBackups(): int
    {
        return count($this->backupFiles());
    }

    /**
     * Deletes all backups but the $keep most recent ones.
     *
     * @return int number of deleted files
     */
    public function purgeBackups(int $keep): int
    {
        if ($keep < 1) {
            throw new \InvalidArgumentException('At least one backup must be kept.');
        }

        $deleted = 0;
        foreach (array_slice($this->backupFiles(), $keep) as $file) {
            if (@unlink($file)) {
                ++$deleted;
            }
        }

        return $deleted;
    }

    /**
     * Restores a backup. The current file is itself backed up first, so a restore can be undone.
     */
    public function restoreBackup(string $name): void
    {
        if (!$this->isBackupName($name)) {
            throw new \InvalidArgumentException(sprintf('Invalid backup name: %s', $name));
        }

        $path = dirname($this->getHtaccessPath()) . '/' . $name;
        $content = @file_get_contents($path);
        if ($content === false) {
            throw new \RuntimeException(sprintf('Backup not found: %s', $name));
        }

        $this->writeAtomic($content);
    }

    /**
     * Reads the options of the managed protection block.
     *
     * @return array{installed: bool, facet_referer: bool, facet_max_filters: int}
     */
    public function readProtection(): array
    {
        $state = ['installed' => false, 'facet_referer' => false, 'facet_max_filters' => 0];

        try {
            $content = file_get_contents($this->getHtaccessPath());
        } catch (\Throwable $e) {
            return $state;
        }

        if ($content === false || !preg_match(self::PROTECTION_PATTERN, $content, $block)) {
            return $state;
        }

        $state['installed'] = true;
        if (preg_match('/^' . preg_quote(self::PROTECTION_OPTIONS, '/') . ' (\{.*\})$/m', $block[0], $m)) {
            $options = json_decode($m[1], true);
            if (is_array($options)) {
                $state['facet_referer'] = (bool) ($options['facet_referer'] ?? false);
                $state['facet_max_filters'] = (int) ($options['facet_max_filters'] ?? 0);
            }
        }

        return $state;
    }

    /**
     * Writes (or replaces) the managed protection block at the top of .htaccess.
     *
     * @param string[] $domains shop hostnames allowed as facet referers
     * @param int $facetMaxFilters max filter groups in ?q= (0 = no limit)
     */
    public function applyProtection(array $domains, bool $facetReferer, int $facetMaxFilters): void
    {
        if (!$facetReferer && $facetMaxFilters === 0) {
            $this->removeProtection();

            return;
        }

        $block = $this->buildProtectionBlock($domains, $facetReferer, $facetMaxFilters);

        $htaccessPath = $this->getHtaccessPath();
        $current = @file_get_contents($htaccessPath);
        if ($current === false) {
            throw new \RuntimeException(sprintf('Cannot read .htaccess at %s', $htaccessPath));
        }

        if (preg_match(self::PROTECTION_PATTERN, $current)) {
            $content = preg_replace_callback(self::PROTECTION_PATTERN, fn () => $block, $current, 1);
        } else {
            // Top of file: must run before PrestaShop's front-controller rewrite
            $content = $block . "\n" . $current;
        }

        $this->writeAtomic((string) $content);
    }

    public function removeProtection(): void
    {
        $htaccessPath = $this->getHtaccessPath();
        $current = @file_get_contents($htaccessPath);
        if ($current === false) {
            throw new \RuntimeException(sprintf('Cannot read .htaccess at %s', $htaccessPath));
        }

        if (!preg_match(self::PROTECTION_PATTERN, $current, $m, PREG_OFFSET_CAPTURE)) {
            return;
        }

        $content = (string) preg_replace(self::PROTECTION_PATTERN, '', $current, 1);
        // Drop the separator line added by applyProtection() when prepending
        if ($m[0][1] === 0 && strpos($content, "\n") === 0) {
            $content = substr($content, 1);
        }

        $this->writeAtomic($content);
    }

    /**
     * @param string[] $domains
     */
    public function buildProtectionBlock(array $domains, bool $facetReferer, int $facetMaxFilters): string
    {
        if ($facetMaxFilters < 0 || $facetMaxFilters > self::FACET_MAX_FILTERS_LIMIT) {
            throw new \InvalidArgumentException(sprintf(
                'facet_max_filters must be between 0 and %d',
                self::FACET_MAX_FILTERS_LIMIT
            ));
        }

        $hosts = [];
        foreach ($domains as $domain) {
            $domain = strtolower(trim((string) $domain));
            if ($domain === '') {
                continue;
            }
            if (!preg_match('/^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$/', $domain)) {
                throw new \InvalidArgumentException(sprintf('Invalid domain: %s', $domain));
            }
            $hosts[$domain] = str_replace('.', '\.', $domain);
        }

        if ($facetReferer && $hosts === []) {
            // An empty whitelist would 403 every facet request, including real customers
            throw new \InvalidArgumentException('No shop domain: refusing to restrict facet referers');
        }

        $options = json_encode(['facet_referer' => $facetReferer, 'facet_max_filters' => $facetMaxFilters]);

        $lines = [
            self::PROTECTION_BEGIN,
            '# Managed by sc_alwaysdata (Back-office > Scriptami > Alwaysdata). Manual edits are overwritten.',
            self::PROTECTION_OPTIONS . ' ' . $options,
            '<IfModule mod_rewrite.c>',
            'RewriteEngine on',
        ];

        if ($facetReferer) {
            $lines[] = '# Facets (?q=) only when browsing from a shop page';
            $lines[] = 'RewriteCond %{QUERY_STRING} (^|&)q= [NC]';
            $lines[] = 'RewriteCond %{HTTP_REFERER} !^https?://(' . implode('|', $hosts) . ')(:\d+)?/ [NC]';
            $lines[] = 'RewriteRule .* - [F,L]';
        }

        if ($facetMaxFilters > 0) {
            // N groups are joined by N-1 slashes: N slashes means one group too many
            $lines[] = sprintf('# Facets: more than %d filter groups = crawler exploring combinations', $facetMaxFilters);
            $lines[] = 'RewriteCond %{QUERY_STRING} (^|&)q=[^&]*' . str_repeat('(/|%2F)[^&]*', $facetMaxFilters) . ' [NC]';
            $lines[] = 'RewriteRule .* - [F,L]';
        }

        $lines[] = '</IfModule>';
        $lines[] = self::PROTECTION_END;

        return implode("\n", $lines) . "\n";
    }

    public function readSnippet(int $maxLength = 3000): string
    {
        try {
            $content = file_get_contents($this->getHtaccessPath());

            return $content === false ? '' : substr($content, 0, $maxLength);
        } catch (\Throwable $e) {
            return '';
        }
    }

    private function isBackupName(string $name): bool
    {
        $base = preg_quote(basename($this->getHtaccessPath()), '/');

        return (bool) preg_match('/^' . $base . '\.\d{4}-\d{2}-\d{2}_\d{2}-\d{2}-\d{2}(-\d+)?\.bak$/', $name);
    }

    /**
     * Backup files of the configured .htaccess, newest first.
     *
     * @return string[]
     */
    private function backupFiles(): array
    {
        $files = [];
        foreach (glob($this->getHtaccessPath() . '.*.bak') ?: [] as $file) {
            if ($this->isBackupName(basename($file))) {
                $files[] = $file;
            }
        }
        // Names sort chronologically (Y-m-d_H-i-s, then -N suffix for same-second writes)
        usort($files, fn (string $a, string $b) => $this->backupSortKey($b) <=> $this->backupSortKey($a));

        return $files;
    }

    private function backupSortKey(string $file): string
    {
        preg_match('/\.(\d{4}-\d{2}-\d{2}_\d{2}-\d{2}-\d{2})(?:-(\d+))?\.bak$/', $file, $m);

        return $m[1] . sprintf('%05d', (int) ($m[2] ?? 0));
    }

    /**
     * @return string[]
     */
    private function significantLines(string $content): array
    {
        $lines = array_map('trim', explode("\n", str_replace("\r\n", "\n", $content)));

        return array_values(array_filter($lines, static fn (string $l) => $l !== ''));
    }

    private function getHtaccessPath(): string
    {
        return (string) \Configuration::get('SC_ALWAYSDATA_HTACCESS_PATH');
    }

    private function writeAtomic(string $content): void
    {
        $htaccessPath = $this->getHtaccessPath();
        $tmp = $htaccessPath . '.tmp';
        $backupPath = null;

        try {
            // Archive the current version before overwriting
            if (file_exists($htaccessPath)) {
                // Unique name: two writes in the same second must not overwrite the undo point
                $stamp = $htaccessPath . '.' . date('Y-m-d_H-i-s');
                $backupPath = $stamp . '.bak';
                for ($n = 2; file_exists($backupPath); ++$n) {
                    $backupPath = $stamp . '-' . $n . '.bak';
                }
                if (!copy($htaccessPath, $backupPath)) {
                    throw new \RuntimeException(sprintf('Failed to create backup: %s', $backupPath));
                }
            }

            $result = file_put_contents($tmp, $content);
            if ($result === false) {
                throw new \RuntimeException(sprintf('Failed to write temporary file: %s', $tmp));
            }

            if (!rename($tmp, $htaccessPath)) {
                throw new \RuntimeException(sprintf('Failed to rename %s to %s', $tmp, $htaccessPath));
            }

            // Validate Apache syntax — restore backup if invalid
            $syntaxError = $this->validateApacheSyntax();
            if ($syntaxError !== null) {
                if ($backupPath !== null && file_exists($backupPath)) {
                    copy($backupPath, $htaccessPath);
                    throw new \RuntimeException(sprintf(
                        "Syntaxe Apache invalide — backup restaur\u00e9 :\n%s",
                        $syntaxError
                    ));
                }
                throw new \RuntimeException(sprintf("Syntaxe Apache invalide :\n%s", $syntaxError));
            }
        } catch (\Throwable $e) {
            @unlink($tmp);
            throw new \RuntimeException(sprintf('Atomic write failed: %s', $e->getMessage()));
        }
    }

    /**
     * Runs `apachectl -t` to check .htaccess syntax.
     * Returns the error output if invalid, null if valid or if apachectl is not available.
     */
    private function validateApacheSyntax(): ?string
    {
        foreach (['apachectl', 'apache2ctl'] as $cmd) {
            $which = @shell_exec('which ' . escapeshellarg($cmd) . ' 2>/dev/null');
            if ($which === null || trim($which) === '') {
                continue;
            }

            $output = [];
            $exitCode = 0;
            exec(escapeshellcmd($cmd) . ' -t 2>&1', $output, $exitCode);

            return $exitCode === 0 ? null : implode("\n", $output);
        }

        // apachectl not found — skip validation silently
        return null;
    }
}

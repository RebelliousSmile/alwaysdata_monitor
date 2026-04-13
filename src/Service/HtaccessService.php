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
        $ua = str_replace(['"', '\\'], '', $ua);

        $htaccessPath = $this->getHtaccessPath();
        $current = @file_get_contents($htaccessPath);
        if ($current === false) {
            throw new \RuntimeException(sprintf('Cannot read .htaccess at %s', $htaccessPath));
        }

        $q = preg_quote($ua, '/');

        // Remove module-written block (comment + RewriteCond + RewriteRule)
        $content = preg_replace(
            '/\n?# sc_alwaysdata block UA: ' . $q . '\nRewriteCond %\{HTTP_USER_AGENT\} "' . $q . '" \[NC\]\nRewriteRule \.\* - \[F,L\]\n?/',
            "\n",
            $current
        );

        // Remove loose RewriteCond (quoted) + following RewriteRule
        $content = preg_replace(
            '/\nRewriteCond %\{HTTP_USER_AGENT\} "' . $q . '" \[NC\]\nRewriteRule \.\* - \[F,L\]\n?/i',
            "\n",
            $content ?? $current
        );

        // Remove loose RewriteCond (unquoted) + following RewriteRule
        $content = preg_replace(
            '/\nRewriteCond %\{HTTP_USER_AGENT\} ' . $q . ' \[NC\]\nRewriteRule \.\* - \[F,L\]\n?/i',
            "\n",
            $content ?? $current
        );

        // Remove SetEnvIfNoCase lines (quoted or unquoted)
        $content = preg_replace(
            '/\nSetEnvIfNoCase User-Agent "?' . $q . '"?[^\n]*\n/i',
            "\n",
            $content ?? $current
        );

        $this->writeAtomic($content ?? $current);
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
        $ua = str_replace(['"', '\\'], '', $ua);

        $htaccessPath = $this->getHtaccessPath();
        $current = @file_get_contents($htaccessPath);
        if ($current === false) {
            throw new \RuntimeException(sprintf('Cannot read .htaccess at %s', $htaccessPath));
        }

        $rule = "\n# sc_alwaysdata block UA: {$ua}\n"
            . "RewriteCond %{HTTP_USER_AGENT} \"{$ua}\" [NC]\n"
            . "RewriteRule .* - [F,L]\n";

        // Prefer inserting inside an existing <IfModule mod_rewrite.c> block so that
        // RewriteEngine is guaranteed to be active for our rules.
        $openPos = stripos($current, '<IfModule mod_rewrite.c>');
        if ($openPos !== false) {
            $closePos = stripos($current, '</IfModule>', $openPos);
            if ($closePos !== false) {
                $content = substr($current, 0, $closePos) . $rule . substr($current, $closePos);
                $this->writeAtomic($content);

                return;
            }
        }

        // Fallback: wrap in its own IfModule block and append
        $wrapped = "\n<IfModule mod_rewrite.c>\nRewriteEngine On" . $rule . "</IfModule>\n";
        $this->writeAtomic($current . $wrapped);
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
                $backupPath = $htaccessPath . '.' . date('Y-m-d_H-i-s') . '.bak';
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

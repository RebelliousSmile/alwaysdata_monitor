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

/**
 * Manages a delimited block at the end of robots.txt.
 *
 * Settings live in Configuration, not in the file: PrestaShop's "Generate robots.txt"
 * truncates the file, and the module re-appends the block from the
 * actionAdminMetaAfterWriteRobotsFile hook using these settings.
 */
class RobotsTxtService
{
    public const CONFIG_KEY = 'SC_ALWAYSDATA_ROBOTS';

    /** Listing parameters that multiply crawlable URLs (facets, sort, pagination size, view). */
    public const DEFAULT_DISALLOW = [
        '/*?q=',
        '/*&q=',
        '/*?order=',
        '/*&order=',
        '/*resultsPerPage=',
        '/*productListView=',
    ];

    /** SEO/AI crawlers with no commercial value for the shop that do honour robots.txt. */
    public const DEFAULT_BOTS = [
        'AhrefsBot',
        'SemrushBot',
        'DotBot',
        'MJ12bot',
        'DataForSeoBot',
        'BLEXBot',
        'Barkrowler',
        'PetalBot',
        'Baiduspider',
        'CCBot',
    ];

    private const BLOCK_BEGIN = '# BEGIN sc_alwaysdata robots';
    private const BLOCK_END = '# END sc_alwaysdata robots';
    private const BLOCK_PATTERN = '/\n*^# BEGIN sc_alwaysdata robots\n.*?^# END sc_alwaysdata robots\n?/ms';

    /**
     * @return array{configured: bool, enabled: bool, disallow: string[], bots: string[], in_file: bool}
     */
    public function readSettings(): array
    {
        $stored = json_decode((string) \Configuration::get(self::CONFIG_KEY), true);
        $configured = is_array($stored);

        $content = $this->readFile();

        return [
            'configured' => $configured,
            'enabled' => $configured && (bool) ($stored['enabled'] ?? false),
            'disallow' => $configured ? array_values((array) ($stored['disallow'] ?? [])) : self::DEFAULT_DISALLOW,
            'bots' => $configured ? array_values((array) ($stored['bots'] ?? [])) : self::DEFAULT_BOTS,
            'in_file' => $content !== null && preg_match(self::BLOCK_PATTERN, $content) === 1,
        ];
    }

    /**
     * Validates, stores the settings, then rewrites the block in robots.txt.
     *
     * @param string[] $disallow
     * @param string[] $bots
     */
    public function saveAndApply(bool $enabled, array $disallow, array $bots): void
    {
        $disallow = $this->normalizeDisallow($disallow);
        $bots = $this->normalizeBots($bots);

        \Configuration::updateValue(self::CONFIG_KEY, json_encode([
            'enabled' => $enabled,
            'disallow' => $disallow,
            'bots' => $bots,
        ]));

        $current = $this->readFile();
        if ($current === null) {
            throw new \RuntimeException(sprintf('Cannot read robots.txt at %s', $this->getRobotsPath()));
        }

        $content = (string) preg_replace(self::BLOCK_PATTERN, '', $current);
        if ($content !== '' && substr($content, -1) !== "\n") {
            // The pattern eats the newlines before the block, including the last line's
            $content .= "\n";
        }
        $block = $enabled ? $this->buildBlock($disallow, $bots) : '';
        if ($block !== '') {
            $content = rtrim($content, "\n") . "\n\n" . $block;
        }

        if ($content !== $current) {
            $this->writeAtomic($content);
        }
    }

    /**
     * Adds bots to the "Disallow: /" list and turns the block on, keeping the
     * current Disallow paths (the suggested defaults when never configured).
     *
     * @param string[] $bots
     */
    public function addBots(array $bots): void
    {
        $settings = $this->readSettings();
        $this->saveAndApply(true, $settings['disallow'], array_merge($settings['bots'], $bots));
    }

    /**
     * Block built from stored settings, '' when disabled. Used by the regeneration hook.
     */
    public function buildConfiguredBlock(): string
    {
        $settings = $this->readSettings();

        return $settings['enabled'] ? $this->buildBlock($settings['disallow'], $settings['bots']) : '';
    }

    /**
     * @param string[] $disallow
     * @param string[] $bots
     */
    public function buildBlock(array $disallow, array $bots): string
    {
        if ($disallow === [] && $bots === []) {
            return '';
        }

        $lines = [
            self::BLOCK_BEGIN,
            '# Managed by sc_alwaysdata (Back-office > Scriptami > Alwaysdata). Manual edits are overwritten.',
        ];

        if ($disallow !== []) {
            // Crawlers merge every group matching their user-agent (RFC 9309 §2.2.1)
            $lines[] = 'User-agent: *';
            foreach ($disallow as $path) {
                $lines[] = 'Disallow: ' . $path;
            }
        }

        foreach ($bots as $bot) {
            $lines[] = '';
            $lines[] = 'User-agent: ' . $bot;
            $lines[] = 'Disallow: /';
        }

        $lines[] = self::BLOCK_END;

        return implode("\n", $lines) . "\n";
    }

    public function getRobotsPath(): string
    {
        // robots.txt sits next to PrestaShop's .htaccess, in the shop root
        return dirname((string) \Configuration::get('SC_ALWAYSDATA_HTACCESS_PATH')) . '/robots.txt';
    }

    /**
     * @param string[] $paths
     *
     * @return string[]
     */
    private function normalizeDisallow(array $paths): array
    {
        $result = [];
        foreach ($paths as $path) {
            $path = trim((string) $path);
            if ($path === '') {
                continue;
            }
            if (!preg_match('#^[/*][\x21-\x7E]*$#', $path)) {
                throw new \InvalidArgumentException(sprintf('Invalid Disallow path (must start with / or *, no spaces): %s', $path));
            }
            $result[$path] = true;
        }

        return array_keys($result);
    }

    /**
     * @param string[] $bots
     *
     * @return string[]
     */
    private function normalizeBots(array $bots): array
    {
        $result = [];
        foreach ($bots as $bot) {
            $bot = trim((string) $bot);
            if ($bot === '') {
                continue;
            }
            if ($bot === '*' || !preg_match('/^[A-Za-z0-9._-]+$/', $bot)) {
                throw new \InvalidArgumentException(sprintf('Invalid user-agent token: %s', $bot));
            }
            $result[strtolower($bot)] ??= $bot;
        }

        return array_values($result);
    }

    private function readFile(): ?string
    {
        $path = $this->getRobotsPath();
        if (!is_file($path)) {
            return null;
        }

        $content = @file_get_contents($path);

        return $content === false ? null : str_replace("\r\n", "\n", $content);
    }

    private function writeAtomic(string $content): void
    {
        $path = $this->getRobotsPath();
        $tmp = $path . '.tmp';

        try {
            $backupPath = $path . '.' . date('Y-m-d_H-i-s') . '.bak';
            if (!copy($path, $backupPath)) {
                throw new \RuntimeException(sprintf('Failed to create backup: %s', $backupPath));
            }
            if (file_put_contents($tmp, $content) === false) {
                throw new \RuntimeException(sprintf('Failed to write temporary file: %s', $tmp));
            }
            if (!rename($tmp, $path)) {
                throw new \RuntimeException(sprintf('Failed to rename %s to %s', $tmp, $path));
            }
        } catch (\Throwable $e) {
            @unlink($tmp);
            throw new \RuntimeException(sprintf('Atomic write failed: %s', $e->getMessage()));
        }
    }
}

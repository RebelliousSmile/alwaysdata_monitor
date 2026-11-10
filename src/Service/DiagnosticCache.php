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
 * Disk cache for the load diagnostic, with one lock per entry.
 *
 * - A closed day's log no longer changes: its entry is valid as long as the
 *   signature (path, size, mtime) matches.
 * - The current day's log grows all the time, so its signature never matches
 *   twice: its entry is valid for a short TTL instead, whatever the signature.
 * - Computing an entry takes an exclusive non-blocking lock. A second request
 *   for the same entry gets DiagnosticBusyException (HTTP 409) instead of
 *   starting another pass over the log on another worker.
 */
class DiagnosticCache
{
    public const TODAY_TTL = 300;
    public const PURGE_AFTER_DAYS = 30;

    private string $dir;
    /** @var callable(): int */
    private $clock;

    /**
     * @param callable(): int|null $clock returns the current Unix time (injected by tests)
     */
    public function __construct(string $dir, ?callable $clock = null)
    {
        $this->dir = rtrim($dir, '/\\') . '/';
        $this->clock = $clock ?? 'time';
    }

    /**
     * @param string $key file-safe name of the entry
     * @param bool $isToday true when the log is still being written
     * @param callable(): array<mixed> $compute produces the value on a miss
     *
     * @return array<mixed>
     *
     * @throws DiagnosticBusyException when another request is computing the same entry
     */
    public function remember(string $key, string $signature, bool $isToday, callable $compute): array
    {
        if (!preg_match('/^[A-Za-z0-9._-]+$/', $key)) {
            throw new \InvalidArgumentException('Invalid cache key: ' . $key);
        }

        $file = $this->dir . $key . '.json';
        $hit = $this->read($file, $signature, $isToday);
        if ($hit !== null) {
            return $hit;
        }

        $this->ensureDir();
        $lock = @fopen($this->dir . $key . '.lock', 'c');
        if ($lock === false) {
            // Without a lock file the request still answers, it just is not serialised
            return $compute();
        }

        try {
            if (!flock($lock, LOCK_EX | LOCK_NB)) {
                throw new DiagnosticBusyException('Diagnostic already running for ' . $key);
            }

            // The request holding the lock before us may have filled the entry
            $hit = $this->read($file, $signature, $isToday);
            if ($hit !== null) {
                return $hit;
            }

            $value = $compute();
            $payload = json_encode(['signature' => $signature, 'created' => ($this->clock)(), 'value' => $value]);
            if ($payload === false || @file_put_contents($file, $payload, LOCK_EX) === false) {
                $this->log('[sc_alwaysdata] Diagnostic cache write failed: ' . $file);
            }

            return $value;
        } finally {
            flock($lock, LOCK_UN);
            fclose($lock);
        }
    }

    /**
     * Deletes entries and lock files older than PURGE_AFTER_DAYS.
     *
     * @return int number of files removed
     */
    public function purge(): int
    {
        $limit = ($this->clock)() - self::PURGE_AFTER_DAYS * 86400;
        $removed = 0;
        // Two patterns rather than GLOB_BRACE, which some libc builds lack
        $files = array_merge(glob($this->dir . '*.json') ?: [], glob($this->dir . '*.lock') ?: []);
        foreach ($files as $file) {
            $mtime = @filemtime($file);
            if ($mtime !== false && $mtime < $limit && @unlink($file)) {
                ++$removed;
            }
        }

        return $removed;
    }

    /**
     * @return array<mixed>|null
     */
    private function read(string $file, string $signature, bool $isToday): ?array
    {
        if (!is_readable($file)) {
            return null;
        }
        $cached = json_decode((string) @file_get_contents($file), true);
        if (!is_array($cached) || !is_array($cached['value'] ?? null)) {
            return null;
        }

        if ($isToday) {
            $age = ($this->clock)() - (int) ($cached['created'] ?? 0);

            return $age >= 0 && $age < self::TODAY_TTL ? $cached['value'] : null;
        }

        return ($cached['signature'] ?? null) === $signature ? $cached['value'] : null;
    }

    private function ensureDir(): void
    {
        if (!is_dir($this->dir) && !@mkdir($this->dir, 0755, true) && !is_dir($this->dir)) {
            $this->log('[sc_alwaysdata] Cannot create diagnostic cache directory: ' . $this->dir);
        }
    }

    private function log(string $message): void
    {
        if (class_exists('PrestaShopLogger')) {
            \PrestaShopLogger::addLog($message, 2, null, 'sc_alwaysdata');
        }
    }
}

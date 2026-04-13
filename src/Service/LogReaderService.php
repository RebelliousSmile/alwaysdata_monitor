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

class LogReaderService
{
    private const DEFAULT_LINES = [
        'apache' => 5000,
        'http'   => 10000,
        'php'    => 5000,
        'sites'  => 2000,
    ];
    private const LOG_DIRS = ['apache', 'http', 'php', 'sites'];

    private function getLinesForDir(string $dir): int
    {
        $key = 'SC_ALWAYSDATA_LINES_' . strtoupper($dir);
        $v = (int) \Configuration::get($key);
        return $v > 0 ? $v : (self::DEFAULT_LINES[$dir] ?? 5000);
    }

    /**
     * Resolve the absolute path of the HTTP log file for a given date (J-1 typically).
     * Tries plain .log first, then .log.gz. Returns null if not found.
     */
    public function findHttpLogPath(string $date): ?string
    {
        $basePath = $this->resolveBasePath();
        if ($basePath === null) {
            return null;
        }

        $year = substr($date, 0, 4);
        $base = $basePath . 'http/' . $year . '/http-' . $date;

        if (is_readable($base . '.log')) {
            return $base . '.log';
        }

        if (is_readable($base . '.log.gz')) {
            return $base . '.log.gz';
        }

        return null;
    }

    public function readTodayLogs(): array
    {
        set_time_limit(60);

        $basePath = $this->resolveBasePath();

        if ($basePath === null) {
            return [
                [
                    'source' => 'base',
                    'lines' => [],
                    'truncated' => false,
                    'error' => 'No readable log base path found (check configuration)',
                ],
            ];
        }

        $results = [];
        foreach (self::LOG_DIRS as $dir) {
            $results[] = $this->readSource($basePath, $dir);
        }

        return $results;
    }

    /**
     * Resolve the first readable logs base path from configured value + common Alwaysdata candidates.
     */
    private function resolveBasePath(): ?string
    {
        $configured = rtrim((string) \Configuration::get('SC_ALWAYSDATA_LOGS_PATH'), '/') . '/';
        $home = $_SERVER['HOME'] ?? '';

        $candidates = array_unique(array_filter([
            $configured !== '/' ? $configured : null,
            $home !== '' ? rtrim($home, '/') . '/admin/logs/' : null,
            '/home/admin/logs/',
            '/home/logs/',
            '/admin/logs/',
        ]));

        foreach ($candidates as $path) {
            if (is_dir($path) && is_readable($path)) {
                return $path;
            }
        }

        return null;
    }

    private function readSource(string $basePath, string $dir): array
    {
        try {
            $dirPath = $basePath . $dir . '/';

            if (!is_readable($dirPath)) {
                return [
                    'source' => $dir,
                    'lines' => [],
                    'truncated' => false,
                    'error' => 'Directory not readable: ' . $dirPath,
                ];
            }

            $today = date('Y-m-d');
            $file = $this->findTodayFile($dirPath, $today);

            if ($file === null) {
                $file = $this->findMostRecentFile($dirPath);
            }

            if ($file === null) {
                return [
                    'source' => $dir,
                    'lines' => [],
                    'truncated' => false,
                    'error' => 'No log file found',
                ];
            }

            $lines = $this->tailFile($file, $this->getLinesForDir($dir));

            return [
                'source' => $dir,
                'lines' => $lines,
                'truncated' => false,
                'error' => null,
                'max_lines' => $this->getLinesForDir($dir),
            ];
        } catch (\Throwable $e) {
            return [
                'source' => $dir,
                'lines' => [],
                'truncated' => false,
                'error' => $e->getMessage(),
            ];
        }
    }

    /**
     * Recursively search for a file whose name contains today's date.
     */
    private function findTodayFile(string $dirPath, string $today): ?string
    {
        $entries = glob($dirPath . '*') ?: [];
        foreach ($entries as $entry) {
            if (is_file($entry) && strpos(basename($entry), $today) !== false) {
                return $entry;
            }
            if (is_dir($entry) && is_readable($entry)) {
                $found = $this->findTodayFile($entry . '/', $today);
                if ($found !== null) {
                    return $found;
                }
            }
        }

        return null;
    }

    /**
     * Recursively find the most recently modified file in a directory tree.
     */
    private function findMostRecentFile(string $dirPath): ?string
    {
        $allFiles = $this->collectAllFiles($dirPath);
        if (empty($allFiles)) {
            return null;
        }

        usort($allFiles, function (string $a, string $b): int {
            return (int) filemtime($b) - (int) filemtime($a);
        });

        return $allFiles[0];
    }

    /**
     * Collect all files recursively under a directory.
     */
    private function collectAllFiles(string $dirPath): array
    {
        $files = [];
        $entries = glob($dirPath . '*') ?: [];
        foreach ($entries as $entry) {
            if (is_file($entry)) {
                $files[] = $entry;
            } elseif (is_dir($entry) && is_readable($entry)) {
                $files = array_merge($files, $this->collectAllFiles($entry . '/'));
            }
        }

        return $files;
    }

    private function tailFile(string $filePath, int $maxLines): array
    {
        $fh = fopen($filePath, 'rb');
        if ($fh === false) {
            return [];
        }

        try {
            fseek($fh, 0, SEEK_END);
            $fileSize = ftell($fh);
            $chunkSize = 8192;
            $buffer = '';
            $pos = $fileSize;
            $lines = [];

            while (count($lines) <= $maxLines && $pos > 0) {
                $readSize = min($chunkSize, $pos);
                $pos -= $readSize;
                fseek($fh, $pos);
                $buffer = fread($fh, $readSize) . $buffer;
                $lines = explode("\n", $buffer);
            }

            $lines = array_filter($lines, fn ($l) => $l !== '');

            return array_slice(array_values($lines), -$maxLines);
        } finally {
            fclose($fh);
        }
    }
}

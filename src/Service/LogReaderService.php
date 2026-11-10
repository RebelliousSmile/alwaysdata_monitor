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
    /** Log folders read under the base path, in display order, with their default line count. */
    public const DEFAULT_LINES = [
        'apache' => 5000,
        'http' => 10000,
        'php' => 5000,
        'jobs' => 2000,
        'sites' => 2000,
    ];
    public const LOG_DIRS = ['apache', 'http', 'php', 'jobs', 'sites'];

    private const PHP_MONTHS = [
        'Jan' => '01', 'Feb' => '02', 'Mar' => '03', 'Apr' => '04', 'May' => '05', 'Jun' => '06',
        'Jul' => '07', 'Aug' => '08', 'Sep' => '09', 'Oct' => '10', 'Nov' => '11', 'Dec' => '12',
    ];

    /**
     * Hard cap on how many bytes tailFile() may walk back through, whatever the
     * requested line count. Without it, a file containing no newline (a gzip
     * archive opened as plain text) is read entirely into memory.
     */
    private const MAX_TAIL_BYTES = 33554432; // 32 MiB

    public const MIN_LINES = 100;
    /** Upper bound of SC_ALWAYSDATA_LINES_*: tailFileGz keeps up to twice this many lines in memory. */
    public const MAX_LINES = 50000;

    /**
     * Bounds a configured line count to [MIN_LINES, MAX_LINES].
     */
    public static function clampLines(int $lines): int
    {
        return min(self::MAX_LINES, max(self::MIN_LINES, $lines));
    }

    /**
     * Validates a logs base path before it is stored or used: it must resolve to
     * an existing readable directory holding at least one of the Alwaysdata log
     * folders (LOG_DIRS). Returns the path with a trailing
     * slash, or null when the path is refused.
     */
    public static function normalizeBasePath(string $path): ?string
    {
        $path = trim($path);
        if ($path === '' || strpos($path, "\0") !== false) {
            return null;
        }

        $real = realpath($path);
        if ($real === false || !is_dir($real) || !is_readable($real)) {
            return null;
        }

        foreach (self::LOG_DIRS as $dir) {
            if (is_dir($real . DIRECTORY_SEPARATOR . $dir)) {
                // The path as typed, not its realpath: the stored value stays recognisable
                return rtrim($path, '/\\') . '/';
            }
        }

        return null;
    }

    private function getLinesForDir(string $dir): int
    {
        $key = 'SC_ALWAYSDATA_LINES_' . strtoupper($dir);
        $v = (int) \Configuration::get($key);

        // Upper bound only: the lower one is a form constraint, a smaller stored value stays honoured
        return $v > 0 ? min($v, self::MAX_LINES) : (self::DEFAULT_LINES[$dir] ?? 5000);
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

    /**
     * Lit le fichier de log PHP d'une date donnée et retourne un "source"
     * exploitable par PhpErrorAnalyserService::analyse().
     *
     * A file whose name carries the date is read as is. Otherwise the undated
     * files (Alwaysdata writes a single php/php.log) are filtered on the date
     * that opens each entry, "[10-Nov-2026 08:53:33 Europe/Paris]".
     *
     * @return array{source: string, lines: array<int, string>, truncated: bool, error: string|null}
     */
    public function readPhpLogForDate(string $date): array
    {
        $basePath = $this->resolveBasePath();
        if ($basePath === null) {
            return ['source' => 'php', 'lines' => [], 'truncated' => false, 'error' => 'No readable log base path'];
        }

        $phpDir = $basePath . 'php/';
        if (!is_readable($phpDir)) {
            return ['source' => 'php', 'lines' => [], 'truncated' => false, 'error' => 'PHP log directory not readable: ' . $phpDir];
        }

        try {
            $maxLines = $this->getLinesForDir('php');

            $file = $this->findTodayFile($phpDir, $date);
            if ($file !== null) {
                return [
                    'source' => 'php',
                    'lines' => $this->readLogLines($file, $maxLines),
                    'truncated' => false,
                    'error' => null,
                    'max_lines' => $maxLines,
                ];
            }

            $start = strtotime($date . ' 00:00:00');
            if (!preg_match('/^\d{4}-\d{2}-\d{2}$/', $date) || $start === false) {
                return ['source' => 'php', 'lines' => [], 'truncated' => false, 'error' => 'Invalid date: ' . $date];
            }

            // A file last written before the day began holds none of its entries;
            // oldest first so that a rotated file comes before the current one
            $files = array_values(array_filter(
                $this->collectAllFiles($phpDir),
                fn (string $f): bool => (int) @filemtime($f) >= $start
            ));
            if ($files === []) {
                return ['source' => 'php', 'lines' => [], 'truncated' => false, 'error' => 'No PHP log file found for ' . $date];
            }
            usort($files, fn (string $a, string $b): int => (int) filemtime($a) - (int) filemtime($b));

            $lines = [];
            $truncated = false;
            foreach ($files as $f) {
                $this->appendLinesOfDate($f, $date, $maxLines, $lines, $truncated);
            }

            return [
                'source' => 'php',
                'lines' => $lines,
                'truncated' => $truncated,
                'error' => null,
                'max_lines' => $maxLines,
            ];
        } catch (\Throwable $e) {
            return ['source' => 'php', 'lines' => [], 'truncated' => false, 'error' => $e->getMessage()];
        }
    }

    /**
     * Streams a PHP error log (plain or gzip) and appends the entries dated
     * $date to $lines, keeping the last $maxLines. A line that does not open
     * with a date (stack trace) belongs to the entry above it. Reading stops
     * at the first entry of a later day, the log being chronological.
     *
     * @param array<int, string> $lines
     */
    private function appendLinesOfDate(string $file, string $date, int $maxLines, array &$lines, bool &$truncated): void
    {
        // gzopen reads uncompressed files too
        $fh = @gzopen($file, 'rb');
        if ($fh === false) {
            return;
        }

        try {
            $inDay = false;
            $lastDay = '';
            $lastCmp = 0;
            while (($line = gzgets($fh)) !== false) {
                if (preg_match('/^\[(\d{2})-([A-Z][a-z]{2})-(\d{4}) /', $line, $m)) {
                    $day = $m[3] . '-' . (self::PHP_MONTHS[$m[2]] ?? '00') . '-' . $m[1];
                    if ($day !== $lastDay) {
                        $lastDay = $day;
                        $lastCmp = strcmp($day, $date);
                    }
                    if ($lastCmp > 0) {
                        break;
                    }
                    $inDay = $lastCmp === 0;
                }
                if (!$inDay) {
                    continue;
                }

                $lines[] = rtrim($line, "\r\n");
                if (count($lines) >= $maxLines * 2) {
                    $lines = array_slice($lines, -$maxLines);
                    $truncated = true;
                }
            }

            if (count($lines) > $maxLines) {
                $lines = array_slice($lines, -$maxLines);
                $truncated = true;
            }
        } finally {
            gzclose($fh);
        }
    }

    /**
     * Lit un fichier texte ou gzip (dernier maxLines) et retourne les lignes.
     *
     * @return array<int, string>
     */
    private function readLogLines(string $filePath, int $maxLines): array
    {
        if (substr($filePath, -3) === '.gz') {
            return $this->tailFileGz($filePath, $maxLines);
        }

        return $this->tailFile($filePath, $maxLines);
    }

    /**
     * @return array<int, string>
     */
    private function tailFileGz(string $filePath, int $maxLines): array
    {
        $fh = gzopen($filePath, 'rb');
        if ($fh === false) {
            return [];
        }

        try {
            // Sliding window: never hold more than 2 * $maxLines lines in memory,
            // whatever the uncompressed size of the archive. Compacting in batches
            // avoids the O(n) cost of array_shift() on every single line.
            $lines = [];
            while (!gzeof($fh)) {
                $line = gzgets($fh);
                if ($line === false) {
                    continue;
                }
                $lines[] = rtrim($line, "\r\n");
                if (count($lines) >= $maxLines * 2) {
                    $lines = array_slice($lines, -$maxLines);
                }
            }

            return array_slice($lines, -$maxLines);
        } finally {
            gzclose($fh);
        }
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

        // A stored value saved before 1.11.4 was never validated: it goes through the same check
        foreach ($candidates as $path) {
            $valid = self::normalizeBasePath($path);
            if ($valid !== null) {
                return $valid;
            }
        }

        return null;
    }

    private function readSource(string $basePath, string $dir): array
    {
        try {
            $dirPath = $basePath . $dir . '/';

            // A folder Alwaysdata did not create (no scheduled task, no site log) is shown like an empty one
            if (!is_dir($dirPath)) {
                return ['source' => $dir, 'lines' => [], 'truncated' => false, 'error' => null, 'empty' => true];
            }

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
                // An empty folder is a normal state (sites/ on most accounts), not an error
                return [
                    'source' => $dir,
                    'lines' => [],
                    'truncated' => false,
                    'error' => null,
                    'empty' => true,
                ];
            }

            $maxLines = $this->getLinesForDir($dir);
            $lines = $this->readLogLines($file, $maxLines);

            return [
                'source' => $dir,
                'lines' => $lines,
                'truncated' => count($lines) >= $maxLines,
                'error' => null,
                'max_lines' => $maxLines,
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
            $chunkSize = 65536;
            $pos = $fileSize;
            $chunks = [];
            $newlines = 0;
            $bytesRead = 0;
            $maxBytes = self::MAX_TAIL_BYTES;

            // Walk backwards, counting newlines per chunk instead of re-splitting a
            // growing buffer on every iteration (which was quadratic). The byte cap
            // guarantees we stop even on a file that holds no newline at all —
            // a gzip archive read as plain text, for instance.
            while ($newlines <= $maxLines && $pos > 0 && $bytesRead < $maxBytes) {
                $readSize = (int) min($chunkSize, $pos, $maxBytes - $bytesRead);
                $pos -= $readSize;
                fseek($fh, $pos);
                $chunk = fread($fh, $readSize);
                if ($chunk === false) {
                    break;
                }
                array_unshift($chunks, $chunk);
                $newlines += substr_count($chunk, "\n");
                $bytesRead += $readSize;
            }

            $lines = explode("\n", implode('', $chunks));
            $lines = array_filter($lines, fn ($l) => $l !== '');

            return array_slice(array_values($lines), -$maxLines);
        } finally {
            fclose($fh);
        }
    }
}

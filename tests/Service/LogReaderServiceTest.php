<?php

declare(strict_types=1);

namespace ScAlwaysdata\Tests\Service;

use PHPUnit\Framework\TestCase;
use ScAlwaysdata\Service\LogReaderService;

class LogReaderServiceTest extends TestCase
{
    private string $tmpBase = '';
    private string|false $originalHome;

    protected function setUp(): void
    {
        // Neutralise the HOME-based fallback candidate so only SC_ALWAYSDATA_LOGS_PATH matters.
        $this->originalHome = $_SERVER['HOME'] ?? false;
        unset($_SERVER['HOME']);

        \Configuration::$testValues = [];
    }

    protected function tearDown(): void
    {
        // Restore HOME.
        if ($this->originalHome !== false) {
            $_SERVER['HOME'] = $this->originalHome;
        }

        \Configuration::$testValues = [];

        // Clean up any temp tree created during the test.
        if ($this->tmpBase !== '' && is_dir($this->tmpBase)) {
            $this->removeDirRecursive($this->tmpBase);
        }

        $this->tmpBase = '';
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    /**
     * Create a temp base directory and point SC_ALWAYSDATA_LOGS_PATH to it.
     * Returns the base path WITHOUT trailing slash (resolveBasePath will add it).
     */
    private function createTmpBase(): string
    {
        $path = sys_get_temp_dir() . '/sc_alwaysdata_test_' . uniqid('', true);
        mkdir($path, 0755, true);
        $this->tmpBase = $path;
        \Configuration::$testValues['SC_ALWAYSDATA_LOGS_PATH'] = $path;
        return $path;
    }

    /**
     * Create a directory (including parents) relative to the base path.
     */
    private function mkdirUnder(string $basePath, string $relative): string
    {
        $full = $basePath . '/' . $relative;
        mkdir($full, 0755, true);
        return $full;
    }

    /**
     * Create an empty file at $path.
     */
    private function touch(string $path): void
    {
        file_put_contents($path, '');
    }

    private function removeDirRecursive(string $dir): void
    {
        $items = array_diff(scandir($dir) ?: [], ['.', '..']);
        foreach ($items as $item) {
            $full = $dir . '/' . $item;
            is_dir($full) ? $this->removeDirRecursive($full) : unlink($full);
        }
        rmdir($dir);
    }

    private function service(): LogReaderService
    {
        return new LogReaderService();
    }

    // -------------------------------------------------------------------------
    // Case 1 — resolveBasePath() returns null (no configured / accessible dir)
    // -------------------------------------------------------------------------

    public function testReturnsNullWhenBasePathCannotBeResolved(): void
    {
        // No SC_ALWAYSDATA_LOGS_PATH set and HOME is already unset → no candidate resolves.
        // Also make sure the hard-coded candidates do not exist on CI.
        // We rely on the fact that /home/admin/logs/, /home/logs/, /admin/logs/ are
        // very unlikely to exist in the test environment.  If they do, skip gracefully.
        if (
            is_dir('/home/admin/logs/')
            || is_dir('/home/logs/')
            || is_dir('/admin/logs/')
        ) {
            $this->markTestSkipped('System has one of the hard-coded fallback paths — cannot isolate this case.');
        }

        $result = $this->service()->findHttpLogPath('2025-03-15');

        $this->assertNull($result);
    }

    // -------------------------------------------------------------------------
    // Case 2 — base path exists but http/ sub-directory is absent
    // -------------------------------------------------------------------------

    public function testReturnsNullWhenHttpDirectoryDoesNotExist(): void
    {
        $base = $this->createTmpBase();
        // Deliberately do NOT create $base/http/

        $result = $this->service()->findHttpLogPath('2025-03-15');

        $this->assertNull($result);
    }

    // -------------------------------------------------------------------------
    // Case 3 — plain .log file is present → returns its absolute path
    // -------------------------------------------------------------------------

    public function testReturnsLogPathWhenPlainLogFileExists(): void
    {
        $base  = $this->createTmpBase();
        $date  = '2025-03-15';
        $year  = '2025';

        $this->mkdirUnder($base, 'http/' . $year);
        $logFile = $base . '/http/' . $year . '/http-' . $date . '.log';
        $this->touch($logFile);

        $result = $this->service()->findHttpLogPath($date);

        $this->assertSame($logFile, $result);
    }

    // -------------------------------------------------------------------------
    // Case 4 — .log absent, .log.gz present → returns .log.gz path
    // -------------------------------------------------------------------------

    public function testReturnsGzPathWhenOnlyGzFileExists(): void
    {
        $base = $this->createTmpBase();
        $date = '2025-03-15';
        $year = '2025';

        $this->mkdirUnder($base, 'http/' . $year);
        $gzFile = $base . '/http/' . $year . '/http-' . $date . '.log.gz';
        $this->touch($gzFile);
        // No plain .log file created.

        $result = $this->service()->findHttpLogPath($date);

        $this->assertSame($gzFile, $result);
    }

    // -------------------------------------------------------------------------
    // Case 5 — neither .log nor .log.gz present → returns null
    // -------------------------------------------------------------------------

    public function testReturnsNullWhenNeitherLogNorGzExists(): void
    {
        $base = $this->createTmpBase();
        $date = '2025-03-15';
        $year = '2025';

        $this->mkdirUnder($base, 'http/' . $year);
        // Directory exists but no log files inside.

        $result = $this->service()->findHttpLogPath($date);

        $this->assertNull($result);
    }

    // -------------------------------------------------------------------------
    // Case 6 — year is correctly extracted from the date string
    // -------------------------------------------------------------------------

    public function testYearIsExtractedFromDateForPathConstruction(): void
    {
        $base = $this->createTmpBase();
        $date = '2024-11-30';
        $year = '2024';

        // Create the file only under the correct year sub-directory.
        $this->mkdirUnder($base, 'http/' . $year);
        $logFile = $base . '/http/' . $year . '/http-' . $date . '.log';
        $this->touch($logFile);

        // Create a decoy directory for another year to confirm the year is read from $date.
        $this->mkdirUnder($base, 'http/2025');
        $this->touch($base . '/http/2025/http-' . $date . '.log');

        $result = $this->service()->findHttpLogPath($date);

        // Must resolve to the 2024 path, not the 2025 decoy.
        $this->assertSame($logFile, $result);
    }
}

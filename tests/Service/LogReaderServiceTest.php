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
        $base = $this->createTmpBase();
        $date = '2025-03-15';
        $year = '2025';

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

    // -------------------------------------------------------------------------
    // Case 7 — readTodayLogs() decompresses a gzipped log of the day
    // -------------------------------------------------------------------------

    public function testReadTodayLogsDecompressesGzippedSource(): void
    {
        $base = $this->createTmpBase();
        $today = date('Y-m-d');

        $this->mkdirUnder($base, 'http');
        $lines = [];
        for ($i = 1; $i <= 50; ++$i) {
            $lines[] = 'line-' . $i;
        }
        $gzFile = $base . '/http/http-' . $today . '.log.gz';
        file_put_contents($gzFile, gzencode(implode("\n", $lines) . "\n"));

        $sources = $this->service()->readTodayLogs();
        $http = $this->sourceNamed($sources, 'http');

        $this->assertNull($http['error']);
        $this->assertSame(50, count($http['lines']));
        $this->assertSame('line-1', $http['lines'][0]);
        $this->assertSame('line-50', $http['lines'][49]);
    }

    // -------------------------------------------------------------------------
    // Case 8 — readTodayLogs() keeps only the last max_lines entries
    // -------------------------------------------------------------------------

    public function testReadTodayLogsKeepsOnlyTheLastLines(): void
    {
        $base = $this->createTmpBase();
        $today = date('Y-m-d');
        \Configuration::$testValues['SC_ALWAYSDATA_LINES_HTTP'] = 10;

        $this->mkdirUnder($base, 'http');
        $lines = [];
        for ($i = 1; $i <= 100; ++$i) {
            $lines[] = 'line-' . $i;
        }
        file_put_contents($base . '/http/http-' . $today . '.log', implode("\n", $lines) . "\n");

        $sources = $this->service()->readTodayLogs();
        $http = $this->sourceNamed($sources, 'http');

        $this->assertSame(10, count($http['lines']));
        $this->assertSame('line-91', $http['lines'][0]);
        $this->assertSame('line-100', $http['lines'][9]);
        $this->assertTrue($http['truncated']);
    }

    // -------------------------------------------------------------------------
    // Case 9 — a file holding no newline at all must not be read wholesale
    // -------------------------------------------------------------------------

    public function testReadTodayLogsHandlesFileWithoutAnyNewline(): void
    {
        $base = $this->createTmpBase();
        $today = date('Y-m-d');
        \Configuration::$testValues['SC_ALWAYSDATA_LINES_HTTP'] = 10;

        $this->mkdirUnder($base, 'http');
        file_put_contents($base . '/http/http-' . $today . '.log', str_repeat('x', 200000));

        $sources = $this->service()->readTodayLogs();
        $http = $this->sourceNamed($sources, 'http');

        $this->assertNull($http['error']);
        $this->assertSame(1, count($http['lines']));
    }

    // -------------------------------------------------------------------------
    // Case 10 — configured line counts are bounded
    // -------------------------------------------------------------------------

    public function testClampLinesBoundsTheConfiguredValue(): void
    {
        $this->assertSame(LogReaderService::MIN_LINES, LogReaderService::clampLines(1));
        $this->assertSame(LogReaderService::MIN_LINES, LogReaderService::clampLines(-5));
        $this->assertSame(5000, LogReaderService::clampLines(5000));
        $this->assertSame(LogReaderService::MAX_LINES, LogReaderService::clampLines(10000000));
    }

    public function testAStoredLineCountAboveTheCapIsReducedOnRead(): void
    {
        $base = $this->createTmpBase();
        \Configuration::$testValues['SC_ALWAYSDATA_LINES_HTTP'] = 10000000;
        $this->mkdirUnder($base, 'http');
        file_put_contents($base . '/http/http-' . date('Y-m-d') . '.log', "a\nb\n");

        $http = $this->sourceNamed($this->service()->readTodayLogs(), 'http');

        $this->assertSame(LogReaderService::MAX_LINES, $http['max_lines']);
    }

    // -------------------------------------------------------------------------
    // Case 11 — the logs base path is validated before use
    // -------------------------------------------------------------------------

    public function testNormalizeBasePathRefusesEmptyNulByteAndMissingPaths(): void
    {
        $this->assertNull(LogReaderService::normalizeBasePath(''));
        $this->assertNull(LogReaderService::normalizeBasePath('   '));
        $this->assertNull(LogReaderService::normalizeBasePath("/tmp\0/etc"));
        $this->assertNull(LogReaderService::normalizeBasePath(sys_get_temp_dir() . '/sc_alwaysdata_missing_' . uniqid()));
    }

    public function testNormalizeBasePathRefusesADirectoryWithoutLogFolders(): void
    {
        $base = $this->createTmpBase();
        $this->mkdirUnder($base, 'unrelated');

        $this->assertNull(LogReaderService::normalizeBasePath($base));
    }

    public function testNormalizeBasePathAcceptsADirectoryHoldingALogFolder(): void
    {
        $base = $this->createTmpBase();
        $this->mkdirUnder($base, 'http');

        $this->assertSame($base . '/', LogReaderService::normalizeBasePath($base));
        $this->assertSame($base . '/', LogReaderService::normalizeBasePath($base . '/'));
    }

    public function testAStoredBasePathWithoutLogFoldersIsIgnored(): void
    {
        $base = $this->createTmpBase();
        $this->mkdirUnder($base, 'unrelated');

        $sources = $this->service()->readTodayLogs();

        $this->assertSame('base', $sources[0]['source']);
        $this->assertNotNull($sources[0]['error']);
    }

    // -------------------------------------------------------------------------
    // Case 12 — the daily PHP snapshot reads an undated php.log by entry date
    // -------------------------------------------------------------------------

    public function testReadPhpLogForDateKeepsOnlyTheEntriesOfThatDay(): void
    {
        $base = $this->createTmpBase();
        $this->mkdirUnder($base, 'php');
        file_put_contents($base . '/php/php.log', implode("\n", [
            '[14-Mar-2025 23:59:59 Europe/Paris] PHP Warning:  before in /a.php on line 1',
            '[15-Mar-2025 00:00:01 Europe/Paris] PHP Fatal error:  first in /b.php on line 2',
            'Stack trace:',
            '#0 {main}',
            '[15-Mar-2025 23:59:58 Europe/Paris] PHP Notice:  second in /c.php on line 3',
            '[16-Mar-2025 00:00:00 Europe/Paris] PHP Warning:  after in /d.php on line 4',
            '[15-Mar-2025 10:00:00 Europe/Paris] PHP Warning:  out of order, never reached',
        ]) . "\n");

        $php = $this->service()->readPhpLogForDate('2025-03-15');

        $this->assertNull($php['error']);
        $this->assertSame([
            '[15-Mar-2025 00:00:01 Europe/Paris] PHP Fatal error:  first in /b.php on line 2',
            'Stack trace:',
            '#0 {main}',
            '[15-Mar-2025 23:59:58 Europe/Paris] PHP Notice:  second in /c.php on line 3',
        ], $php['lines']);
        $this->assertFalse($php['truncated']);
    }

    public function testReadPhpLogForDateReadsARotatedArchiveBeforeTheCurrentFile(): void
    {
        $base = $this->createTmpBase();
        $this->mkdirUnder($base, 'php');
        $rotated = $base . '/php/php.log.1.gz';
        file_put_contents($rotated, gzencode("[15-Mar-2025 08:00:00 UTC] PHP Warning:  morning in /a.php on line 1\n"));
        touch($rotated, time() - 3600);
        file_put_contents($base . '/php/php.log', "[15-Mar-2025 20:00:00 UTC] PHP Warning:  evening in /b.php on line 2\n");

        $php = $this->service()->readPhpLogForDate('2025-03-15');

        $this->assertSame([
            '[15-Mar-2025 08:00:00 UTC] PHP Warning:  morning in /a.php on line 1',
            '[15-Mar-2025 20:00:00 UTC] PHP Warning:  evening in /b.php on line 2',
        ], $php['lines']);
    }

    public function testReadPhpLogForDateKeepsTheLastLinesOfTheDay(): void
    {
        $base = $this->createTmpBase();
        \Configuration::$testValues['SC_ALWAYSDATA_LINES_PHP'] = 3;
        $this->mkdirUnder($base, 'php');
        $lines = [];
        for ($i = 1; $i <= 10; ++$i) {
            $lines[] = sprintf('[15-Mar-2025 10:00:%02d UTC] PHP Warning:  n%d in /a.php on line %d', $i, $i, $i);
        }
        file_put_contents($base . '/php/php.log', implode("\n", $lines) . "\n");

        $php = $this->service()->readPhpLogForDate('2025-03-15');

        $this->assertSame(array_slice($lines, -3), $php['lines']);
        $this->assertTrue($php['truncated']);
    }

    public function testReadPhpLogForDatePrefersAFileNamedAfterTheDate(): void
    {
        $base = $this->createTmpBase();
        $this->mkdirUnder($base, 'php');
        file_put_contents($base . '/php/php-2025-03-15.log', "dated line\n");
        file_put_contents($base . '/php/php.log', "[15-Mar-2025 10:00:00 UTC] PHP Warning:  undated in /a.php on line 1\n");

        $php = $this->service()->readPhpLogForDate('2025-03-15');

        $this->assertSame(['dated line'], $php['lines']);
    }

    public function testReadPhpLogForDateIgnoresFilesWrittenBeforeThatDay(): void
    {
        $base = $this->createTmpBase();
        $this->mkdirUnder($base, 'php');
        $old = $base . '/php/php.log';
        file_put_contents($old, "[15-Mar-2025 10:00:00 UTC] PHP Warning:  impossible in /a.php on line 1\n");
        touch($old, (int) strtotime('2025-03-14 12:00:00'));

        $php = $this->service()->readPhpLogForDate('2025-03-15');

        $this->assertSame([], $php['lines']);
        $this->assertNotNull($php['error']);
    }

    // -------------------------------------------------------------------------
    // Case 13 — jobs/ is read, an empty folder is not an error
    // -------------------------------------------------------------------------

    public function testReadTodayLogsReadsTheJobsFolder(): void
    {
        $base = $this->createTmpBase();
        $this->mkdirUnder($base, 'jobs');
        file_put_contents($base . '/jobs/jobs-' . date('Y-m-d') . '.log', "job ran\n");

        $jobs = $this->sourceNamed($this->service()->readTodayLogs(), 'jobs');

        $this->assertNull($jobs['error']);
        $this->assertSame(['job ran'], $jobs['lines']);
    }

    public function testAnEmptyLogFolderIsReportedAsEmptyNotAsAnError(): void
    {
        $base = $this->createTmpBase();
        $this->mkdirUnder($base, 'http');
        $this->mkdirUnder($base, 'sites');

        $sites = $this->sourceNamed($this->service()->readTodayLogs(), 'sites');

        $this->assertNull($sites['error']);
        $this->assertTrue($sites['empty']);
        $this->assertSame([], $sites['lines']);
    }

    public function testAMissingLogFolderIsReportedAsEmpty(): void
    {
        $base = $this->createTmpBase();
        $this->mkdirUnder($base, 'http');

        $jobs = $this->sourceNamed($this->service()->readTodayLogs(), 'jobs');

        $this->assertNull($jobs['error']);
        $this->assertTrue($jobs['empty']);
    }

    public function testNormalizeBasePathAcceptsADirectoryHoldingOnlyJobs(): void
    {
        $base = $this->createTmpBase();
        $this->mkdirUnder($base, 'jobs');

        $this->assertSame($base . '/', LogReaderService::normalizeBasePath($base));
    }

    /**
     * @param array<int, array<string, mixed>> $sources
     *
     * @return array<string, mixed>
     */
    private function sourceNamed(array $sources, string $name): array
    {
        foreach ($sources as $source) {
            if ($source['source'] === $name) {
                return $source;
            }
        }

        $this->fail('No source named ' . $name . ' in the result.');
    }
}

<?php

declare(strict_types=1);

namespace ScAlwaysdata\Tests\Service;

use PHPUnit\Framework\TestCase;
use ScAlwaysdata\Service\PhpErrorAnalyserService;

class PhpErrorAnalyserServiceTest extends TestCase
{
    private PhpErrorAnalyserService $service;

    protected function setUp(): void
    {
        $this->service = new PhpErrorAnalyserService();
    }

    private function makeSource(string $name, array $lines): array
    {
        return ['source' => $name, 'lines' => $lines, 'error' => null, 'truncated' => false];
    }

    // -----------------------------------------------------------------
    // Source filtering
    // -----------------------------------------------------------------

    public function testIgnoresNonPhpSources(): void
    {
        $line = '[06-Mar-2026 10:00:00 UTC] PHP Fatal error:  Test in /app/test.php on line 1';
        $sources = [
            $this->makeSource('apache', [$line]),
            $this->makeSource('http', [$line]),
        ];

        $result = $this->service->analyse($sources);

        $this->assertEmpty($result);
    }

    public function testIgnoresSourcesWithError(): void
    {
        $source = ['source' => 'php', 'lines' => ['PHP Fatal error:  Test in /app/test.php on line 1'], 'error' => 'file not found', 'truncated' => false];

        $result = $this->service->analyse([$source]);

        $this->assertEmpty($result);
    }

    public function testAcceptsNullError(): void
    {
        // 'error' is null (not missing) — must still be processed
        $source = ['source' => 'php', 'lines' => ['PHP Warning:  Test in /app/test.php on line 1'], 'error' => null];

        $result = $this->service->analyse([$source]);

        $this->assertNotEmpty($result);
    }

    // -----------------------------------------------------------------
    // Error parsing
    // -----------------------------------------------------------------

    public function testParsesFatalError(): void
    {
        $lines = ['[06-Mar-2026 10:00:00 Europe/Paris] PHP Fatal error:  Uncaught Exception in /var/www/test.php on line 42'];
        $result = $this->service->analyse([$this->makeSource('php', $lines)]);

        $this->assertCount(1, $result);
        $this->assertSame('fatal', $result[0]['level']);
        $this->assertSame('/var/www/test.php', $result[0]['file']);
        $this->assertSame(42, $result[0]['line']);
        $this->assertSame(1, $result[0]['count']);
    }

    public function testParsesParseErrorAsFatal(): void
    {
        $lines = ['PHP Parse error:  syntax error in /app/broken.php on line 5'];
        $result = $this->service->analyse([$this->makeSource('php', $lines)]);

        $this->assertCount(1, $result);
        $this->assertSame('fatal', $result[0]['level']);
    }

    public function testParsesWarning(): void
    {
        $lines = ['PHP Warning:  include() failed to open stream in /app/test.php on line 10'];
        $result = $this->service->analyse([$this->makeSource('php', $lines)]);

        $this->assertCount(1, $result);
        $this->assertSame('warning', $result[0]['level']);
    }

    public function testParsesNotice(): void
    {
        $lines = ['PHP Notice:  Undefined variable in /app/test.php on line 3'];
        $result = $this->service->analyse([$this->makeSource('php', $lines)]);

        $this->assertCount(1, $result);
        $this->assertSame('notice', $result[0]['level']);
    }

    public function testParsesDeprecated(): void
    {
        $lines = ['PHP Deprecated:  strpos(): Passing null is deprecated in /app/test.php on line 7'];
        $result = $this->service->analyse([$this->makeSource('php', $lines)]);

        $this->assertCount(1, $result);
        $this->assertSame('deprecated', $result[0]['level']);
    }

    public function testParsesStrictStandardsAsNotice(): void
    {
        $lines = ['PHP Strict Standards:  Declaration of MyClass::method() in /app/test.php on line 2'];
        $result = $this->service->analyse([$this->makeSource('php', $lines)]);

        $this->assertCount(1, $result);
        $this->assertSame('notice', $result[0]['level']);
    }

    public function testParsesLineWithColonFormat(): void
    {
        // Alternative: "in /file.php:42" instead of "on line 42"
        $lines = ['PHP Fatal error:  Uncaught Exception in /var/www/test.php:99'];
        $result = $this->service->analyse([$this->makeSource('php', $lines)]);

        $this->assertCount(1, $result);
        $this->assertSame(99, $result[0]['line']);
    }

    public function testParsesPhpFpmFormat(): void
    {
        // PHP-FPM wraps the message in 'child N said into stderr: "PHP Fatal error: ..."'
        $lines = ['[06-Mar-2026 10:00:00] WARNING: [pool www] child 12345 said into stderr: "PHP Fatal error:  Test error in /app/file.php on line 5"'];
        $result = $this->service->analyse([$this->makeSource('php', $lines)]);

        $this->assertCount(1, $result);
        $this->assertSame('fatal', $result[0]['level']);
    }

    // -----------------------------------------------------------------
    // Deduplication
    // -----------------------------------------------------------------

    public function testDeduplicatesIdenticalErrors(): void
    {
        $line = 'PHP Warning:  Undefined index in /app/test.php on line 10';
        $lines = array_fill(0, 5, $line);
        $result = $this->service->analyse([$this->makeSource('php', $lines)]);

        $this->assertCount(1, $result);
        $this->assertSame(5, $result[0]['count']);
    }

    public function testDifferentFilesNotDeduplicated(): void
    {
        $lines = [
            'PHP Warning:  Undefined index in /app/file1.php on line 10',
            'PHP Warning:  Undefined index in /app/file2.php on line 10',
        ];
        $result = $this->service->analyse([$this->makeSource('php', $lines)]);

        $this->assertCount(2, $result);
    }

    // -----------------------------------------------------------------
    // Sorting: severity first, then count
    // -----------------------------------------------------------------

    public function testSortsBySeverityDesc(): void
    {
        $lines = [
            'PHP Notice:  Undefined variable in /app/a.php on line 1',
            'PHP Warning:  Division by zero in /app/b.php on line 2',
            'PHP Fatal error:  Uncaught in /app/c.php on line 3',
            'PHP Deprecated:  Old func in /app/d.php on line 4',
        ];
        $result = $this->service->analyse([$this->makeSource('php', $lines)]);

        $this->assertSame('fatal', $result[0]['level']);
        $this->assertSame('warning', $result[1]['level']);
    }

    public function testSortsByCountWhenSameSeverity(): void
    {
        $lines = array_merge(
            array_fill(0, 3, 'PHP Warning:  A in /app/a.php on line 1'),
            array_fill(0, 7, 'PHP Warning:  B in /app/b.php on line 2')
        );
        $result = $this->service->analyse([$this->makeSource('php', $lines)]);

        $this->assertSame(7, $result[0]['count']);
        $this->assertSame(3, $result[1]['count']);
    }

    public function testMaxEntriesCapped(): void
    {
        $lines = [];
        for ($i = 0; $i < 150; ++$i) {
            $lines[] = sprintf('PHP Warning:  Error %d in /app/file%d.php on line 1', $i, $i);
        }
        $result = $this->service->analyse([$this->makeSource('php', $lines)]);

        $this->assertLessThanOrEqual(100, count($result));
    }

    // -----------------------------------------------------------------
    // Edge cases
    // -----------------------------------------------------------------

    public function testReturnsEmptyForNoMatches(): void
    {
        $lines = ['just a random log line with no php error'];
        $result = $this->service->analyse([$this->makeSource('php', $lines)]);

        $this->assertEmpty($result);
    }

    public function testHandlesEmptySource(): void
    {
        $result = $this->service->analyse([$this->makeSource('php', [])]);

        $this->assertEmpty($result);
    }
}

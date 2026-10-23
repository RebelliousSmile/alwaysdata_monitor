<?php

declare(strict_types=1);

namespace ScAlwaysdata\Tests\Service;

use PHPUnit\Framework\TestCase;
use ScAlwaysdata\Service\CrawlerAnalyserService;

class CrawlerAnalyserServiceTest extends TestCase
{
    private CrawlerAnalyserService $service;

    protected function setUp(): void
    {
        $this->service = new CrawlerAnalyserService();
    }

    private function makeSource(string $name, array $lines): array
    {
        return ['source' => $name, 'lines' => $lines, 'error' => null, 'truncated' => false];
    }

    /**
     * Standard Alwaysdata HTTP log line:
     * hostname ip - - [date] "GET / HTTP/1.1" 200 1234 "-" "UA"
     */
    private function httpLine(string $ip, string $ua, string $path = '/index.php'): string
    {
        return sprintf(
            'www.site-a.example %s - - [09/Mar/2026:10:00:00 +0100] "GET %s HTTP/1.1" 200 1234 "-" "%s" http 0.123',
            $ip,
            $path,
            $ua
        );
    }

    // -----------------------------------------------------------------
    // Source filtering
    // -----------------------------------------------------------------

    public function testIgnoresNonHttpSources(): void
    {
        $sources = [
            $this->makeSource('php', [$this->httpLine('203.0.113.14', 'AhrefsBot/7.0')]),
            $this->makeSource('sites', [$this->httpLine('203.0.113.14', 'AhrefsBot/7.0')]),
        ];

        $result = $this->service->analyse($sources);

        $this->assertEmpty($result, 'php/sites sources must be ignored');
    }

    public function testIgnoresSourcesWithError(): void
    {
        $source = ['source' => 'http', 'lines' => [$this->httpLine('203.0.113.14', 'AhrefsBot/7.0')], 'error' => 'file not found', 'truncated' => false];

        $result = $this->service->analyse([$source]);

        $this->assertEmpty($result);
    }

    public function testAcceptsApacheAndHttpSources(): void
    {
        $sources = [
            $this->makeSource('apache', [$this->httpLine('203.0.113.14', 'AhrefsBot/7.0')]),
            $this->makeSource('http', [$this->httpLine('203.0.113.15', 'AhrefsBot/7.0')]),
        ];

        $result = $this->service->analyse($sources);

        $this->assertNotEmpty($result);
        $entry = $result[0];
        $this->assertSame('AhrefsBot', $entry['matched_bot']);
        // Both IPs merged into the same group
        $this->assertCount(2, $entry['ips']);
        $this->assertContains('203.0.113.14', $entry['ips']);
        $this->assertContains('203.0.113.15', $entry['ips']);
    }

    // -----------------------------------------------------------------
    // Known bot detection
    // -----------------------------------------------------------------

    public function testDetectsKnownBot(): void
    {
        $sources = [$this->makeSource('http', [$this->httpLine('203.0.113.14', 'AhrefsBot/7.0')])];

        $result = $this->service->analyse($sources);

        $this->assertCount(1, $result);
        $this->assertSame('AhrefsBot', $result[0]['matched_bot']);
        $this->assertSame('known_bot', $result[0]['reason']);
    }

    public function testKnownBotIsCaseInsensitive(): void
    {
        $sources = [$this->makeSource('http', [$this->httpLine('203.0.113.14', 'ahrefsbot/7.0')])];

        $result = $this->service->analyse($sources);

        $this->assertNotEmpty($result);
        $this->assertSame('AhrefsBot', $result[0]['matched_bot']);
    }

    public function testGroupsKnownBotAcrossIps(): void
    {
        $lines = [
            $this->httpLine('10.0.0.1', 'SemrushBot-SA/0.01'),
            $this->httpLine('10.0.0.2', 'SemrushBot-SI/0.01'),
            $this->httpLine('10.0.0.3', 'SemrushBot/1.2'),
        ];
        $sources = [$this->makeSource('http', $lines)];

        $result = $this->service->analyse($sources);

        $this->assertCount(1, $result);
        $this->assertSame('SemrushBot', $result[0]['matched_bot']);
        $this->assertCount(3, $result[0]['ips']);
        $this->assertSame(3, $result[0]['request_count']);
    }

    public function testRequestCountAccumulates(): void
    {
        // Same IP hits twice with the same bot UA
        $lines = array_fill(0, 10, $this->httpLine('203.0.113.5', 'GPTBot/1.0'));
        $sources = [$this->makeSource('http', $lines)];

        $result = $this->service->analyse($sources);

        $this->assertSame(10, $result[0]['request_count']);
    }

    // -----------------------------------------------------------------
    // High-frequency detection (unknown bot)
    // -----------------------------------------------------------------

    public function testHighFrequencyUnknownIp(): void
    {
        $lines = array_fill(0, 200, $this->httpLine('203.0.113.9', 'curl/7.x'));
        $sources = [$this->makeSource('http', $lines)];

        $result = $this->service->analyse($sources);

        $this->assertCount(1, $result);
        $this->assertSame('high_frequency', $result[0]['reason']);
        $this->assertNull($result[0]['matched_bot']);
        $this->assertSame(200, $result[0]['request_count']);
    }

    public function testBelowThresholdNotReported(): void
    {
        $lines = array_fill(0, 199, $this->httpLine('203.0.113.9', 'curl/7.x'));
        $sources = [$this->makeSource('http', $lines)];

        $result = $this->service->analyse($sources);

        $this->assertEmpty($result);
    }

    // -----------------------------------------------------------------
    // Admin filtering
    // -----------------------------------------------------------------

    public function testSkipsAdminRequests(): void
    {
        // 200 requests to the admin panel — must not trigger high-frequency
        $lines = array_fill(0, 200, $this->httpLine('203.0.113.9', 'Mozilla/5.0', '/admin9615/index.php'));
        $sources = [$this->makeSource('http', $lines)];

        $result = $this->service->analyse($sources);

        $this->assertEmpty($result, 'Admin panel requests must be filtered out');
    }

    // -----------------------------------------------------------------
    // IP extraction
    // -----------------------------------------------------------------

    public function testCapturesCorrectIpNotHostname(): void
    {
        // Alwaysdata format: hostname ip - - [...]
        $line = 'www.site-a.example 203.0.113.42 - - [09/Mar/2026:10:00:00 +0100] "GET / HTTP/1.1" 200 1 "-" "AhrefsBot/7.0"';
        $sources = [$this->makeSource('http', array_fill(0, 1, $line))];

        $result = $this->service->analyse($sources);

        $this->assertNotEmpty($result);
        $this->assertContains('203.0.113.42', $result[0]['ips']);
        $this->assertNotContains('www.site-a.example', $result[0]['ips']);
    }

    public function testCapturesIpv6(): void
    {
        $line = 'www.site-a.example 2a03:2880:f814:ab::face:b00c - - [09/Mar/2026:10:00:00 +0100] "GET / HTTP/1.1" 200 1 "-" "facebookexternalhit/1.1"';
        $sources = [$this->makeSource('http', [$line])];

        $result = $this->service->analyse($sources);

        $this->assertNotEmpty($result);
        $this->assertContains('2a03:2880:f814:ab::face:b00c', $result[0]['ips']);
    }

    // -----------------------------------------------------------------
    // Sorting
    // -----------------------------------------------------------------

    public function testResultsSortedByRequestCountDesc(): void
    {
        $lines = [];
        $lines = array_merge($lines, array_fill(0, 5, $this->httpLine('203.0.113.11', 'AhrefsBot/7.0')));
        $lines = array_merge($lines, array_fill(0, 200, $this->httpLine('203.0.113.12', 'curl/7.x'))); // high freq
        $lines = array_merge($lines, array_fill(0, 50, $this->httpLine('203.0.113.13', 'SemrushBot/1.0')));
        $sources = [$this->makeSource('http', $lines)];

        $result = $this->service->analyse($sources);

        $this->assertCount(3, $result);
        $this->assertGreaterThanOrEqual($result[1]['request_count'], $result[0]['request_count']);
        $this->assertGreaterThanOrEqual($result[2]['request_count'], $result[1]['request_count']);
    }

    public function testMaxResultsCapped(): void
    {
        // Generate 60 distinct high-frequency IPs
        $lines = [];
        for ($i = 0; $i < 60; ++$i) {
            $ip = sprintf('10.0.%d.%d', intdiv($i, 256), $i % 256);
            $lines = array_merge($lines, array_fill(0, 200, $this->httpLine($ip, 'curl/7.x')));
        }
        $sources = [$this->makeSource('http', $lines)];

        $result = $this->service->analyse($sources);

        $this->assertLessThanOrEqual(50, count($result));
    }
}

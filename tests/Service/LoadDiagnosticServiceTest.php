<?php

declare(strict_types=1);

namespace ScAlwaysdata\Tests\Service;

use PHPUnit\Framework\TestCase;
use ScAlwaysdata\Service\CrawlerAnalyserService;
use ScAlwaysdata\Service\LoadDiagnosticService;

class LoadDiagnosticServiceTest extends TestCase
{
    private const SHOP_HOSTS = ['www.site-a.example', 'www.site-a.test'];

    private LoadDiagnosticService $service;

    /** @var string[] */
    private array $tmpFiles = [];

    protected function setUp(): void
    {
        $this->service = new LoadDiagnosticService(new CrawlerAnalyserService(), null, static fn (string $ip): ?string => null);
    }

    protected function tearDown(): void
    {
        foreach ($this->tmpFiles as $f) {
            @unlink($f);
        }
        $this->tmpFiles = [];
    }

    /**
     * @param array<string, string> $o
     */
    private function line(array $o = []): string
    {
        $o += [
            'ip' => '203.0.113.14', 'hour' => '14', 'method' => 'GET', 'url' => '/4-vtt',
            'status' => '200', 'referer' => '-', 'ua' => 'Mozilla/5.0', 'time' => '0.250',
        ];

        return sprintf(
            'www.site-a.example %s - - [25/Sep/2026:%s:32:10 +0200] "%s %s HTTP/2.0" %s 12345 "%s" "%s" https %s',
            $o['ip'], $o['hour'], $o['method'], $o['url'], $o['status'], $o['referer'], $o['ua'], $o['time']
        );
    }

    /**
     * @param string[] $lines
     */
    private function writeLog(array $lines, bool $gzip = false): string
    {
        $base = tempnam(sys_get_temp_dir(), 'diag');
        $path = $base . ($gzip ? '.log.gz' : '.log');
        $content = implode("\n", $lines) . "\n";
        file_put_contents($path, $gzip ? gzencode($content) : $content);
        array_push($this->tmpFiles, $base, $path);

        return $path;
    }

    /**
     * @param array<int, array{value: string, count: int}> $list
     *
     * @return array<string, int>
     */
    private function asMap(array $list): array
    {
        return array_column($list, 'count', 'value');
    }

    public function testCountsVolumeStaticsAndServerTime(): void
    {
        $result = $this->service->analyse($this->writeLog([
            $this->line(['url' => '/img/p/1.webp', 'time' => '0.001']),
            $this->line(['url' => '/themes/app.css?v=3', 'time' => '0.001']),
            $this->line(['time' => '1.5']),
            '',
            'garbage line',
        ]), self::SHOP_HOSTS);

        $this->assertSame(4, $result['total']);
        $this->assertSame(1, $result['unparsed']);
        $this->assertSame(2, $result['static']);
        $this->assertSame(1.5, $result['time_total']);
        $this->assertSame(3, $result['hourly'][14]);
    }

    public function testTopListsStripQueryStringAndKeepStringKeys(): void
    {
        $result = $this->service->analyse($this->writeLog([
            $this->line(['url' => '/4-vtt?page=2', 'ip' => '10.0.0.1']),
            $this->line(['url' => '/4-vtt', 'ip' => '10.0.0.1']),
            $this->line(['url' => '/panier', 'ip' => '2a01:cb00::1']),
        ]), self::SHOP_HOSTS);

        $this->assertSame(['value' => '/4-vtt', 'count' => 2], $result['top_urls'][0]);
        $this->assertSame(['10.0.0.1' => 2, '2a01:cb00::1' => 1], $this->asMap($result['top_ips']));
    }

    public function testDeclaredBotsAreGroupedCaseInsensitively(): void
    {
        $result = $this->service->analyse($this->writeLog([
            $this->line(['ua' => 'Mozilla/5.0 (compatible; GPTBot/1.2)']),
            $this->line(['ua' => 'mozilla/5.0 gptbot']),
            $this->line(['ua' => 'Mozilla/5.0 (compatible; Applebot-Extended/0.1)']),
            $this->line(['ua' => 'Mozilla/5.0 Firefox']),
        ]), self::SHOP_HOSTS);

        $this->assertSame(['GPTBot' => 2, 'Applebot-Extended' => 1], $this->asMap($result['bots']));
    }

    public function testFacetsAreSplitByRefererOrigin(): void
    {
        $result = $this->service->analyse($this->writeLog([
            $this->line(['url' => '/43-cuissards?q=Taille-S', 'status' => '403', 'time' => '0.002']),
            $this->line(['url' => '/43-cuissards?q=Taille-S', 'referer' => 'https://site-a.example/43-cuissards', 'time' => '2']),
            $this->line([
                'url' => '/43-cuissards?page=1&q=Taille-M', 'referer' => 'https://www.google.com/?x=1',
                'ua' => 'FakeChrome', 'status' => '403', 'ip' => '203.0.113.9',
            ]),
            $this->line(['url' => '/recherche?s=casque']),
        ]), self::SHOP_HOSTS);

        $facets = $result['facets'];
        $this->assertSame(3, $facets['count']);
        $this->assertSame(2, $facets['distinct_ips']);
        $this->assertSame(['vide' => 1, 'interne' => 1, 'externe' => 1], $facets['origin']);
        $this->assertSame(['403' => 2, '200' => 1], $this->asMap($facets['statuses']));
        $this->assertSame(['https://www.google.com/' => 1], $this->asMap($facets['top_referers']));
        $this->assertSame(['FakeChrome' => 1], $this->asMap($facets['external_uas']));
        $this->assertSame(2.3, $facets['time']);
        $this->assertSame(1, $result['search']);
    }

    public function testHourlyBreakdownSeparatesRefusedRequestsAndServerTime(): void
    {
        $result = $this->service->analyse($this->writeLog([
            $this->line(['hour' => '23', 'status' => '403', 'time' => '0.1']),
            $this->line(['hour' => '23', 'status' => '403', 'time' => '0.1']),
            $this->line(['hour' => '23', 'time' => '2']),
            $this->line(['hour' => '08', 'time' => '1']),
        ]), self::SHOP_HOSTS);

        $this->assertSame(3, $result['hourly'][23]);
        $this->assertSame(2, $result['hourly_refused'][23]);
        $this->assertSame(0, $result['hourly_refused'][8]);
        $this->assertSame(2.2, $result['hourly_time'][23]);
        $this->assertSame(1.0, $result['hourly_time'][8]);
    }

    public function testTopIpsGetASuspicionProfile(): void
    {
        $lines = [];
        for ($i = 0; $i < 30; ++$i) {
            $lines[] = $this->line(['ip' => '203.0.113.5', 'url' => '/43-cuissards?q=Taille-' . $i, 'status' => '403', 'ua' => 'python-requests/2.31']);
        }
        $lines[] = $this->line(['ip' => '203.0.113.8', 'url' => '/4-vtt', 'referer' => 'https://www.site-a.example/']);
        $lines[] = $this->line(['ip' => '203.0.113.8', 'url' => '/themes/app.css']);

        $service = new LoadDiagnosticService(new CrawlerAnalyserService(), null, static function (string $ip): ?string {
            return $ip === '203.0.113.5' ? 'vps-1234.ovh.net' : 'lfbn-1.abo.wanadoo.fr';
        });
        $profiles = array_column($service->analyse($this->writeLog($lines), self::SHOP_HOSTS)['ip_profiles'], null, 'ip');

        $this->assertSame(['203.0.113.5', '203.0.113.8'], array_keys($profiles));
        $scraper = $profiles['203.0.113.5'];
        $this->assertSame('vps-1234.ovh.net', $scraper['rdns']);
        $this->assertSame(100, $scraper['facet_pct']);
        $this->assertSame(100, $scraper['refused_pct']);
        $this->assertSame(30, $scraper['peak_minute']);
        $this->assertSame('eleve', $scraper['level']);
        $this->assertSame('hebergeur', $scraper['network']);
        $this->assertSame('faible', $profiles['203.0.113.8']['level']);
        $this->assertSame(0, $profiles['203.0.113.8']['score']);
    }

    public function testLoginRequestsAreSplitByMethod(): void
    {
        $result = $this->service->analyse($this->writeLog([
            $this->line(['url' => '/connexion?back=my-account']),
            $this->line(['url' => '/connexion', 'method' => 'POST']),
            $this->line(['url' => '/connexion', 'method' => 'POST']),
        ]), self::SHOP_HOSTS);

        $this->assertSame(['GET' => 1, 'POST' => 2], $result['login']);
    }

    public function testReadsGzippedLogs(): void
    {
        $result = $this->service->analyse($this->writeLog([$this->line(), $this->line()], true), self::SHOP_HOSTS);

        $this->assertSame(2, $result['total']);
    }

    public function testLinesWithoutRefererOrTimeStillParse(): void
    {
        $result = $this->service->analyse($this->writeLog([
            '203.0.113.14 - - [25/Sep/2026:03:00:00 +0200] "GET /4-vtt?q=x HTTP/1.1" 200 10',
        ]), self::SHOP_HOSTS);

        $this->assertSame(0, $result['unparsed']);
        $this->assertSame(1, $result['facets']['origin']['vide']);
        $this->assertSame(0.0, $result['time_total']);
    }

    public function testMissingFileThrows(): void
    {
        $this->expectException(\RuntimeException::class);
        $this->service->analyse('/nonexistent/http.log', self::SHOP_HOSTS);
    }

    public function testAuditFlagsBlockedHumanAndLeavesScrapersAlone(): void
    {
        $lines = [];
        // Scraper: facets without referer
        for ($i = 0; $i < 40; ++$i) {
            $lines[] = $this->line(['ip' => '203.0.113.5', 'url' => '/4-vtt?q=Taille-M' . $i, 'status' => '403']);
        }
        // Customer from Google, gives up after two 403s
        $lines[] = $this->line(['ip' => '203.0.113.9', 'url' => '/fr/', 'status' => '403', 'referer' => 'https://www.google.fr/']);
        $lines[] = $this->line(['ip' => '203.0.113.9', 'url' => '/fr/', 'status' => '403', 'referer' => 'https://www.google.fr/']);
        $lines[] = $this->line(['ip' => '203.0.113.9', 'url' => '/favicon.ico', 'status' => '403']);
        // Not blocked: ignored
        $lines[] = $this->line(['ip' => '203.0.113.11', 'url' => '/', 'referer' => 'https://www.google.fr/']);
        // Internal referer is not a human signal
        $lines[] = $this->line(['ip' => '203.0.113.7', 'url' => '/4-vtt', 'status' => '403', 'referer' => 'https://www.site-a.example/']);

        $audit = $this->service->auditBlockedIps($this->writeLog($lines), ['203.0.113.5', '203.0.113.9', '203.0.113.7', '203.0.113.8'], ['www.site-a.example']);
        $byIp = array_column($audit['seen'], null, 'ip');

        $this->assertSame('203.0.113.9', $audit['seen'][0]['ip']);
        $this->assertSame('humain', $byIp['203.0.113.9']['verdict']);
        $this->assertSame(2, $byIp['203.0.113.9']['pages']);
        $this->assertSame(2, $byIp['203.0.113.9']['homepage']);
        $this->assertSame([['value' => 'www.google.fr', 'count' => 2]], $byIp['203.0.113.9']['referers']);
        $this->assertSame('robot', $byIp['203.0.113.5']['verdict']);
        $this->assertSame('robot', $byIp['203.0.113.7']['verdict']);
        $this->assertArrayNotHasKey('203.0.113.11', $byIp);
        $this->assertSame(['203.0.113.8'], $audit['absent']);
    }

    public function testAuditHumanSignalsOnHeavyTrafficNeedAHumanCheck(): void
    {
        $lines = [];
        for ($i = 0; $i < 50; ++$i) {
            $lines[] = $this->line(['ip' => '203.0.113.6', 'url' => '/4-vtt?q=' . $i, 'status' => '403', 'referer' => 'https://www.google.com/']);
        }

        $audit = $this->service->auditBlockedIps($this->writeLog($lines), ['203.0.113.6'], ['www.site-a.example']);

        $this->assertSame('a_verifier', $audit['seen'][0]['verdict']);
    }

    public function testAuditMatchesCidrRules(): void
    {
        $lines = [
            $this->line(['ip' => '10.1.2.3', 'url' => '/', 'status' => '403', 'referer' => 'https://www.facebook.com/']),
            $this->line(['ip' => '10.1.3.3', 'url' => '/', 'status' => '200']),
            $this->line(['ip' => '2001:db8::5', 'url' => '/', 'status' => '403']),
        ];

        $audit = $this->service->auditBlockedIps($this->writeLog($lines), ['10.1.2.0/24', '2001:db8::/32'], ['www.site-a.example']);
        $byIp = array_column($audit['seen'], null, 'ip');

        $this->assertSame('10.1.2.0/24', $byIp['10.1.2.3']['rule']);
        $this->assertArrayNotHasKey('10.1.3.3', $byIp);
        $this->assertSame('2001:db8::/32', $byIp['2001:db8::5']['rule']);
        $this->assertSame([], $audit['absent']);
    }
}

<?php

declare(strict_types=1);

namespace ScAlwaysdata\Tests\Service;

use PHPUnit\Framework\TestCase;
use ScAlwaysdata\Service\IpSuspicionScorer;

class IpSuspicionScorerTest extends TestCase
{
    private IpSuspicionScorer $scorer;

    protected function setUp(): void
    {
        $this->scorer = new IpSuspicionScorer();
    }

    /**
     * @param array<string, mixed> $o
     *
     * @return array{requests: int, static: int, facets: int, refused: int, empty_referer_pages: int, uas: array<string, int>, peak_minute: int}
     */
    private function stats(array $o = []): array
    {
        return $o + [
            'requests' => 100, 'static' => 60, 'facets' => 0, 'refused' => 0,
            'empty_referer_pages' => 0, 'uas' => ['Mozilla/5.0 Firefox' => 100], 'peak_minute' => 5,
        ];
    }

    public function testHostedFacetScraperScoresHigh(): void
    {
        $r = $this->scorer->score($this->stats([
            'static' => 0, 'facets' => 95, 'refused' => 90, 'empty_referer_pages' => 100, 'peak_minute' => 80,
        ]), 'ec2-1-2-3-4.compute.amazonaws.com', null);

        $this->assertSame(95, $r['score']);
        $this->assertSame('eleve', $r['level']);
        $this->assertSame('hebergeur', $r['network']);
    }

    public function testRefusedRequestsDoNotChangeTheScore(): void
    {
        $open = $this->scorer->score($this->stats(['facets' => 90]), null, null);
        $refused = $this->scorer->score($this->stats(['facets' => 90, 'refused' => 100]), null, null);

        $this->assertSame($open['score'], $refused['score']);
    }

    public function testBrowserOnConsumerIspScoresZero(): void
    {
        $r = $this->scorer->score($this->stats(), 'lfbn-idf1-1-2-3.w90-1.abo.wanadoo.fr', null);

        $this->assertSame(0, $r['score']);
        $this->assertSame('faible', $r['level']);
        $this->assertSame('fai', $r['network']);
    }

    public function testConsumerIspLowersScoreOfSharedIp(): void
    {
        $scraping = $this->stats(['static' => 0, 'facets' => 50, 'empty_referer_pages' => 100]);
        $onIsp = $this->scorer->score($scraping, 'bouyguestelecom.fr', null);
        $unknown = $this->scorer->score($scraping, 'host.example', null);

        $this->assertSame($unknown['score'] - 25, $onIsp['score']);
    }

    public function testUaRotationIgnoredOnConsumerNetwork(): void
    {
        $uas = ['a' => 1, 'b' => 1, 'c' => 1, 'd' => 1, 'e' => 1];
        $isp = $this->scorer->score($this->stats(['uas' => $uas]), 'x.proxad.net', null);
        $hosted = $this->scorer->score($this->stats(['uas' => $uas]), 'x.hetzner.com', null);

        $this->assertNotContains(15, array_column($isp['reasons'], 'points'));
        $this->assertContains(15, array_column($hosted['reasons'], 'points'));
    }

    public function testGenuineSearchEngineIsNeverSuspicious(): void
    {
        $r = $this->scorer->score($this->stats(['static' => 0, 'peak_minute' => 200]), 'crawl-66-249-66-1.googlebot.com', 'Googlebot');

        $this->assertSame(0, $r['score']);
        $this->assertSame('moteur', $r['level']);
    }

    public function testFakeGooglebotIsFlagged(): void
    {
        $r = $this->scorer->score($this->stats(), 'vps.contabo.net', 'Googlebot');

        $this->assertGreaterThanOrEqual(IpSuspicionScorer::LEVEL_HIGH, $r['score']);
        $this->assertStringContainsString('Googlebot', $r['reasons'][0]['label']);
    }

    public function testToolUserAgentAddsPoints(): void
    {
        $r = $this->scorer->score($this->stats(['uas' => ['curl/8.4.0' => 100]]), null, null);

        $this->assertSame(25, $r['score']);
    }
}

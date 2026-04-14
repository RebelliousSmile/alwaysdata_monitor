<?php

declare(strict_types=1);

namespace ScAlwaysdata\Tests\Service;

use PHPUnit\Framework\TestCase;
use ScAlwaysdata\Service\CrawlerAnalyserService;
use ScAlwaysdata\Service\HttpLogParserService;

class HttpLogParserServiceTest extends TestCase
{
    private HttpLogParserService $service;

    /** @var string[] */
    private array $tmpFiles = [];

    protected function setUp(): void
    {
        $this->service = new HttpLogParserService(new CrawlerAnalyserService());
    }

    protected function tearDown(): void
    {
        foreach ($this->tmpFiles as $f) {
            if (file_exists($f)) {
                @unlink($f);
            }
        }
        $this->tmpFiles = [];
    }

    // -----------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------

    /**
     * Generate a single Apache/Alwaysdata combined log line.
     *
     * @param array<string, mixed> $overrides
     */
    private function makeLine(array $overrides = []): string
    {
        $defaults = [
            'ip'     => '1.2.3.4',
            'hour'   => '14',
            'method' => 'GET',
            'path'   => '/index.html',
            'status' => '200',
            'ua'     => 'Mozilla/5.0 (compatible)',
        ];

        $o = array_merge($defaults, $overrides);

        return sprintf(
            'site-a.example %s - - [12/Apr/2026:%s:32:10 +0200] "%s %s HTTP/2.0" %s 12345 "-" "%s"',
            $o['ip'],
            str_pad((string) $o['hour'], 2, '0', STR_PAD_LEFT),
            $o['method'],
            $o['path'],
            $o['status'],
            $o['ua']
        );
    }

    private function createLogFile(array $lines): string
    {
        $path = tempnam(sys_get_temp_dir(), 'httplog_test_') . '.log';
        file_put_contents($path, implode("\n", $lines) . "\n");
        $this->tmpFiles[] = $path;

        return $path;
    }

    private function createGzLogFile(array $lines): string
    {
        $path = tempnam(sys_get_temp_dir(), 'httplog_test_') . '.gz';
        $handle = gzopen($path, 'wb');
        gzwrite($handle, implode("\n", $lines) . "\n");
        gzclose($handle);
        $this->tmpFiles[] = $path;

        return $path;
    }

    // -----------------------------------------------------------------
    // Parsing de base
    // -----------------------------------------------------------------

    public function testNonExistentFileThrowsRuntimeException(): void
    {
        $this->expectException(\RuntimeException::class);
        $this->service->parse('/tmp/does_not_exist_at_all_xyzzy.log');
    }

    public function testEmptyFileReturnsAllCountersAtZero(): void
    {
        $path = $this->createLogFile([]);

        $result = $this->service->parse($path);

        $this->assertSame(0, $result['requests_total']);
        $this->assertSame(0, $result['requests_human']);
        $this->assertSame(0, $result['mobile']);
        $this->assertSame(0, $result['desktop']);
        $this->assertSame(0, $result['views_product']);
        $this->assertSame(0, $result['cart_adds']);
        $this->assertSame(0, $result['views_cart']);
        $this->assertSame(0, $result['views_checkout']);
        $this->assertSame(0, $result['post_checkout']);
        $this->assertSame(0, $result['errors_500_front']);
        $this->assertSame(0, $result['errors_500_bo']);
        $this->assertSame(0, $result['errors_500_checkout']);
        $this->assertSame([], $result['errors_500_checkout_detail']);
        $this->assertSame([], $result['page_counts']);
    }

    public function testLineNotMatchingRegexIsIgnoredButIncrementsTotalCounter(): void
    {
        $path = $this->createLogFile(['this is garbage and does not match the log format']);

        $result = $this->service->parse($path);

        $this->assertSame(1, $result['requests_total']);
        $this->assertSame(0, $result['requests_human']);
    }

    // -----------------------------------------------------------------
    // Filtrage bots — UA
    // -----------------------------------------------------------------

    public function testKnownBotUaIsNotCountedInRequestsHuman(): void
    {
        $path = $this->createLogFile([
            $this->makeLine(['ua' => 'AhrefsBot/7.0']),
        ]);

        $result = $this->service->parse($path);

        $this->assertSame(1, $result['requests_total']);
        $this->assertSame(0, $result['requests_human']);
    }

    // -----------------------------------------------------------------
    // Filtrage bots — IP
    // -----------------------------------------------------------------

    public function testBotIpPrefixIsNotCountedInRequestsHuman(): void
    {
        $path = $this->createLogFile([
            $this->makeLine(['ip' => '74.125.1.1']),
        ]);

        $result = $this->service->parse($path);

        $this->assertSame(1, $result['requests_total']);
        $this->assertSame(0, $result['requests_human']);
    }

    // -----------------------------------------------------------------
    // Filtrage bots — humain
    // -----------------------------------------------------------------

    public function testHumanRequestIsCountedInRequestsHuman(): void
    {
        $path = $this->createLogFile([
            $this->makeLine(['path' => '/page', 'status' => '200']),
        ]);

        $result = $this->service->parse($path);

        $this->assertSame(1, $result['requests_total']);
        $this->assertSame(1, $result['requests_human']);
    }

    // -----------------------------------------------------------------
    // Filtrage assets statiques
    // -----------------------------------------------------------------

    public function testStaticCssIsNotCountedInRequestsHuman(): void
    {
        $path = $this->createLogFile([
            $this->makeLine(['path' => '/assets/style.css']),
        ]);

        $result = $this->service->parse($path);

        $this->assertSame(1, $result['requests_total']);
        $this->assertSame(0, $result['requests_human']);
        $this->assertSame([], $result['page_counts']);
    }

    public function testStaticJsIsNotCountedInRequestsHuman(): void
    {
        $path = $this->createLogFile([
            $this->makeLine(['path' => '/assets/app.js']),
        ]);

        $result = $this->service->parse($path);

        $this->assertSame(0, $result['requests_human']);
    }

    public function testStaticPngIsNotCountedInRequestsHuman(): void
    {
        $path = $this->createLogFile([
            $this->makeLine(['path' => '/img/logo.png']),
        ]);

        $result = $this->service->parse($path);

        $this->assertSame(0, $result['requests_human']);
    }

    public function testStaticWoff2IsNotCountedInRequestsHuman(): void
    {
        $path = $this->createLogFile([
            $this->makeLine(['path' => '/fonts/font.woff2']),
        ]);

        $result = $this->service->parse($path);

        $this->assertSame(0, $result['requests_human']);
    }

    // -----------------------------------------------------------------
    // Détection mobile/desktop
    // -----------------------------------------------------------------

    public function testIphoneUaIncrementsMobileCounter(): void
    {
        $path = $this->createLogFile([
            $this->makeLine(['path' => '/page', 'ua' => 'Mozilla/5.0 (iPhone; CPU iPhone OS 15_0)']),
        ]);

        $result = $this->service->parse($path);

        $this->assertSame(1, $result['mobile']);
        $this->assertSame(0, $result['desktop']);
    }

    public function testAndroidUaIncrementsMobileCounter(): void
    {
        $path = $this->createLogFile([
            $this->makeLine(['path' => '/page', 'ua' => 'Mozilla/5.0 (Linux; Android 11; Pixel 5)']),
        ]);

        $result = $this->service->parse($path);

        $this->assertSame(1, $result['mobile']);
        $this->assertSame(0, $result['desktop']);
    }

    public function testDesktopUaIncrementsDesktopCounter(): void
    {
        $path = $this->createLogFile([
            $this->makeLine(['path' => '/page', 'ua' => 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)']),
        ]);

        $result = $this->service->parse($path);

        $this->assertSame(0, $result['mobile']);
        $this->assertSame(1, $result['desktop']);
    }

    // -----------------------------------------------------------------
    // Funnel
    // -----------------------------------------------------------------

    public function testGetProductHtmlIncrementsViewsProductAndHourlyCounts(): void
    {
        $path = $this->createLogFile([
            $this->makeLine(['method' => 'GET', 'path' => '/produit.html', 'status' => '200', 'hour' => '14']),
        ]);

        $result = $this->service->parse($path);

        $this->assertSame(1, $result['views_product']);
        $this->assertSame(1, $result['hourly_product_views'][14]);
    }

    public function testPostPanierIncrementsCartAdds(): void
    {
        $path = $this->createLogFile([
            $this->makeLine(['method' => 'POST', 'path' => '/panier', 'status' => '200']),
        ]);

        $result = $this->service->parse($path);

        $this->assertSame(1, $result['cart_adds']);
    }

    public function testGetPanier200IncrementsViewsCart(): void
    {
        $path = $this->createLogFile([
            $this->makeLine(['method' => 'GET', 'path' => '/panier', 'status' => '200']),
        ]);

        $result = $this->service->parse($path);

        $this->assertSame(1, $result['views_cart']);
    }

    public function testGetCommande200IncrementsViewsCheckout(): void
    {
        $path = $this->createLogFile([
            $this->makeLine(['method' => 'GET', 'path' => '/commande', 'status' => '200']),
        ]);

        $result = $this->service->parse($path);

        $this->assertSame(1, $result['views_checkout']);
    }

    public function testPostCommandeIncrementsPostCheckout(): void
    {
        $path = $this->createLogFile([
            $this->makeLine(['method' => 'POST', 'path' => '/commande', 'status' => '200']),
        ]);

        $result = $this->service->parse($path);

        $this->assertSame(1, $result['post_checkout']);
    }

    // -----------------------------------------------------------------
    // Erreurs 500
    // -----------------------------------------------------------------

    public function testFront500IsCountedBeforeBotFilter(): void
    {
        // Bot UA — but 500 must still be counted
        $path = $this->createLogFile([
            $this->makeLine(['path' => '/page.html', 'status' => '500', 'ua' => 'AhrefsBot/7.0']),
        ]);

        $result = $this->service->parse($path);

        $this->assertSame(1, $result['errors_500_front']);
        $this->assertSame(0, $result['requests_human']);
    }

    public function testAdmin500IncrementsErrors500Bo(): void
    {
        $path = $this->createLogFile([
            $this->makeLine(['path' => '/admin9615/module/index', 'status' => '500']),
        ]);

        $result = $this->service->parse($path);

        $this->assertSame(1, $result['errors_500_bo']);
        $this->assertSame(0, $result['errors_500_front']);
    }

    public function testCheckout500IncrementsErrors500CheckoutAndAddsDetail(): void
    {
        $path = $this->createLogFile([
            $this->makeLine(['path' => '/commande', 'status' => '500', 'ip' => '5.5.5.5', 'hour' => '10']),
        ]);

        $result = $this->service->parse($path);

        $this->assertSame(1, $result['errors_500_checkout']);
        $this->assertCount(1, $result['errors_500_checkout_detail']);
        $detail = $result['errors_500_checkout_detail'][0];
        $this->assertSame('/commande', $detail['path']);
        $this->assertSame('5.5.5.5', $detail['ip']);
        $this->assertSame(10, $detail['hour']);
    }

    // -----------------------------------------------------------------
    // Top pages / top IPs
    // -----------------------------------------------------------------

    public function testPageCountsSortedDescending(): void
    {
        $lines = [];
        // /page-a.html hit 3 times, /page-b.html hit 5 times
        for ($i = 0; $i < 3; $i++) {
            $lines[] = $this->makeLine(['path' => '/page-a.html', 'status' => '200']);
        }
        for ($i = 0; $i < 5; $i++) {
            $lines[] = $this->makeLine(['path' => '/page-b.html', 'status' => '200']);
        }
        $path = $this->createLogFile($lines);

        $result = $this->service->parse($path);

        $counts = array_values($result['page_counts']);
        $this->assertGreaterThanOrEqual($counts[1], $counts[0], 'page_counts must be sorted descending');
    }

    public function testPageCountsCappedAt20Entries(): void
    {
        $lines = [];
        for ($i = 0; $i < 25; $i++) {
            $lines[] = $this->makeLine(['path' => '/page-' . $i . '.html', 'status' => '200', 'ip' => '1.2.3.' . ($i % 254 + 1)]);
        }
        $path = $this->createLogFile($lines);

        $result = $this->service->parse($path);

        $this->assertLessThanOrEqual(20, count($result['page_counts']));
    }

    // -----------------------------------------------------------------
    // Fichier gzip
    // -----------------------------------------------------------------

    public function testGzipFileProducesSameResultAsPlainLog(): void
    {
        $lines = [
            $this->makeLine(['path' => '/produit.html', 'status' => '200']),
            $this->makeLine(['method' => 'POST', 'path' => '/panier', 'status' => '200']),
        ];

        $plainPath = $this->createLogFile($lines);
        $gzPath    = $this->createGzLogFile($lines);

        $plainResult = $this->service->parse($plainPath);
        $gzResult    = $this->service->parse($gzPath);

        $this->assertSame($plainResult['requests_total'], $gzResult['requests_total']);
        $this->assertSame($plainResult['requests_human'], $gzResult['requests_human']);
        $this->assertSame($plainResult['views_product'], $gzResult['views_product']);
        $this->assertSame($plainResult['cart_adds'], $gzResult['cart_adds']);
    }

    // -----------------------------------------------------------------
    // Compteur hourly
    // -----------------------------------------------------------------

    public function testHourlyBreakdownAccumulatesPerHour(): void
    {
        $lines = [
            $this->makeLine(['path' => '/a.html', 'status' => '200', 'hour' => '08']),
            $this->makeLine(['path' => '/b.html', 'status' => '200', 'hour' => '08']),
            $this->makeLine(['path' => '/c.html', 'status' => '200', 'hour' => '20']),
        ];
        $path = $this->createLogFile($lines);

        $result = $this->service->parse($path);

        $this->assertSame(2, $result['hourly_product_views'][8]);
        $this->assertSame(1, $result['hourly_product_views'][20]);
        $this->assertSame(0, $result['hourly_product_views'][12]);
    }
}

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

class HttpLogParserService
{
    /**
     * Alwaysdata/Apache combined log format.
     * Optional leading hostname, then: IP - - [DD/Mon/YYYY:HH:mm:ss +TZ] "METHOD /path HTTP/x" STATUS size "ref" "ua"
     *
     * Groups: 1=IP, 2=hour(00-23), 3=minute(00-59), 4=second(00-59), 5=method, 6=path(no query),
     *         7=query string (with its "?", may be empty), 8=status, 9=ua(optional)
     */
    private const LOG_PATTERN = '/^(?:\S+\s+)?(\S+)\s+\S+\s+\S+\s+\[\d+\/\w+\/\d+:(\d{2}):(\d{2}):(\d{2})\s[^\]]+\]\s+"(\w+)\s+([^?"\ ]+)([^"\ ]*)[^"]*"\s+(\d{3})\s+\S+(?:\s+"[^"]*"\s+"([^"]*)")?/';

    /** Google IPs not identified by UA */
    private const BOT_IP_PREFIXES = ['74.125.'];

    /**
     * Crawlers left out of CrawlerAnalyserService::KNOWN_BOTS on purpose (that list
     * feeds blocking suggestions) but which are no visitors either.
     */
    private const SEARCH_ENGINE_BOTS = [
        'Googlebot', 'Google-InspectionTool', 'GoogleOther', 'AdsBot-Google', 'Mediapartners-Google',
        'Storebot-Google', 'bingbot', 'BingPreview', 'Applebot', 'Qwantbot', 'Amazonbot',
    ];

    private const STATIC_ASSETS_REGEX = '/\.(js|css|png|jpg|jpeg|gif|webp|avif|woff|woff2|svg|ico|map|ttf|eot|otf)$/i';

    private const ADMIN_PATH = '/admin9615/';

    private const TOP_LIMIT = 20;

    /** Checkout 500s kept in detail; errors_500_checkout keeps counting past it */
    private const CHECKOUT_DETAIL_LIMIT = 200;

    /** Distinct user agents remembered by isBot(); past it, answers are computed but not stored */
    private const BOT_CACHE_LIMIT = 10000;

    /** Faceted listing URL (ps_facetedsearch), as in LoadDiagnosticService */
    private const FACET_REGEX = '/[?&]q=/';

    /** Scraper thresholds, aligned on IpSuspicionScorer */
    private const SCRAPER_MIN_PAGES = 20;
    private const SCRAPER_FACET_SHARE = 0.8;

    private CrawlerAnalyserService $crawlerAnalyserService;

    /** Alternation of every bot name, built once per parse() */
    private string $botRegex = '';

    /** @var array<string, bool> ua => is a bot, shared by both passes */
    private array $botCache = [];

    public function __construct(CrawlerAnalyserService $crawlerAnalyserService)
    {
        $this->crawlerAnalyserService = $crawlerAnalyserService;
    }

    /**
     * Parse a full-day HTTP log file and return aggregated metrics.
     * Supports both plain text and gzip-compressed files.
     *
     * Two passes: the first profiles each IP, the second counts. A request only
     * counts as human when it comes from no declared bot, was not refused (403)
     * and its IP does not behave like a scraper; the rest goes to requests_scrapers.
     *
     * @throws \RuntimeException if the file cannot be opened
     */
    public function parse(string $logFilePath): array
    {
        $this->botRegex = $this->buildBotRegex(
            array_merge($this->crawlerAnalyserService->getKnownBots(), self::SEARCH_ENGINE_BOTS)
        );
        $this->botCache = [];
        $scraperIps = $this->findScraperIps($logFilePath);

        $counters = [
            'requests_total'              => 0,
            'requests_human'              => 0,
            'requests_scrapers'           => 0,
            'mobile'                      => 0,
            'desktop'                     => 0,
            'views_product'               => 0,
            'cart_adds'                   => 0,
            'views_cart'                  => 0,
            'views_checkout'              => 0,
            'post_checkout'               => 0,
            'errors_500_front'            => 0,
            'errors_500_bo'               => 0,
            'errors_500_checkout'         => 0,
            'errors_500_checkout_detail'  => [],
            'errors_500_front_pages'      => [],
            'errors_500_bo_pages'         => [],
            'hourly_product_views'               => array_fill(0, 24, 0),
            'page_counts'                 => [],
            'ip_counts'                   => [],
        ];

        $this->eachLine($logFilePath, function (string $line) use (&$counters, $scraperIps): void {
            $counters['requests_total']++;

            $r = $this->parseLine($line);
            if ($r === null) {
                return;
            }

            $ip     = $r['ip'];
            $hour   = $r['hour'];
            $method = $r['method'];
            $path   = $r['path'];
            $status = $r['status'];
            $ua     = $r['ua'];

            $isAdmin = strpos($path, self::ADMIN_PATH) !== false;

            // 500 errors — counted before bot filter to get all server errors
            // Categories are mutually exclusive: BO | checkout | front
            if ($status === 500) {
                if ($isAdmin) {
                    $counters['errors_500_bo']++;
                    $counters['errors_500_bo_pages'][$path] = ($counters['errors_500_bo_pages'][$path] ?? 0) + 1;
                } elseif (strpos($path, '/commande') !== false || strpos($path, '/panier') !== false) {
                    $counters['errors_500_checkout']++;
                    if (count($counters['errors_500_checkout_detail']) < self::CHECKOUT_DETAIL_LIMIT) {
                        $counters['errors_500_checkout_detail'][] = [
                            'path' => $path,
                            'ip'   => $ip,
                            'hour' => $hour,
                            'time' => $r['time'],
                        ];
                    }
                } else {
                    $counters['errors_500_front']++;
                    $counters['errors_500_front_pages'][$path] = ($counters['errors_500_front_pages'][$path] ?? 0) + 1;
                }
            }

            // Bot filter — skip for human metrics
            if ($this->isBot($ip, $ua)) {
                return;
            }

            // Skip static assets
            if (preg_match(self::STATIC_ASSETS_REGEX, $path)) {
                return;
            }

            // A refused request is not a visit; a scraper's pages are not audience
            if ($status === 403 || isset($scraperIps[$ip])) {
                $counters['requests_scrapers']++;

                return;
            }

            $counters['requests_human']++;
            $counters['ip_counts'][$ip] = ($counters['ip_counts'][$ip] ?? 0) + 1;

            // Mobile / Desktop detection
            if (stripos($ua, 'mobile') !== false
                || stripos($ua, 'android') !== false
                || stripos($ua, 'iphone') !== false
                || stripos($ua, 'ipad') !== false
            ) {
                $counters['mobile']++;
            } else {
                $counters['desktop']++;
            }

            if ($isAdmin) {
                return;
            }

            // Top pages (all human GET 200 non-asset non-admin)
            if ($method === 'GET' && $status === 200) {
                $counters['page_counts'][$path] = ($counters['page_counts'][$path] ?? 0) + 1;

                // Product pages (.html)
                if (str_ends_with($path, '.html')) {
                    $counters['views_product']++;
                    $counters['hourly_product_views'][$hour]++;
                }
            }

            // Funnel
            if ($method === 'POST' && str_starts_with($path, '/panier')) {
                $counters['cart_adds']++;
            }

            if ($method === 'GET' && str_starts_with($path, '/panier') && $status === 200) {
                $counters['views_cart']++;
            }

            if ($method === 'GET' && str_starts_with($path, '/commande') && $status === 200) {
                $counters['views_checkout']++;
            }

            if ($method === 'POST' && str_starts_with($path, '/commande')) {
                $counters['post_checkout']++;
            }
        });

        // Post-process: sort and cap top lists
        arsort($counters['page_counts']);
        $counters['page_counts'] = array_slice($counters['page_counts'], 0, self::TOP_LIMIT, true);

        arsort($counters['ip_counts']);
        $counters['ip_counts'] = array_slice($counters['ip_counts'], 0, self::TOP_LIMIT, true);

        arsort($counters['errors_500_front_pages']);
        $counters['errors_500_front_pages'] = array_slice($counters['errors_500_front_pages'], 0, 10, true);

        arsort($counters['errors_500_bo_pages']);
        $counters['errors_500_bo_pages'] = array_slice($counters['errors_500_bo_pages'], 0, 10, true);

        return $counters;
    }

    /**
     * First pass: flags the IPs whose day looks like a scraper's, with the same
     * criteria as IpSuspicionScorer (no static resource at all, or mostly facets).
     * Both require SCRAPER_MIN_PAGES pages so that a visitor with a warm browser
     * cache, who opens one filtered listing and nothing else, is never excluded.
     *
     * @return array<string, true>
     */
    private function findScraperIps(string $logFilePath): array
    {
        /** @var array<string, array{0: int, 1: int, 2: int}> $profiles ip => [requests, static, facets] */
        $profiles = [];

        $this->eachLine($logFilePath, function (string $line) use (&$profiles): void {
            $r = $this->parseLine($line);
            if ($r === null || $this->isBot($r['ip'], $r['ua'])) {
                return;
            }
            $p = $profiles[$r['ip']] ?? [0, 0, 0];
            ++$p[0];
            if (preg_match(self::STATIC_ASSETS_REGEX, $r['path'])) {
                ++$p[1];
            }
            if (preg_match(self::FACET_REGEX, $r['query'])) {
                ++$p[2];
            }
            $profiles[$r['ip']] = $p;
        });

        $scrapers = [];
        foreach ($profiles as $ip => [$requests, $static, $facets]) {
            if ($requests - $static < self::SCRAPER_MIN_PAGES) {
                continue;
            }
            if ($static === 0 || $facets / $requests >= self::SCRAPER_FACET_SHARE) {
                $scrapers[(string) $ip] = true;
            }
        }

        return $scrapers;
    }

    /**
     * @param callable(string): void $onLine called with each non-empty, right-trimmed line
     *
     * @throws \RuntimeException if the file cannot be opened
     */
    private function eachLine(string $logFilePath, callable $onLine): void
    {
        $isGz = str_ends_with($logFilePath, '.gz');
        $handle = $isGz ? @gzopen($logFilePath, 'rb') : @fopen($logFilePath, 'rb');

        if ($handle === false) {
            throw new \RuntimeException('Cannot open log file: ' . $logFilePath);
        }

        try {
            while (($line = $isGz ? gzgets($handle) : fgets($handle)) !== false) {
                $line = rtrim($line);
                if ($line !== '') {
                    $onLine($line);
                }
            }
        } finally {
            $isGz ? gzclose($handle) : fclose($handle);
        }
    }

    /**
     * @return array{ip: string, hour: int, time: string, method: string, path: string, query: string, status: int, ua: string}|null
     */
    private function parseLine(string $line): ?array
    {
        if (!preg_match(self::LOG_PATTERN, $line, $m)) {
            return null;
        }

        return [
            'ip'     => $m[1],
            'hour'   => (int) $m[2],
            'time'   => $m[2] . ':' . $m[3] . ':' . $m[4],
            'method' => strtoupper($m[5]),
            'path'   => $m[6],
            'query'  => $m[7],
            'status' => (int) $m[8],
            'ua'     => $m[9] ?? '',
        ];
    }

    /**
     * @param string[] $bots
     */
    private function buildBotRegex(array $bots): string
    {
        $quoted = array_map(static fn (string $bot): string => preg_quote($bot, '/'), $bots);

        return '/' . implode('|', $quoted) . '/i';
    }

    private function isBot(string $ip, string $ua): bool
    {
        foreach (self::BOT_IP_PREFIXES as $prefix) {
            if (strncmp($ip, $prefix, strlen($prefix)) === 0) {
                return true;
            }
        }

        if (isset($this->botCache[$ua])) {
            return $this->botCache[$ua];
        }

        $isBot = preg_match($this->botRegex, $ua) === 1;
        if (count($this->botCache) < self::BOT_CACHE_LIMIT) {
            $this->botCache[$ua] = $isBot;
        }

        return $isBot;
    }
}

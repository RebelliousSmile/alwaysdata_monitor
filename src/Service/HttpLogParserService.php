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
     * Groups: 1=IP, 2=hour(00-23), 3=method, 4=path(no query), 5=status, 6=ua(optional)
     */
    private const LOG_PATTERN = '/^(?:\S+\s+)?(\S+)\s+\S+\s+\S+\s+\[\d+\/\w+\/\d+:(\d{2}):\d+:\d+\s[^\]]+\]\s+"(\w+)\s+([^?"\ ]+)[^"]*"\s+(\d{3})\s+\S+(?:\s+"[^"]*"\s+"([^"]*)")?/';

    /** Google IPs not identified by UA */
    private const BOT_IP_PREFIXES = ['74.125.'];

    private const STATIC_ASSETS_REGEX = '/\.(js|css|png|jpg|jpeg|gif|webp|avif|woff|woff2|svg|ico|map|ttf|eot|otf)$/i';

    private const ADMIN_PATH = '/admin9615/';

    private const TOP_LIMIT = 20;

    private CrawlerAnalyserService $crawlerAnalyserService;

    public function __construct(CrawlerAnalyserService $crawlerAnalyserService)
    {
        $this->crawlerAnalyserService = $crawlerAnalyserService;
    }

    /**
     * Parse a full-day HTTP log file and return aggregated metrics.
     * Supports both plain text and gzip-compressed files.
     *
     * @throws \RuntimeException if the file cannot be opened
     */
    public function parse(string $logFilePath): array
    {
        $isGz = str_ends_with($logFilePath, '.gz');
        $handle = $isGz ? gzopen($logFilePath, 'rb') : fopen($logFilePath, 'rb');

        if ($handle === false) {
            throw new \RuntimeException('Cannot open log file: ' . $logFilePath);
        }

        $knownBots = $this->crawlerAnalyserService->getKnownBots();

        $counters = [
            'requests_total'              => 0,
            'requests_human'              => 0,
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
            'hourly_counts'               => array_fill(0, 24, 0),
            'page_counts'                 => [],
            'ip_counts'                   => [],
        ];

        try {
            while (true) {
                $line = $isGz ? gzgets($handle) : fgets($handle);
                if ($line === false) {
                    break;
                }

                $line = rtrim($line);
                if ($line === '') {
                    continue;
                }

                $counters['requests_total']++;

                if (!preg_match(self::LOG_PATTERN, $line, $m)) {
                    continue;
                }

                $ip     = $m[1];
                $hour   = (int) $m[2];
                $method = strtoupper($m[3]);
                $path   = $m[4];
                $status = (int) $m[5];
                $ua     = $m[6] ?? '';

                $isAdmin = strpos($path, self::ADMIN_PATH) !== false;

                // 500 errors — counted before bot filter to get all server errors
                if ($status === 500) {
                    if ($isAdmin) {
                        $counters['errors_500_bo']++;
                    } else {
                        $counters['errors_500_front']++;
                    }
                    if (strpos($path, '/commande') !== false) {
                        $counters['errors_500_checkout']++;
                        $counters['errors_500_checkout_detail'][] = [
                            'path' => $path,
                            'ip'   => $ip,
                            'hour' => $hour,
                        ];
                    }
                }

                // Bot filter — skip for human metrics
                if ($this->isBot($ip, $ua, $knownBots)) {
                    continue;
                }

                // Skip static assets
                if (preg_match(self::STATIC_ASSETS_REGEX, $path)) {
                    continue;
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
                    continue;
                }

                // Top pages (all human GET 200 non-asset non-admin)
                if ($method === 'GET' && $status === 200) {
                    $counters['page_counts'][$path] = ($counters['page_counts'][$path] ?? 0) + 1;

                    // Product pages (.html)
                    if (str_ends_with($path, '.html')) {
                        $counters['views_product']++;
                        $counters['hourly_counts'][$hour]++;
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
            }
        } finally {
            $isGz ? gzclose($handle) : fclose($handle);
        }

        // Post-process: sort and cap top lists
        arsort($counters['page_counts']);
        $counters['page_counts'] = array_slice($counters['page_counts'], 0, self::TOP_LIMIT, true);

        arsort($counters['ip_counts']);
        $counters['ip_counts'] = array_slice($counters['ip_counts'], 0, self::TOP_LIMIT, true);

        return $counters;
    }

    private function isBot(string $ip, string $ua, array $knownBots): bool
    {
        foreach (self::BOT_IP_PREFIXES as $prefix) {
            if (strncmp($ip, $prefix, strlen($prefix)) === 0) {
                return true;
            }
        }

        foreach ($knownBots as $bot) {
            if (stripos($ua, $bot) !== false) {
                return true;
            }
        }

        return false;
    }
}

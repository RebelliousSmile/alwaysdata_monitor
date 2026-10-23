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

/**
 * HTTP load diagnostic for one day of Alwaysdata logs.
 *
 * PHP port of the diag-site-a.sh investigation script (CPU saturation / 503
 * caused by facet scrapers). The shell script re-reads the log once per
 * section; this service computes every section in a single streaming pass so it
 * can run inside a back-office request without holding a FastCGI worker for
 * minutes.
 */
class LoadDiagnosticService
{
    /**
     * Alwaysdata format: host IP - - [date] "METHOD URL PROTO" status bytes "referer" "user-agent" https time
     * Groups: 1=IP, 2=hour, 3=minute, 4=request line, 5=status, 6=referer, 7=user-agent, 8=trailing fields
     */
    private const LOG_PATTERN = '/^(?:\S+\s+)?(\S+)\s+\S+\s+\S+\s+\[\d+\/\w+\/\d+:(\d{2}):(\d{2}):\d{2}[^\]]*\]\s+"([^"]*)"\s+(\d{3})\s+\S+(?:\s+"([^"]*)"\s+"([^"]*)")?(.*)$/';

    private const STATIC_REGEX = '/\.(jpe?g|png|webp|avif|gif|svg|css|js|woff2?|ttf|ico)$/i';

    private const FACET_REGEX = '/[?&]q=/';

    private const SEARCH_REGEX = '/controller=search|\/recherche/';

    private const LOGIN_PATH = '/connexion';

    /** "/", "/index.php" or a bare language prefix ("/fr", "/en-us/") */
    private const HOMEPAGE_REGEX = '#^/(index\.php|[a-z]{2}(-[a-z]{2})?/?)?$#i';

    /** A blocked human gives up after a few 403s; beyond that, human signals are suspect */
    private const HUMAN_MAX_PAGES = 30;

    /** Declared bots counted in section 3, on top of CrawlerAnalyserService's list */
    private const EXTRA_BOTS = [
        'Claude-User', 'Amazonbot', 'ImagesiftBot', 'Barkrowler', 'bingbot', 'Googlebot',
        'Applebot', 'OAI-SearchBot', 'TikTokSpider', 'AionBot',
    ];

    private const TOP_LIMIT = 20;

    /**
     * Counter maps are pruned to their PRUNE_KEEP biggest entries once they
     * exceed PRUNE_AT keys, so a scraper hitting millions of unique URLs cannot
     * exhaust memory. Tops stay exact unless an entry was pruned early on and
     * came back massively later, which does not happen with real traffic.
     */
    private const PRUNE_AT = 200000;
    private const PRUNE_KEEP = 50000;

    /** Reverse DNS has no timeout control: stop resolving once this budget is spent */
    private const RDNS_BUDGET_SECONDS = 10.0;

    private CrawlerAnalyserService $crawlerAnalyserService;

    private IpSuspicionScorer $scorer;

    /** @var callable(string): ?string */
    private $reverseDns;

    /**
     * @param (callable(string): ?string)|null $reverseDns injectable for tests
     */
    public function __construct(CrawlerAnalyserService $crawlerAnalyserService, ?IpSuspicionScorer $scorer = null, ?callable $reverseDns = null)
    {
        $this->crawlerAnalyserService = $crawlerAnalyserService;
        $this->scorer = $scorer ?? new IpSuspicionScorer();
        $this->reverseDns = $reverseDns ?? static function (string $ip): ?string {
            $host = @gethostbyaddr($ip);

            return is_string($host) && $host !== $ip ? $host : null;
        };
    }

    /**
     * @param string $logFilePath plain or gzip HTTP log
     * @param string[] $shopHosts hostnames whose referers count as internal navigation
     *
     * @return array<string, mixed>
     *
     * @throws \RuntimeException if the file cannot be opened
     */
    public function analyse(string $logFilePath, array $shopHosts): array
    {
        $isGz = str_ends_with($logFilePath, '.gz');
        $handle = $isGz ? @gzopen($logFilePath, 'rb') : @fopen($logFilePath, 'rb');
        if ($handle === false) {
            throw new \RuntimeException('Cannot open log file: ' . $logFilePath);
        }

        $internalHosts = [];
        foreach ($shopHosts as $host) {
            $internalHosts[$this->normalizeHost($host)] = true;
        }
        [$botRegex, $botNames] = $this->buildBotMatcher();

        $total = 0;
        $unparsed = 0;
        $static = 0;
        $timeTotal = 0.0;
        $bots = [];
        $urls = [];
        $ips = [];
        $uas = [];
        $hourly = array_fill(0, 24, 0);
        $hourlyRefused = array_fill(0, 24, 0);
        $hourlyTime = array_fill(0, 24, 0.0);
        $search = 0;
        $login = ['GET' => 0, 'POST' => 0];
        $facet = [
            'count' => 0, 'time' => 0.0, 'ips' => [], 'statuses' => [],
            'origin' => ['vide' => 0, 'interne' => 0, 'externe' => 0],
            'referers' => [], 'external_uas' => [],
        ];

        try {
            while (($line = $isGz ? gzgets($handle) : fgets($handle)) !== false) {
                $line = rtrim($line);
                if ($line === '') {
                    continue;
                }
                ++$total;

                $parsed = $this->parseLine($line);
                if ($parsed === null) {
                    ++$unparsed;
                    continue;
                }
                ['ip' => $ip, 'hour' => $hour, 'method' => $method, 'url' => $url, 'path' => $path,
                    'status' => $status, 'referer' => $referer, 'ua' => $ua, 'time' => $time] = $parsed;

                $timeTotal += $time;
                $hourly[$hour] = ($hourly[$hour] ?? 0) + 1;
                $hourlyTime[$hour] = ($hourlyTime[$hour] ?? 0.0) + $time;
                // A blocked scraper still shows up in the log: only its status tells it was turned away
                if ($status === '403') {
                    $hourlyRefused[$hour] = ($hourlyRefused[$hour] ?? 0) + 1;
                }
                $this->bump($ips, $ip);
                $this->bump($uas, $ua);
                $this->bump($urls, $path);

                if ($ua !== '' && preg_match($botRegex, $ua, $bm)) {
                    $bot = $botNames[strtolower($bm[1])];
                    $bots[$bot] = ($bots[$bot] ?? 0) + 1;
                }

                if (preg_match(self::STATIC_REGEX, $path)) {
                    ++$static;
                }

                if (preg_match(self::SEARCH_REGEX, $url)) {
                    ++$search;
                }

                if (str_starts_with($path, self::LOGIN_PATH) && isset($login[$method])) {
                    ++$login[$method];
                }

                if (!preg_match(self::FACET_REGEX, $url)) {
                    continue;
                }

                ++$facet['count'];
                $facet['time'] += $time;
                $this->bump($facet['ips'], $ip);
                $facet['statuses'][$status] = ($facet['statuses'][$status] ?? 0) + 1;

                $origin = $this->refererOrigin($referer, $internalHosts);
                ++$facet['origin'][$origin];
                if ($origin === 'externe') {
                    $this->bump($facet['referers'], explode('?', $referer, 2)[0]);
                    $this->bump($facet['external_uas'], $ua);
                }
            }
        } finally {
            $isGz ? gzclose($handle) : fclose($handle);
        }

        arsort($bots);
        arsort($facet['statuses']);

        $topIps = $this->toList($ips, self::TOP_LIMIT);
        $facetTopIps = $this->toList($facet['ips'], self::TOP_LIMIT);
        $profiledIps = array_values(array_unique(array_merge(array_column($topIps, 'value'), array_column($facetTopIps, 'value'))));

        return [
            'total' => $total,
            'unparsed' => $unparsed,
            'static' => $static,
            'time_total' => round($timeTotal, 1),
            'bots' => $this->toList($bots, count($bots)),
            'top_urls' => $this->toList($urls, 25),
            'top_ips' => $topIps,
            'ip_profiles' => $this->profileIps($logFilePath, $profiledIps, $botRegex, $botNames),
            'top_uas' => $this->toList($uas, 15),
            'hourly' => $hourly,
            'hourly_refused' => $hourlyRefused,
            'hourly_time' => array_map(static fn (float $t): float => round($t, 1), $hourlyTime),
            'search' => $search,
            'login' => $login,
            'facets' => [
                'count' => $facet['count'],
                'time' => round($facet['time'], 1),
                'distinct_ips' => count($facet['ips']),
                'origin' => $facet['origin'],
                'statuses' => $this->toList($facet['statuses'], count($facet['statuses'])),
                'top_ips' => $facetTopIps,
                'top_referers' => $this->toList($facet['referers'], 10),
                'external_uas' => $this->toList($facet['external_uas'], 10),
            ],
        ];
    }

    /**
     * @return array{ip: string, hour: int, minute: int, method: string, url: string, path: string,
     *               status: string, referer: string, ua: string, time: float}|null
     */
    private function parseLine(string $line): ?array
    {
        if (!preg_match(self::LOG_PATTERN, $line, $m)) {
            return null;
        }
        $request = explode(' ', $m[4]);
        $url = $request[1] ?? '';

        return [
            'ip' => $m[1],
            'hour' => (int) $m[2],
            'minute' => (int) $m[3],
            'method' => strtoupper($request[0]),
            'url' => $url,
            'path' => explode('?', $url, 2)[0],
            'status' => $m[5],
            'referer' => $m[6] ?? '-',
            'ua' => $m[7] ?? '',
            'time' => $this->responseTime($m[8] ?? ''),
        ];
    }

    /**
     * Second pass restricted to the top IPs: keeping per-IP behaviour for every
     * visitor of the day in the first pass would cost far more memory than
     * re-reading the file once.
     *
     * @param string[] $targets
     * @param array<string, string> $botNames
     *
     * @return array<int, array<string, mixed>>
     */
    private function profileIps(string $logFilePath, array $targets, string $botRegex, array $botNames): array
    {
        if ($targets === []) {
            return [];
        }
        $stats = [];
        foreach ($targets as $ip) {
            $stats[$ip] = [
                'requests' => 0, 'static' => 0, 'facets' => 0, 'refused' => 0,
                'empty_referer_pages' => 0, 'uas' => [], 'minutes' => [], 'bot' => null,
            ];
        }

        $isGz = str_ends_with($logFilePath, '.gz');
        $handle = $isGz ? @gzopen($logFilePath, 'rb') : @fopen($logFilePath, 'rb');
        if ($handle === false) {
            return [];
        }
        try {
            while (($line = $isGz ? gzgets($handle) : fgets($handle)) !== false) {
                $p = $this->parseLine(rtrim($line));
                if ($p === null || !isset($stats[$p['ip']])) {
                    continue;
                }
                $s = &$stats[$p['ip']];
                ++$s['requests'];
                if (preg_match(self::STATIC_REGEX, $p['path'])) {
                    ++$s['static'];
                } elseif ($p['referer'] === '' || $p['referer'] === '-') {
                    ++$s['empty_referer_pages'];
                }
                if (preg_match(self::FACET_REGEX, $p['url'])) {
                    ++$s['facets'];
                }
                if ($p['status'] === '403') {
                    ++$s['refused'];
                }
                if (count($s['uas']) < 50 || isset($s['uas'][$p['ua']])) {
                    $s['uas'][$p['ua']] = ($s['uas'][$p['ua']] ?? 0) + 1;
                }
                $minute = $p['hour'] * 60 + $p['minute'];
                $s['minutes'][$minute] = ($s['minutes'][$minute] ?? 0) + 1;
                if ($s['bot'] === null && $p['ua'] !== '' && preg_match($botRegex, $p['ua'], $bm)) {
                    $s['bot'] = $botNames[strtolower($bm[1])];
                }
                unset($s);
            }
        } finally {
            $isGz ? gzclose($handle) : fclose($handle);
        }

        $profiles = [];
        $rdnsDeadline = microtime(true) + self::RDNS_BUDGET_SECONDS;
        foreach ($stats as $ip => $s) {
            $ip = (string) $ip;
            $rdns = microtime(true) < $rdnsDeadline ? ($this->reverseDns)($ip) : null;
            $s['peak_minute'] = $s['minutes'] === [] ? 0 : max($s['minutes']);
            $total = max(1, $s['requests']);
            $profiles[] = [
                'ip' => $ip,
                'rdns' => $rdns,
                'requests' => $s['requests'],
                'static_pct' => (int) round($s['static'] * 100 / $total),
                'facet_pct' => (int) round($s['facets'] * 100 / $total),
                'refused_pct' => (int) round($s['refused'] * 100 / $total),
                'ua_count' => count($s['uas']),
                'peak_minute' => $s['peak_minute'],
            ] + $this->scorer->score($s, $rdns, $s['bot']);
        }

        return $profiles;
    }

    /**
     * Looks for real visitors among blocked IPs, so a wrongly blocked customer can be released.
     *
     * A scraper hammers deep URLs (facets) without referer. A human blocked by
     * mistake arrives like a human: from a search engine or social network
     * (external referer) or on the homepage, gets a 403, retries a few times and
     * leaves. Many requests with such signals rather point to a scraper forging
     * its referer, or to a shared IP: to check by hand.
     *
     * @param string[] $blockedIps values of the "Require not ip" rules (single IPs or CIDR)
     * @param string[] $shopHosts hostnames whose referers count as internal navigation
     *
     * @return array{seen: array<int, array<string, mixed>>, absent: string[]}
     */
    public function auditBlockedIps(string $logFilePath, array $blockedIps, array $shopHosts): array
    {
        $exact = [];
        $ranges = [];
        foreach ($blockedIps as $rule) {
            if (str_contains($rule, '/')) {
                $ranges[] = $rule;
            } else {
                $exact[$rule] = $rule;
            }
        }
        $internalHosts = [];
        foreach ($shopHosts as $host) {
            $internalHosts[$this->normalizeHost($host)] = true;
        }

        $stats = [];
        $ruleOf = [];
        $isGz = str_ends_with($logFilePath, '.gz');
        $handle = $isGz ? @gzopen($logFilePath, 'rb') : @fopen($logFilePath, 'rb');
        if ($handle === false) {
            throw new \RuntimeException('Cannot open log file: ' . $logFilePath);
        }
        try {
            while (($line = $isGz ? gzgets($handle) : fgets($handle)) !== false) {
                $p = $this->parseLine(rtrim($line));
                if ($p === null) {
                    continue;
                }
                $ip = $p['ip'];
                if (!array_key_exists($ip, $ruleOf)) {
                    $ruleOf[$ip] = $exact[$ip] ?? $this->matchRange($ip, $ranges);
                }
                if ($ruleOf[$ip] === null) {
                    continue;
                }
                $s = &$stats[$ip];
                $s ??= [
                    'rule' => $ruleOf[$ip], 'requests' => 0, 'pages' => 0, 'homepage' => 0, 'external' => 0,
                    'facets' => 0, 'referers' => [], 'uas' => [], 'first' => null, 'last' => null,
                ];
                ++$s['requests'];
                $time = sprintf('%02d:%02d', $p['hour'], $p['minute']);
                $s['first'] ??= $time;
                $s['last'] = $time;
                if (preg_match(self::STATIC_REGEX, $p['path'])) {
                    unset($s);
                    continue;
                }
                ++$s['pages'];
                if (preg_match(self::HOMEPAGE_REGEX, $p['path'])) {
                    ++$s['homepage'];
                }
                if (preg_match(self::FACET_REGEX, $p['url'])) {
                    ++$s['facets'];
                }
                if ($this->refererOrigin($p['referer'], $internalHosts) === 'externe') {
                    ++$s['external'];
                    $host = (string) (parse_url($p['referer'], PHP_URL_HOST) ?: $p['referer']);
                    $s['referers'][$host] = ($s['referers'][$host] ?? 0) + 1;
                }
                if (count($s['uas']) < 20 || isset($s['uas'][$p['ua']])) {
                    $s['uas'][$p['ua']] = ($s['uas'][$p['ua']] ?? 0) + 1;
                }
                unset($s);
            }
        } finally {
            $isGz ? gzclose($handle) : fclose($handle);
        }

        $rank = ['humain' => 0, 'a_verifier' => 1, 'robot' => 2];
        $seen = [];
        $matchedRules = [];
        foreach ($stats as $ip => $s) {
            $matchedRules[$s['rule']] = true;
            $signals = $s['homepage'] + $s['external'];
            $verdict = $signals === 0 ? 'robot' : ($s['pages'] <= self::HUMAN_MAX_PAGES ? 'humain' : 'a_verifier');
            arsort($s['uas']);
            $seen[] = [
                'ip' => (string) $ip,
                'rule' => $s['rule'],
                'verdict' => $verdict,
                'requests' => $s['requests'],
                'pages' => $s['pages'],
                'homepage' => $s['homepage'],
                'external' => $s['external'],
                'facet_pct' => $s['pages'] ? (int) round($s['facets'] * 100 / $s['pages']) : 0,
                'referers' => $this->toList($s['referers'], 5),
                'ua' => (string) array_key_first($s['uas']),
                'ua_count' => count($s['uas']),
                'first' => $s['first'],
                'last' => $s['last'],
            ];
        }
        usort($seen, static fn (array $a, array $b): int => [$rank[$a['verdict']], $b['requests']] <=> [$rank[$b['verdict']], $a['requests']]);

        return [
            'seen' => $seen,
            'absent' => array_values(array_filter($blockedIps, static fn (string $r): bool => !isset($matchedRules[$r]))),
        ];
    }

    /**
     * @param string[] $ranges CIDR notations, IPv4 or IPv6
     */
    private function matchRange(string $ip, array $ranges): ?string
    {
        $addr = @inet_pton($ip);
        if ($addr === false) {
            return null;
        }
        foreach ($ranges as $range) {
            [$net, $bits] = explode('/', $range, 2) + [1 => ''];
            $netAddr = @inet_pton($net);
            if ($netAddr === false || strlen($netAddr) !== strlen($addr) || !ctype_digit($bits)) {
                continue;
            }
            $bits = min((int) $bits, strlen($addr) * 8);
            $bytes = intdiv($bits, 8);
            if (substr($addr, 0, $bytes) !== substr($netAddr, 0, $bytes)) {
                continue;
            }
            $rest = $bits % 8;
            if ($rest === 0) {
                return $range;
            }
            $mask = (0xFF << (8 - $rest)) & 0xFF;
            if ((ord($addr[$bytes]) & $mask) === (ord($netAddr[$bytes]) & $mask)) {
                return $range;
            }
        }

        return null;
    }

    /**
     * @param array<string, int> $map
     */
    private function bump(array &$map, string $key): void
    {
        $map[$key] = ($map[$key] ?? 0) + 1;
        if (count($map) > self::PRUNE_AT) {
            arsort($map);
            $map = array_slice($map, 0, self::PRUNE_KEEP, true);
        }
    }

    /**
     * Keys are returned as strings inside a list: a JSON object would reorder
     * numeric keys (status codes) and cast numeric-looking IPs.
     *
     * @param array<string|int, int> $map
     *
     * @return array<int, array{value: string, count: int}>
     */
    private function toList(array $map, int $limit): array
    {
        arsort($map);
        $list = [];
        foreach (array_slice($map, 0, $limit, true) as $value => $count) {
            $list[] = ['value' => (string) $value, 'count' => $count];
        }

        return $list;
    }

    /**
     * Alwaysdata appends "https time": the response time in seconds is the last field.
     */
    private function responseTime(string $trailing): float
    {
        $fields = preg_split('/\s+/', trim($trailing));
        $last = $fields === false ? '' : (string) end($fields);

        return is_numeric($last) ? (float) $last : 0.0;
    }

    /**
     * @param array<string, bool> $internalHosts
     */
    private function refererOrigin(string $referer, array $internalHosts): string
    {
        if ($referer === '' || $referer === '-') {
            return 'vide';
        }
        $host = parse_url($referer, PHP_URL_HOST);
        if (is_string($host) && isset($internalHosts[$this->normalizeHost($host)])) {
            return 'interne';
        }

        return 'externe';
    }

    private function normalizeHost(string $host): string
    {
        $host = strtolower(trim($host));

        return str_starts_with($host, 'www.') ? substr($host, 4) : $host;
    }

    /**
     * @return array{0: string, 1: array<string, string>} regex + lowercase => display name
     */
    private function buildBotMatcher(): array
    {
        $names = [];
        foreach (array_merge($this->crawlerAnalyserService->getKnownBots(), self::EXTRA_BOTS) as $bot) {
            $names[strtolower($bot)] = $bot;
        }
        // Longest first so "Applebot-Extended" wins over "Applebot"
        $keys = array_keys($names);
        usort($keys, static fn (string $a, string $b): int => strlen($b) <=> strlen($a));
        $alternation = implode('|', array_map(static fn (string $k): string => preg_quote($k, '/'), $keys));

        return ['/(' . $alternation . ')/i', $names];
    }
}

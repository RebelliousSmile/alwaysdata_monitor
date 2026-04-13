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

class CrawlerAnalyserService
{
    private const KNOWN_BOTS = [
        // SEO scrapers
        'AhrefsBot',
        'SemrushBot',
        'DotBot',
        'MJ12bot',
        'DataForSeoBot',
        'BLEXBot',
        'rogerbot',
        'linkdexbot',
        'serpstatbot',
        'SEOkicks',
        'MegaIndex',
        'seoscanners',
        'SurdotlyBot',
        'MauiBot',
        'ZoominfoBot',
        'Screaming Frog',
        // AI crawlers
        'GPTBot',
        'ClaudeBot',
        'CCBot',
        'anthropic-ai',
        'Bytespider',
        'Applebot-Extended',
        'cohere-ai',
        'PerplexityBot',
        'YouBot',
        // Social / Meta crawlers
        'meta-externalagent',
        'facebookexternalhit',
        'Facebot',
        'Twitterbot',
        'LinkedInBot',
        'Pinterest',
        'Slackbot',
        'TelegramBot',
        'WhatsApp',
        'Discordbot',
        // Asian search engines
        'YandexBot',
        'Baiduspider',
        'Sogou',
        '360Spider',
        'PetalBot',
        // Archiving / other aggressive
        'ia_archiver',
        'Exabot',
        'Nutch',
        'SeznamBot',
        'DuckDuckBot',
        'archive.org_bot',
    ];

    private const HIGH_FREQ_THRESHOLD = 200;

    private const MAX_RESULTS = 50;

    // Alwaysdata HTTP log format: hostname ip ident authuser [date] "request" status size "referer" "ua" proto time
    // Standard Apache format:            ip ident authuser [date] "request" status size "referer" "ua"
    // Both are handled: skip optional leading hostname, capture IP, skip 2 dashes, parse rest.
    private const LOG_PATTERN = '/^(?:\S+\s+)?(\d[\d.:a-fA-F]+)\s+\S+\s+\S+\s+\[.*?\]\s+"[^"]*"\s+\d+\s+\S+(?:\s+"[^"]*"\s+"([^"]*)")?/';

    public function getKnownBots(): array
    {
        return self::KNOWN_BOTS;
    }

    public function analyse(array $logSources): array
    {
        /** @var array<string, array{uas: array<string, bool>, count: int}> $ipData */
        $ipData = [];

        foreach ($logSources as $source) {
            if (!isset($source['source'], $source['lines'])) {
                continue;
            }

            $sourceName = (string) $source['source'];
            if ($sourceName !== 'apache' && $sourceName !== 'http') {
                continue;
            }

            if ($source['error'] !== null) {
                continue;
            }

            foreach ((array) $source['lines'] as $line) {
                if (!is_string($line) || $line === '') {
                    continue;
                }

                // Skip back-office requests (admin panel traffic is not public crawlers)
                if (strpos($line, '/admin') !== false && preg_match('#/admin\w+/#', $line)) {
                    continue;
                }

                if (!preg_match(self::LOG_PATTERN, $line, $matches)) {
                    continue;
                }

                $ip = $matches[1];
                $ua = isset($matches[2]) ? $matches[2] : '';

                if (!isset($ipData[$ip])) {
                    $ipData[$ip] = ['uas' => [], 'count' => 0];
                }

                ++$ipData[$ip]['count'];

                if ($ua !== '') {
                    $ipData[$ip]['uas'][$ua] = true;
                }
            }
        }

        // Known bots grouped by bot name; high-frequency kept per IP
        /** @var array<string, array{ips: string[], user_agents: array<string,bool>, request_count: int}> $botGroups */
        $botGroups      = [];
        $highFreqByIp   = [];

        foreach ($ipData as $ip => $data) {
            $matchedBot = null;

            foreach (array_keys($data['uas']) as $ua) {
                foreach (self::KNOWN_BOTS as $bot) {
                    if (stripos($ua, $bot) !== false) {
                        $matchedBot = $bot;
                        break 2;
                    }
                }
            }

            if ($matchedBot !== null) {
                if (!isset($botGroups[$matchedBot])) {
                    $botGroups[$matchedBot] = ['ips' => [], 'user_agents' => [], 'request_count' => 0];
                }
                $botGroups[$matchedBot]['ips'][] = $ip;
                $botGroups[$matchedBot]['request_count'] += $data['count'];
                foreach (array_keys($data['uas']) as $ua) {
                    $botGroups[$matchedBot]['user_agents'][$ua] = true;
                }
            } elseif ($data['count'] >= self::HIGH_FREQ_THRESHOLD) {
                $highFreqByIp[$ip] = [
                    'ips'           => [$ip],
                    'user_agents'   => array_keys($data['uas']),
                    'request_count' => $data['count'],
                    'reason'        => 'high_frequency',
                    'matched_bot'   => null,
                ];
            }
        }

        $candidates = [];

        foreach ($botGroups as $botName => $group) {
            $candidates[] = [
                'ips'           => $group['ips'],
                'user_agents'   => array_keys($group['user_agents']),
                'request_count' => $group['request_count'],
                'reason'        => 'known_bot',
                'matched_bot'   => $botName,
            ];
        }

        foreach ($highFreqByIp as $entry) {
            $candidates[] = $entry;
        }

        usort($candidates, function (array $a, array $b): int {
            return $b['request_count'] - $a['request_count'];
        });

        return array_slice($candidates, 0, self::MAX_RESULTS);
    }
}

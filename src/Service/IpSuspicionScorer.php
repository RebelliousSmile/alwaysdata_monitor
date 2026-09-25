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
 * Turns one IP's behaviour over a day into a 0-100 suspicion index.
 *
 * No single signal is reliable: a mobile operator's CGNAT IP carries hundreds
 * of real customers with many user-agents, while a scraper on a residential
 * proxy looks like a home connection. The index therefore adds weighted
 * signals and subtracts points for a consumer ISP network, where blocking
 * an IP is most likely to hit innocent visitors.
 */
class IpSuspicionScorer
{
    public const LEVEL_HIGH = 70;
    public const LEVEL_MEDIUM = 40;

    /** Checked before ISP patterns: hosting names are specific, ISP ones partly generic */
    private const HOSTING_PATTERNS = [
        'amazonaws', 'compute.amazon', 'googleusercontent', 'cloudapp', 'azure', 'ovh', 'kimsufi',
        'hetzner', 'your-server.de', 'digitalocean', 'linode', 'akamai', 'vultr', 'choopa', 'contabo',
        'scaleway', 'online.net', 'poneytelecom', 'alibaba', 'aliyun', 'tencent', 'huaweicloud',
        'oraclecloud', 'leaseweb', 'hostinger', 'ionos', 'm247', 'datacamp', 'colocrossing', 'psychz',
        'hosting', 'vps', 'server', 'dedicated', 'cloud',
    ];

    private const ISP_PATTERNS = [
        'orange', 'wanadoo', 'free.fr', 'proxad', 'sfr', 'neufbox', 'numericable', 'bbox',
        'bouyguestelecom', 'bytel', 'skynet', 'proximus', 'swisscom', 'telenet', 'vodafone', 'telekom',
        't-ipconnect', 'btcentralplus', 'virginm', 'comcast', 'verizon', 'dsl', 'dyn', 'cable',
        'fibre', 'fiber', 'mobile', 'pool', 'ftth',
    ];

    /** Search engine => domains its genuine crawlers reverse-resolve to */
    private const SEARCH_ENGINES = [
        'googlebot'   => ['googlebot.com', 'google.com'],
        'bingbot'     => ['search.msn.com'],
        'applebot'    => ['applebot.apple.com'],
        'duckduckbot' => ['duckduckgo.com'],
    ];

    private const NON_BROWSER_UA = '/^$|curl|wget|python|go-http|java\/|libwww|scrapy|httpclient|axios|node-fetch|okhttp|guzzle|headless/i';

    /**
     * @param array{
     *     requests: int, static: int, facets: int, refused: int, empty_referer_pages: int,
     *     uas: array<string, int>, peak_minute: int
     * } $stats
     * @param string|null $rdns reverse DNS host, null when not resolved
     * @param string|null $bot  declared bot name matched in the UA
     *
     * @return array{score: int, level: string, network: string, reasons: array<int, array{points: int, label: string}>}
     */
    public function score(array $stats, ?string $rdns, ?string $bot): array
    {
        $requests = max(1, $stats['requests']);
        $pages = $stats['requests'] - $stats['static'];
        $network = $this->network($rdns);
        $reasons = [];
        $add = static function (int $points, string $label) use (&$reasons): void {
            $reasons[] = ['points' => $points, 'label' => $label];
        };

        $engine = $bot !== null ? strtolower($bot) : null;
        if ($engine !== null && isset(self::SEARCH_ENGINES[$engine])) {
            if ($rdns !== null && !$this->hostEndsWith($rdns, self::SEARCH_ENGINES[$engine])) {
                $add(60, sprintf('se présente comme %s mais le reverse DNS (%s) n\'est pas le sien', $bot, $rdns));
            } else {
                // Unresolved: benefit of the doubt, blocking a real crawler costs SEO
                return [
                    'score'   => 0,
                    'level'   => 'moteur',
                    'network' => $network,
                    'reasons' => [['points' => 0, 'label' => sprintf('moteur de recherche %s%s : ne pas bloquer', $bot, $rdns !== null ? ' (vérifié)' : '')]],
                ];
            }
        } elseif ($bot !== null) {
            $add(20, sprintf('bot déclaré (%s) : aucun visiteur derrière', $bot));
        }

        $facetShare = $stats['facets'] / $requests;
        if ($facetShare >= 0.8) {
            $add(25, sprintf('%d %% de ses requêtes sont des facettes ?q=', round($facetShare * 100)));
        } elseif ($facetShare >= 0.4) {
            $add(15, sprintf('%d %% de ses requêtes sont des facettes ?q=', round($facetShare * 100)));
        }

        // A browser loads CSS/JS/images; a scraper fetches HTML only
        if ($pages >= 20 && $stats['static'] === 0) {
            $add(20, 'aucune ressource statique chargée (CSS, JS, images)');
        }

        // 403s are deliberately not scored: they measure our own rules, not the IP's behaviour
        // (an IP blocked yesterday would score itself up), and a fully refused IP already costs nothing.

        if ($pages >= 20 && $stats['empty_referer_pages'] / $pages >= 0.9) {
            $add(10, 'pages demandées sans referer');
        }

        foreach (array_keys($stats['uas']) as $ua) {
            if (preg_match(self::NON_BROWSER_UA, (string) $ua)) {
                $add(20, sprintf('user-agent d\'outil, pas de navigateur (%s)', $ua === '' ? 'vide' : mb_strimwidth((string) $ua, 0, 40, '…')));
                break;
            }
        }

        $uaCount = count($stats['uas']);
        if ($uaCount >= 5 && $network !== 'fai') {
            $add(15, sprintf('%d user-agents différents hors réseau grand public (rotation)', $uaCount));
        }

        if ($stats['peak_minute'] >= 60) {
            $add(15, sprintf('pic de %d requêtes en une minute', $stats['peak_minute']));
        } elseif ($stats['peak_minute'] >= 20) {
            $add(5, sprintf('pic de %d requêtes en une minute', $stats['peak_minute']));
        }

        if ($network === 'hebergeur') {
            $add(25, sprintf('IP d\'hébergeur (%s) : pas un internaute', $rdns));
        } elseif ($network === 'fai') {
            $add(-25, sprintf('FAI grand public (%s) : IP possiblement partagée par de vrais clients', $rdns));
        } elseif ($rdns === null) {
            $add(5, 'aucun reverse DNS');
        }

        $score = max(0, min(100, array_sum(array_column($reasons, 'points'))));
        usort($reasons, static fn (array $a, array $b): int => $b['points'] <=> $a['points']);

        return [
            'score'   => $score,
            'level'   => $score >= self::LEVEL_HIGH ? 'eleve' : ($score >= self::LEVEL_MEDIUM ? 'moyen' : 'faible'),
            'network' => $network,
            'reasons' => $reasons,
        ];
    }

    /**
     * @return string 'hebergeur', 'fai' or 'inconnu'
     */
    public function network(?string $rdns): string
    {
        if ($rdns === null) {
            return 'inconnu';
        }
        $host = strtolower($rdns);
        foreach (self::HOSTING_PATTERNS as $p) {
            if (str_contains($host, $p)) {
                return 'hebergeur';
            }
        }
        foreach (self::ISP_PATTERNS as $p) {
            if (str_contains($host, $p)) {
                return 'fai';
            }
        }

        return 'inconnu';
    }

    /**
     * @param string[] $domains
     */
    private function hostEndsWith(string $host, array $domains): bool
    {
        $host = strtolower(rtrim($host, '.'));
        foreach ($domains as $d) {
            if ($host === $d || str_ends_with($host, '.' . $d)) {
                return true;
            }
        }

        return false;
    }
}

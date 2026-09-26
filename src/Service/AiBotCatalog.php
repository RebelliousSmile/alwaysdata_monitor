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
 * Crawlers run by LLM vendors, grouped by what blocking them costs the shop.
 *
 * - training: collects pages to train models, brings no visitor: free to block.
 * - search: indexes pages for an AI answer engine that links back to the shop.
 * - user: fetches a page because a person asked the assistant about it.
 *
 * Some names are robots.txt tokens only (Google-Extended, Applebot-Extended):
 * those vendors crawl with their regular search bot and only read the token
 * to decide on AI usage, so a .htaccess rule on them would match nothing.
 */
class AiBotCatalog
{
    public const PURPOSE_TRAINING = 'training';
    public const PURPOSE_SEARCH = 'search';
    public const PURPOSE_USER = 'user';

    /** name => [vendor, purpose, robotsOnly, honoursRobots] */
    private const BOTS = [
        'GPTBot'                      => ['OpenAI', self::PURPOSE_TRAINING, false, true],
        'ClaudeBot'                   => ['Anthropic', self::PURPOSE_TRAINING, false, true],
        'anthropic-ai'                => ['Anthropic', self::PURPOSE_TRAINING, false, true],
        'Google-Extended'             => ['Google', self::PURPOSE_TRAINING, true, true],
        'Applebot-Extended'           => ['Apple', self::PURPOSE_TRAINING, true, true],
        'meta-externalagent'          => ['Meta', self::PURPOSE_TRAINING, false, true],
        'CCBot'                       => ['Common Crawl', self::PURPOSE_TRAINING, false, true],
        'Bytespider'                  => ['ByteDance', self::PURPOSE_TRAINING, false, false],
        'Amazonbot'                   => ['Amazon', self::PURPOSE_TRAINING, false, true],
        'cohere-ai'                   => ['Cohere', self::PURPOSE_TRAINING, false, true],
        'cohere-training-data-crawler' => ['Cohere', self::PURPOSE_TRAINING, false, true],
        'AI2Bot'                      => ['Allen Institute', self::PURPOSE_TRAINING, false, true],
        'Diffbot'                     => ['Diffbot', self::PURPOSE_TRAINING, false, true],
        'PanguBot'                    => ['Huawei', self::PURPOSE_TRAINING, false, true],
        'Timpibot'                    => ['Timpi', self::PURPOSE_TRAINING, false, true],
        'ImagesiftBot'                => ['ImageSift', self::PURPOSE_TRAINING, false, true],
        'omgili'                      => ['Webz.io', self::PURPOSE_TRAINING, false, true],
        'OAI-SearchBot'               => ['OpenAI', self::PURPOSE_SEARCH, false, true],
        'Claude-SearchBot'            => ['Anthropic', self::PURPOSE_SEARCH, false, true],
        'PerplexityBot'               => ['Perplexity', self::PURPOSE_SEARCH, false, true],
        'ChatGPT-User'                => ['OpenAI', self::PURPOSE_USER, false, false],
        'Claude-User'                 => ['Anthropic', self::PURPOSE_USER, false, false],
        'Perplexity-User'             => ['Perplexity', self::PURPOSE_USER, false, false],
        'meta-externalfetcher'        => ['Meta', self::PURPOSE_USER, false, false],
    ];

    /**
     * @return array<int, array{name: string, vendor: string, purpose: string, robots_only: bool, honours_robots: bool}>
     */
    public function all(): array
    {
        $list = [];
        foreach (self::BOTS as $name => [$vendor, $purpose, $robotsOnly, $honours]) {
            $list[] = [
                'name'           => $name,
                'vendor'         => $vendor,
                'purpose'        => $purpose,
                'robots_only'    => $robotsOnly,
                'honours_robots' => $honours,
            ];
        }

        return $list;
    }

    /**
     * Keeps only catalogued names, in their canonical spelling.
     *
     * @param string[] $names
     *
     * @return string[]
     */
    public function filter(array $names): array
    {
        $canonical = [];
        foreach (array_keys(self::BOTS) as $name) {
            $canonical[strtolower($name)] = $name;
        }
        $result = [];
        foreach ($names as $name) {
            $key = strtolower(trim((string) $name));
            if (isset($canonical[$key])) {
                $result[$canonical[$key]] = true;
            }
        }

        return array_keys($result);
    }

    /**
     * @param string[] $names catalogued names
     *
     * @return string[] names a user-agent rule can actually match
     */
    public function withUserAgent(array $names): array
    {
        return array_values(array_filter($names, static fn (string $n): bool => isset(self::BOTS[$n]) && !self::BOTS[$n][2]));
    }
}

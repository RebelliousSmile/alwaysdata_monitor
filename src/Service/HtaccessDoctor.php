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
 * Diagnoses and repairs .htaccess content. Pure string in / string out: file I/O,
 * backups and syntax validation stay in HtaccessService.
 */
class HtaccessDoctor
{
    public const SEVERITY_CRITICAL = 'critical';
    public const SEVERITY_WARNING = 'warning';
    public const SEVERITY_INFO = 'info';

    public const DEAD_UA_RULES = 'dead_ua_rules';
    public const DEAD_OTHER_RULES = 'dead_other_rules';
    public const PROTECTION_AFTER_PRESTASHOP = 'protection_after_prestashop';
    public const SEARCH_ENGINE_BLOCKED = 'search_engine_blocked';
    public const BROWSER_BLOCKED = 'browser_blocked';
    public const BROWSER_ONLY_RULE = 'browser_only_rule';
    public const SOCIAL_PREVIEW_BLOCKED = 'social_preview_blocked';
    public const IFMODULE_UNBALANCED = 'ifmodule_unbalanced';
    public const DANGLING_REWRITECOND = 'dangling_rewritecond';
    public const DUPLICATE_UA = 'duplicate_ua';

    public const BLOCKS_BEGIN = '# BEGIN sc_alwaysdata blocks';
    public const BLOCKS_END = '# END sc_alwaysdata blocks';
    private const BLOCKS_PATTERN = '/^# BEGIN sc_alwaysdata blocks\n.*?^# END sc_alwaysdata blocks\n?/ms';
    private const PROTECTION_PATTERN = '/^# BEGIN sc_alwaysdata protection\n.*?^# END sc_alwaysdata protection\n?/ms';

    /** Crawlers whose blocking removes the shop from search results. */
    private const SEARCH_ENGINES = [
        'Googlebot' => 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)',
        'Googlebot smartphone' => 'Mozilla/5.0 (Linux; Android 6.0.1; Nexus 5X Build/MMB29P) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Mobile Safari/537.36 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)',
        'Googlebot-Image' => 'Googlebot-Image/1.0',
        'AdsBot-Google' => 'AdsBot-Google (+http://www.google.com/adsbot.html)',
        'Google-InspectionTool' => 'Mozilla/5.0 (compatible; Google-InspectionTool/1.0;)',
        'bingbot' => 'Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)',
        'Applebot' => 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/13.1.1 Safari/605.1.15 (Applebot/0.1; +http://www.apple.com/go/applebot)',
        'Qwantbot' => 'Mozilla/5.0 (compatible; Qwantbot/1.0; +https://help.qwant.com/bot/)',
        'DuckDuckBot' => 'DuckDuckBot/1.1; (+http://duckduckgo.com/duckduckbot.html)',
    ];

    /** Real visitors, including in-app browsers that do not announce "Safari". */
    private const BROWSERS = [
        'Chrome Windows' => 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36',
        'Firefox' => 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:130.0) Gecko/20100101 Firefox/130.0',
        'Safari iPhone' => 'Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1',
        'Chrome Android' => 'Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Mobile Safari/537.36',
        'Instagram iOS' => 'Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148 Instagram 339.0.3.12.91 (iPhone13,2; iOS 17_5; fr_FR; fr; scale=3.00; 1170x2532; 618338301)',
        'Facebook iOS' => 'Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148 [FBAN/FBIOS;FBAV/470.0.0.37.109;FBBV/617046405;FBDV/iPhone13,2;FBMD/iPhone;FBSN/iOS;FBSV/17.5;FBSS/3;FBID/phone;FBLC/fr_FR;FBOP/5]',
    ];

    /** Link-preview fetchers: blocking them breaks shared links and Meta ads previews. */
    private const SOCIAL_PREVIEWS = [
        'facebookexternalhit' => 'facebookexternalhit/1.1 (+http://www.facebook.com/externalhit_uatext.php)',
        'Twitterbot' => 'Twitterbot/1.0',
        'LinkedInBot' => 'LinkedInBot/1.0 (compatible; Mozilla/5.0; Apache-HttpClient +http://www.linkedin.com)',
        'Pinterestbot' => 'Mozilla/5.0 (compatible; Pinterestbot/1.0; +http://www.pinterest.com/bot.html)',
        'WhatsApp' => 'WhatsApp/2.23.20.0 A',
    ];

    /**
     * @param array{facet_referer?: bool} $protection current state of the managed protection block
     *
     * @return array<int, array{code: string, severity: string, title: string, detail: string, lines: int[], items: string[], fixable: bool}>
     */
    public function analyse(string $content, array $protection = []): array
    {
        $content = str_replace("\r\n", "\n", $content);
        $findings = [];
        $groups = $this->parseGroups($content);
        $deadOffset = $this->deadZoneOffset($content);

        // 1. Blocking rules placed after PrestaShop's front controller rewrite
        if ($deadOffset !== null) {
            $deadUa = [];
            $deadUaLines = [];
            $deadOther = [];
            foreach ($groups as $g) {
                if ($g['start'] < $deadOffset || !$g['blocking']) {
                    continue;
                }
                if ($g['uas'] !== []) {
                    array_push($deadUa, ...$g['uas']);
                    $deadUaLines[] = $g['line'];
                } else {
                    $deadOther[] = $g['line'];
                }
            }
            if ($deadUa !== []) {
                $findings[] = $this->finding(
                    self::DEAD_UA_RULES,
                    self::SEVERITY_CRITICAL,
                    'Blocages de robots jamais appliqués',
                    'Ces règles sont placées après la réécriture PrestaShop vers index.php, qui termine le traitement ([L]) : '
                    . 'Apache ne les lit jamais et les robots passent. Réparer les déplace dans le bloc géré en tête de fichier.',
                    $deadUaLines,
                    array_values(array_unique($deadUa)),
                    true
                );
            }
            if ($deadOther !== []) {
                $findings[] = $this->finding(
                    self::DEAD_OTHER_RULES,
                    self::SEVERITY_CRITICAL,
                    'Règles de blocage jamais appliquées',
                    'Règles placées après la réécriture PrestaShop : sans effet. Trop spécifiques pour être déplacées '
                    . 'automatiquement, à remonter à la main au-dessus de « # ~~start~~ ».',
                    $deadOther,
                    [],
                    false
                );
            }
        }

        // 2. Managed protection block below PrestaShop's section
        $psStart = $this->prestashopStartOffset($content);
        if ($psStart !== null && preg_match(self::PROTECTION_PATTERN, $content, $m, PREG_OFFSET_CAPTURE) && $m[0][1] > $psStart) {
            $findings[] = $this->finding(
                self::PROTECTION_AFTER_PRESTASHOP,
                self::SEVERITY_CRITICAL,
                'Protection des facettes placée après PrestaShop',
                'Le bloc « sc_alwaysdata protection » doit précéder les règles PrestaShop pour être appliqué. Réparer le remonte en tête.',
                [$this->lineAt($content, $m[0][1])],
                [],
                true
            );
        }

        // 3. User-agent blocks catching visitors worth keeping
        $uaRules = $this->collectUaRules($content, $groups);
        foreach ([
            [self::SEARCH_ENGINE_BLOCKED, self::SEVERITY_CRITICAL, self::SEARCH_ENGINES, 'Moteurs de recherche bloqués',
                'Un blocage de robot correspond aussi à un moteur de recherche : pages désindexées à terme. Réparer retire ces blocages.'],
            [self::BROWSER_BLOCKED, self::SEVERITY_CRITICAL, self::BROWSERS, 'Vrais navigateurs bloqués',
                'Un motif de blocage correspond au user-agent de navigateurs courants : des clients reçoivent un 403. Réparer retire ces blocages.'],
            [self::SOCIAL_PREVIEW_BLOCKED, self::SEVERITY_WARNING, self::SOCIAL_PREVIEWS, 'Aperçus de liens bloqués',
                'Les liens partagés (et les publicités Meta pour facebookexternalhit) s\'affichent sans image ni titre. '
                . 'Bloquer ces robots ne se justifie qu\'en cas de charge avérée. Réparer retire ces blocages.'],
        ] as [$code, $severity, $samples, $title, $detail]) {
            $hits = [];
            $lines = [];
            foreach ($uaRules as $rule) {
                foreach ($samples as $name => $sample) {
                    if ($this->uaMatches($rule['pattern'], $sample)) {
                        $hits[$rule['pattern']] = $rule['pattern'] . ' → ' . $name;
                        $lines[] = $rule['line'];
                        break;
                    }
                }
            }
            if ($hits !== []) {
                $findings[] = $this->finding($code, $severity, $title, $detail, array_values(array_unique($lines)), array_values($hits), true);
            }
        }

        // 4. "Browsers only" rules (negated user-agent) that turn real visitors away
        $refererActive = (bool) ($protection['facet_referer'] ?? false);
        foreach ($groups as $g) {
            if (!$g['blocking'] || $g['negated_ua'] === []) {
                continue;
            }
            $rejected = [];
            foreach (self::BROWSERS as $name => $sample) {
                $allowed = false;
                foreach ($g['negated_ua'] as $pattern) {
                    if ($this->uaMatches($pattern, $sample)) {
                        $allowed = true;
                        break;
                    }
                }
                if (!$allowed) {
                    $rejected[] = $name;
                }
            }
            if ($rejected !== []) {
                $findings[] = $this->finding(
                    self::BROWSER_ONLY_RULE,
                    self::SEVERITY_WARNING,
                    'Règle « navigateurs uniquement » qui refuse de vrais visiteurs',
                    'Liste blanche de user-agents trop étroite : les navigateurs intégrés (liens ouverts depuis Instagram ou Facebook) reçoivent un 403. '
                    . ($refererActive
                        ? 'La protection Referer du module couvre déjà les facettes : réparer supprime cette règle.'
                        : 'Activez d\'abord la protection Referer des facettes, puis réparez pour supprimer cette règle.'),
                    [$g['line']],
                    $rejected,
                    $refererActive
                );
            }
        }

        // 5. Structure
        $open = preg_match_all('/^\s*<IfModule\b/mi', $content);
        $close = preg_match_all('/^\s*<\/IfModule>/mi', $content);
        if ($open !== $close) {
            $findings[] = $this->finding(
                self::IFMODULE_UNBALANCED,
                self::SEVERITY_CRITICAL,
                'Balises <IfModule> déséquilibrées',
                sprintf('%d ouvertures pour %d fermetures : Apache renvoie une erreur 500. Correction manuelle requise.', $open, $close),
                [],
                [],
                false
            );
        }

        $dangling = $this->danglingConditionLines($content);
        if ($dangling !== []) {
            $findings[] = $this->finding(
                self::DANGLING_REWRITECOND,
                self::SEVERITY_CRITICAL,
                'RewriteCond sans RewriteRule',
                'Une condition non suivie de sa règle s\'applique à la règle suivante du fichier, avec un effet imprévisible. Correction manuelle requise.',
                $dangling,
                [],
                false
            );
        }

        $counts = [];
        foreach ($uaRules as $rule) {
            $key = strtolower($rule['pattern']);
            $counts[$key] = ($counts[$key] ?? 0) + 1;
        }
        $duplicates = array_keys(array_filter($counts, static fn (int $c) => $c > 1));
        if ($duplicates !== []) {
            $findings[] = $this->finding(
                self::DUPLICATE_UA,
                self::SEVERITY_INFO,
                'Robots bloqués plusieurs fois',
                'Sans conséquence, mais débloquer un de ces robots demande de retirer toutes ses règles.',
                [],
                $duplicates,
                false
            );
        }

        $rank = [self::SEVERITY_CRITICAL => 0, self::SEVERITY_WARNING => 1, self::SEVERITY_INFO => 2];
        usort($findings, static fn (array $a, array $b) => $rank[$a['severity']] <=> $rank[$b['severity']]);

        return $findings;
    }

    /**
     * Applies the repair for one finding code. Throws when the code is not repairable
     * in this content (nothing to do, or rules too complex to edit safely).
     *
     * @param array{facet_referer?: bool} $protection
     */
    public function repair(string $content, string $code, array $protection = []): string
    {
        $content = str_replace("\r\n", "\n", $content);
        $finding = null;
        foreach ($this->analyse($content, $protection) as $f) {
            if ($f['code'] === $code) {
                $finding = $f;
                break;
            }
        }
        if ($finding === null || !$finding['fixable']) {
            throw new \InvalidArgumentException(sprintf('Nothing to repair for "%s"', $code));
        }

        switch ($code) {
            case self::DEAD_UA_RULES:
                $repaired = $this->moveDeadUaRules($content);
                break;
            case self::PROTECTION_AFTER_PRESTASHOP:
                preg_match(self::PROTECTION_PATTERN, $content, $m);
                $repaired = $m[0] . "\n" . ltrim((string) preg_replace(self::PROTECTION_PATTERN, '', $content, 1), "\n");
                break;
            case self::SEARCH_ENGINE_BLOCKED:
            case self::BROWSER_BLOCKED:
            case self::SOCIAL_PREVIEW_BLOCKED:
                $repaired = $content;
                foreach ($finding['items'] as $item) {
                    $repaired = $this->removeUaRules($repaired, explode(' → ', $item)[0]);
                }
                break;
            case self::BROWSER_ONLY_RULE:
                $repaired = $content;
                foreach (array_reverse($this->parseGroups($content)) as $g) {
                    if ($g['blocking'] && $g['negated_ua'] !== [] && in_array($g['line'], $finding['lines'], true)) {
                        $repaired = $this->cut($repaired, $g['start'], $g['end']);
                    }
                }
                break;
            default:
                throw new \InvalidArgumentException(sprintf('Unknown repair "%s"', $code));
        }

        if ($repaired === $content) {
            throw new \RuntimeException('Règles trop complexes pour une réparation automatique : correction manuelle requise.');
        }

        return $repaired;
    }

    /**
     * Adds UA blocking rules to the managed "blocks" section, created right after the
     * protection block (or at the top of the file) so that it runs before PrestaShop.
     *
     * @param string[] $uas
     */
    public function addUaRules(string $content, array $uas): string
    {
        $content = str_replace("\r\n", "\n", $content);

        if (!preg_match(self::BLOCKS_PATTERN, $content, $m, PREG_OFFSET_CAPTURE)) {
            $section = self::BLOCKS_BEGIN . "\n"
                . "# Managed by sc_alwaysdata (Back-office > Scriptami > Alwaysdata).\n"
                . "<IfModule mod_rewrite.c>\nRewriteEngine on\n</IfModule>\n"
                . self::BLOCKS_END . "\n";
            $at = preg_match(self::PROTECTION_PATTERN, $content, $p, PREG_OFFSET_CAPTURE)
                ? $p[0][1] + strlen($p[0][0])
                : 0;
            $content = substr($content, 0, $at) . ($at > 0 ? "\n" : '') . $section . "\n" . ltrim(substr($content, $at), "\n");
            preg_match(self::BLOCKS_PATTERN, $content, $m, PREG_OFFSET_CAPTURE);
        }

        $section = $m[0][0];
        $existing = array_map('strtolower', $this->uaTokensOf($section));
        $rules = '';
        foreach ($uas as $ua) {
            $ua = str_replace(['"', '\\', "\n", "\r"], '', trim($ua));
            if ($ua === '' || in_array(strtolower($ua), $existing, true)) {
                continue;
            }
            $existing[] = strtolower($ua);
            $rules .= "# sc_alwaysdata block UA: {$ua}\n"
                . "RewriteCond %{HTTP_USER_AGENT} \"{$ua}\" [NC]\n"
                . "RewriteRule .* - [F,L]\n";
        }

        $closePos = strrpos($section, '</IfModule>');
        $newSection = substr($section, 0, (int) $closePos) . $rules . substr($section, (int) $closePos);

        return substr($content, 0, $m[0][1]) . $newSection . substr($content, $m[0][1] + strlen($section));
    }

    /**
     * Removes every simple rule blocking this user-agent (module format, loose RewriteCond
     * with or without quotes, SetEnvIfNoCase). Rules inside OR chains are left alone.
     */
    public function removeUaRules(string $content, string $ua): string
    {
        $ua = str_replace(['"', '\\'], '', $ua);
        $q = preg_quote($ua, '/');

        $content = (string) preg_replace(
            '/\n?# sc_alwaysdata block UA: ' . $q . '\nRewriteCond %\{HTTP_USER_AGENT\} "' . $q . '" \[NC\]\nRewriteRule \.\* - \[F,L\]\n?/',
            "\n",
            $content
        );
        $content = (string) preg_replace(
            '/\nRewriteCond %\{HTTP_USER_AGENT\} "' . $q . '" \[NC\]\nRewriteRule \.\* - \[F,L\]\n?/i',
            "\n",
            $content
        );
        $content = (string) preg_replace(
            '/\nRewriteCond %\{HTTP_USER_AGENT\} ' . $q . ' \[NC\]\nRewriteRule \.\* - \[F,L\]\n?/i',
            "\n",
            $content
        );

        return (string) preg_replace('/\nSetEnvIfNoCase User-Agent "?' . $q . '"?[^\n]*\n/i', "\n", $content);
    }

    /**
     * Blocking rule groups: optional comment line, RewriteCond lines, then a RewriteRule.
     *
     * @return array<int, array{start: int, end: int, line: int, blocking: bool, uas: string[], negated_ua: string[]}>
     */
    private function parseGroups(string $content): array
    {
        $groups = [];
        $lines = explode("\n", $content);
        $offsets = [];
        $pos = 0;
        foreach ($lines as $i => $l) {
            $offsets[$i] = $pos;
            $pos += strlen($l) + 1;
        }

        $count = count($lines);
        for ($i = 0; $i < $count; ++$i) {
            if (!preg_match('/^\s*RewriteCond\s/i', $lines[$i])) {
                continue;
            }
            $first = $i;
            $conds = [];
            while ($i < $count && (preg_match('/^\s*RewriteCond\s/i', $lines[$i]) || preg_match('/^\s*#/', $lines[$i]))) {
                if (preg_match('/^\s*RewriteCond\s/i', $lines[$i])) {
                    $conds[] = trim($lines[$i]);
                }
                ++$i;
            }
            if ($i >= $count || !preg_match('/^\s*RewriteRule\s/i', $lines[$i])) {
                // dangling: reported separately
                --$i;
                continue;
            }

            $start = $offsets[$first];
            if ($first > 0 && preg_match('/^\s*#/', $lines[$first - 1]) && !preg_match('/^# ((BEGIN|END) sc_alwaysdata|~~(start|end)~~)/', $lines[$first - 1])) {
                $start = $offsets[$first - 1];
            }

            $uas = [];
            $negated = [];
            $simpleUa = true;
            foreach ($conds as $cond) {
                if (preg_match('/^RewriteCond\s+%\{HTTP_USER_AGENT\}\s+(!?)("?)(.+?)\2\s+\[(NC|NC,OR|OR,NC)\]$/i', $cond, $cm)) {
                    if ($cm[1] === '!') {
                        $negated[] = $cm[3];
                        $simpleUa = false;
                    } else {
                        $uas[] = $cm[3];
                    }
                } else {
                    $simpleUa = false;
                }
            }

            $groups[] = [
                'start' => $start,
                'end' => min(strlen($content), $offsets[$i] + strlen($lines[$i]) + 1),
                'line' => $first + 1,
                'blocking' => (bool) preg_match('/\[(?:[^\]]*,)?\s*F\s*(?:,[^\]]*)?\]\s*$/i', $lines[$i]),
                'uas' => $simpleUa ? $uas : [],
                'negated_ua' => $negated,
            ];
        }

        return $groups;
    }

    /**
     * @param array<int, array{start: int, end: int, line: int, blocking: bool, uas: string[], negated_ua: string[]}> $groups
     *
     * @return array<int, array{pattern: string, line: int}>
     */
    private function collectUaRules(string $content, array $groups): array
    {
        $rules = [];
        foreach ($groups as $g) {
            if ($g['blocking']) {
                foreach ($g['uas'] as $ua) {
                    $rules[] = ['pattern' => $ua, 'line' => $g['line']];
                }
            }
        }

        if (preg_match_all('/^\s*SetEnvIfNoCase\s+User-Agent\s+"?([^"\s]+)"?/mi', $content, $m, PREG_OFFSET_CAPTURE)) {
            foreach ($m[1] as [$pattern, $offset]) {
                $rules[] = ['pattern' => $pattern, 'line' => $this->lineAt($content, $offset)];
            }
        }

        return $rules;
    }

    private function moveDeadUaRules(string $content): string
    {
        $deadOffset = (int) $this->deadZoneOffset($content);
        $uas = [];
        foreach (array_reverse($this->parseGroups($content)) as $g) {
            if ($g['start'] >= $deadOffset && $g['blocking'] && $g['uas'] !== []) {
                array_unshift($uas, ...$g['uas']);
                $content = $this->cut($content, $g['start'], $g['end']);
            }
        }

        // Drop the wrappers left empty (old fallback of blockUserAgent)
        $head = substr($content, 0, $deadOffset);
        $tail = (string) preg_replace('/\n*<IfModule mod_rewrite\.c>\s*(RewriteEngine\s+on\s*)?<\/IfModule>\n?/i', "\n", substr($content, $deadOffset));
        $content = rtrim($head . $tail, "\n") . "\n";

        return $this->addUaRules($content, $uas);
    }

    private function cut(string $content, int $start, int $end): string
    {
        $before = substr($content, 0, $start);
        $after = substr($content, $end);
        // Avoid leaving a double blank line where the group was
        if (substr($before, -2) === "\n\n" && ($after === '' || $after[0] === "\n")) {
            $after = ltrim($after, "\n");
            $after = $after === '' ? '' : "\n" . $after;
        }

        return $before . $after;
    }

    /**
     * Offset where rewrite rules stop being evaluated: end of PrestaShop's section
     * ("# ~~end~~"), or the </IfModule> closing the front-controller rewrite.
     */
    private function deadZoneOffset(string $content): ?int
    {
        if (preg_match('/^# ~~end~~[^\n]*\n?/m', $content, $m, PREG_OFFSET_CAPTURE)) {
            return $m[0][1] + strlen($m[0][0]);
        }
        if (preg_match('/^\s*RewriteRule\s+\S+\s+%\{ENV:REWRITEBASE\}index\.php[^\n]*$/mi', $content, $m, PREG_OFFSET_CAPTURE)) {
            $close = stripos($content, '</IfModule>', $m[0][1]);
            if ($close !== false) {
                $eol = strpos($content, "\n", $close);

                return $eol === false ? strlen($content) : $eol + 1;
            }
        }

        return null;
    }

    private function prestashopStartOffset(string $content): ?int
    {
        if (preg_match('/^# ~~start~~/m', $content, $m, PREG_OFFSET_CAPTURE)) {
            return $m[0][1];
        }
        if (preg_match('/^\s*RewriteRule\s+\S+\s+%\{ENV:REWRITEBASE\}index\.php/mi', $content, $m, PREG_OFFSET_CAPTURE)) {
            return $m[0][1];
        }

        return null;
    }

    /**
     * @return int[]
     */
    private function danglingConditionLines(string $content): array
    {
        $lines = explode("\n", $content);
        $result = [];
        $pending = null;
        foreach ($lines as $i => $l) {
            if (preg_match('/^\s*RewriteCond\s/i', $l)) {
                $pending ??= $i + 1;
            } elseif (preg_match('/^\s*RewriteRule\s/i', $l)) {
                $pending = null;
            } elseif ($pending !== null && trim($l) !== '' && !preg_match('/^\s*#/', $l)) {
                $result[] = $pending;
                $pending = null;
            }
        }
        if ($pending !== null) {
            $result[] = $pending;
        }

        return $result;
    }

    /**
     * @return string[]
     */
    private function uaTokensOf(string $section): array
    {
        preg_match_all('/RewriteCond\s+%\{HTTP_USER_AGENT\}\s+"?([^"\s]+)"?\s+\[NC\]/i', $section, $m);

        return $m[1];
    }

    private function uaMatches(string $pattern, string $ua): bool
    {
        // Apache regexes are PCRE; an invalid pattern never matches
        return @preg_match('~' . str_replace('~', '\~', $pattern) . '~i', $ua) === 1;
    }

    private function lineAt(string $content, int $offset): int
    {
        return substr_count($content, "\n", 0, $offset) + 1;
    }

    /**
     * @param int[] $lines
     * @param string[] $items
     *
     * @return array{code: string, severity: string, title: string, detail: string, lines: int[], items: string[], fixable: bool}
     */
    private function finding(string $code, string $severity, string $title, string $detail, array $lines, array $items, bool $fixable): array
    {
        return compact('code', 'severity', 'title', 'detail', 'lines', 'items', 'fixable');
    }
}

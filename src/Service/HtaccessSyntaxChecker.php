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
 * Structural check of .htaccess content. Pure string in / list of problems out.
 *
 * It catches what makes Apache answer 500 for the whole site and can be seen
 * without Apache: unbalanced or malformed section tags, unterminated quotes,
 * RewriteCond / RewriteRule without their two arguments, a bad RewriteEngine
 * value. It does not know which directives or modules exist, so an unknown
 * directive is not reported.
 */
final class HtaccessSyntaxChecker
{
    public const UNCLOSED_SECTION = 'unclosed_section';
    public const STRAY_CLOSING_TAG = 'stray_closing_tag';
    public const MALFORMED_TAG = 'malformed_tag';
    public const UNTERMINATED_QUOTE = 'unterminated_quote';
    public const MISSING_ARGUMENTS = 'missing_arguments';
    public const BAD_ENGINE_VALUE = 'bad_engine_value';

    /**
     * @return list<array{code: string, line: int, message: string}>
     */
    public function check(string $content): array
    {
        $problems = [];
        $stack = [];

        foreach ($this->logicalLines($content) as [$line, $text]) {
            $trimmed = trim($text);
            if ($trimmed === '' || $trimmed[0] === '#') {
                continue;
            }

            if ($trimmed[0] === '<') {
                $this->checkTag($trimmed, $line, $stack, $problems);
                continue;
            }

            if ($this->hasUnterminatedQuote($trimmed)) {
                $problems[] = $this->problem(self::UNTERMINATED_QUOTE, $line, 'Guillemet non fermé.');
                continue;
            }

            $this->checkDirective($trimmed, $line, $problems);
        }

        foreach ($stack as [$name, $line]) {
            $problems[] = $this->problem(self::UNCLOSED_SECTION, $line, sprintf('<%s> n\'est jamais fermée.', $name));
        }

        usort($problems, static fn (array $a, array $b): int => $a['line'] <=> $b['line']);

        return $problems;
    }

    /**
     * Problems present in $after that $before did not already have, by kind: a file
     * that was already broken can still be edited, but never made worse.
     *
     * @param list<array{code: string, line: int, message: string}> $before
     * @param list<array{code: string, line: int, message: string}> $after
     *
     * @return list<array{code: string, line: int, message: string}>
     */
    public function introduced(array $before, array $after): array
    {
        $known = [];
        foreach ($before as $problem) {
            $known[$problem['code']] = ($known[$problem['code']] ?? 0) + 1;
        }

        $newOnes = [];
        $seen = [];
        foreach ($after as $problem) {
            $seen[$problem['code']] = ($seen[$problem['code']] ?? 0) + 1;
            if ($seen[$problem['code']] > ($known[$problem['code']] ?? 0)) {
                $newOnes[] = $problem;
            }
        }

        return $newOnes;
    }

    /**
     * Lines joined across trailing-backslash continuations, with their first line number.
     *
     * @return list<array{0: int, 1: string}>
     */
    private function logicalLines(string $content): array
    {
        $result = [];
        $buffer = '';
        $start = 0;
        foreach (explode("\n", str_replace("\r\n", "\n", $content)) as $i => $raw) {
            if ($buffer === '') {
                $start = $i + 1;
            }
            if (preg_match('/\\\\\s*$/', $raw) === 1 && !str_starts_with(ltrim($raw), '#')) {
                $buffer .= preg_replace('/\\\\\s*$/', ' ', $raw);
                continue;
            }
            $result[] = [$start, $buffer . $raw];
            $buffer = '';
        }
        if ($buffer !== '') {
            $result[] = [$start, $buffer];
        }

        return $result;
    }

    /**
     * @param list<array{0: string, 1: int}> $stack
     * @param list<array{code: string, line: int, message: string}> $problems
     */
    private function checkTag(string $text, int $line, array &$stack, array &$problems): void
    {
        if (preg_match('/^<(\/?)([A-Za-z][A-Za-z0-9]*)(\s[^>]*)?>$/', $text, $m) !== 1) {
            $problems[] = $this->problem(self::MALFORMED_TAG, $line, 'Balise de section mal formée.');

            return;
        }

        $name = $m[2];
        if ($m[1] === '') {
            $stack[] = [$name, $line];

            return;
        }

        $open = array_pop($stack);
        if ($open === null) {
            $problems[] = $this->problem(self::STRAY_CLOSING_TAG, $line, sprintf('</%s> sans ouverture.', $name));
        } elseif (strcasecmp($open[0], $name) !== 0) {
            $problems[] = $this->problem(
                self::STRAY_CLOSING_TAG,
                $line,
                sprintf('</%s> ferme <%s> ouverte ligne %d.', $name, $open[0], $open[1])
            );
        }
    }

    /**
     * @param list<array{code: string, line: int, message: string}> $problems
     */
    private function checkDirective(string $text, int $line, array &$problems): void
    {
        $args = $this->splitArguments($text);
        $directive = strtolower((string) array_shift($args));

        if (($directive === 'rewritecond' || $directive === 'rewriterule') && count($args) < 2) {
            $problems[] = $this->problem(
                self::MISSING_ARGUMENTS,
                $line,
                sprintf('%s demande au moins deux arguments.', $directive === 'rewritecond' ? 'RewriteCond' : 'RewriteRule')
            );
        } elseif ($directive === 'rewriteengine' && (count($args) !== 1 || !in_array(strtolower($args[0]), ['on', 'off'], true))) {
            $problems[] = $this->problem(self::BAD_ENGINE_VALUE, $line, 'RewriteEngine attend on ou off.');
        }
    }

    /**
     * @return list<string>
     */
    private function splitArguments(string $text): array
    {
        preg_match_all('/"((?:[^"\\\\]|\\\\.)*)"|(\S+)/', $text, $matches, PREG_SET_ORDER);

        return array_map(static fn (array $m): string => ($m[2] ?? '') !== '' ? $m[2] : $m[1], $matches);
    }

    private function hasUnterminatedQuote(string $text): bool
    {
        return preg_match_all('/(?<!\\\\)"/', $text) % 2 === 1;
    }

    /**
     * @return array{code: string, line: int, message: string}
     */
    private function problem(string $code, int $line, string $message): array
    {
        return ['code' => $code, 'line' => $line, 'message' => $message];
    }
}

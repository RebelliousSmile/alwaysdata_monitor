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
 * Checks the token of the three cron front controllers.
 *
 * The token is read from the `X-Cron-Token` request header first, then from the
 * `token` query parameter. The header keeps the secret out of web server access
 * logs and `Referer` values; the query parameter stays accepted so that
 * already scheduled URLs keep working.
 */
final class CronTokenGuard
{
    public const HEADER = 'X-Cron-Token';

    /**
     * @param array<string, mixed> $server the $_SERVER array
     * @param string $queryToken value of the `token` query parameter
     */
    public static function provided(array $server, string $queryToken): string
    {
        $header = $server['HTTP_' . strtoupper(str_replace('-', '_', self::HEADER))] ?? '';

        return is_string($header) && $header !== '' ? $header : $queryToken;
    }

    public static function isValid(string $storedToken, string $providedToken): bool
    {
        return $storedToken !== '' && hash_equals($storedToken, $providedToken);
    }
}

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
 * Looks an executable up in the PATH without going through a shell.
 */
final class ExecutableFinder
{
    /**
     * @param string $name bare command name (no directory separator)
     * @param string|null $path PATH-style list of directories; the PATH environment variable when null
     *
     * @return string|null absolute path of the first executable regular file found, null otherwise
     */
    public static function find(string $name, ?string $path = null): ?string
    {
        if ($name === '' || str_contains($name, '/') || str_contains($name, '\\') || str_contains($name, "\0")) {
            return null;
        }

        $path ??= (string) getenv('PATH');
        foreach (explode(PATH_SEPARATOR, $path) as $directory) {
            if ($directory === '') {
                continue;
            }

            $candidate = rtrim($directory, '/\\') . DIRECTORY_SEPARATOR . $name;
            if (is_file($candidate) && is_executable($candidate)) {
                return $candidate;
            }
        }

        return null;
    }
}

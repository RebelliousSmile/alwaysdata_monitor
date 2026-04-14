<?php

declare(strict_types=1);

require_once __DIR__ . '/../vendor/autoload.php';

/**
 * Minimal stub for PrestaShop's Configuration class.
 * Allows HtaccessService (which calls \Configuration::get()) to be tested
 * without a full PrestaShop bootstrap.
 */
if (!class_exists('Configuration')) {
    class Configuration
    {
        public static array $testValues = [];

        public static function get(string $key): mixed
        {
            return static::$testValues[$key] ?? false;
        }

        public static function set(string $key, mixed $value): void
        {
            static::$testValues[$key] = $value;
        }
    }
}

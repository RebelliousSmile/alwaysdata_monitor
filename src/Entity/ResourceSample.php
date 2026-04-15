<?php
/**
 * SC Alwaysdata - PrestaShop 8 Module
 *
 * @author    Scriptami
 * @copyright Scriptami
 * @license   Academic Free License version 3.0
 */

declare(strict_types=1);

namespace ScAlwaysdata\Entity;

if (!defined('_PS_VERSION_')) {
    exit;
}

class ResourceSample extends \ObjectModel
{
    /** @var string */
    public $sampled_at;

    /** @var int Unix timestamp floored to 900s (15 min bucket) — UNIQUE for idempotency */
    public $bucket_key = 0;

    /** @var int */
    public $ram_used_mb = 0;

    /** @var int */
    public $ram_total_mb = 2048;

    /** @var float */
    public $cpu_load_1 = 0.0;

    /** @var float */
    public $cpu_load_5 = 0.0;

    /** @var float */
    public $cpu_load_15 = 0.0;

    /** @var float */
    public $disk_used_gb = 0.0;

    /** @var float */
    public $disk_total_gb = 100.0;

    /** @var float */
    public $opcache_used_mb = 0.0;

    /** @var string JSON-encoded [{name, pid, rss_mb}] */
    public $top_processes = '[]';

    /** @var string JSON-encoded [{module, size_mb, script_count}] */
    public $top_modules_opcache = '[]';

    public static $definition = [
        'table'   => 'sc_alwaysdata_resources_samples',
        'primary' => 'id_sample',
        'fields'  => [
            'sampled_at'          => ['type' => self::TYPE_DATE,   'validate' => 'isDate',        'required' => true],
            'bucket_key'          => ['type' => self::TYPE_INT,    'validate' => 'isUnsignedInt', 'required' => true],
            'ram_used_mb'         => ['type' => self::TYPE_INT,    'validate' => 'isUnsignedInt'],
            'ram_total_mb'        => ['type' => self::TYPE_INT,    'validate' => 'isUnsignedInt'],
            'cpu_load_1'          => ['type' => self::TYPE_FLOAT,  'validate' => 'isFloat'],
            'cpu_load_5'          => ['type' => self::TYPE_FLOAT,  'validate' => 'isFloat'],
            'cpu_load_15'         => ['type' => self::TYPE_FLOAT,  'validate' => 'isFloat'],
            'disk_used_gb'        => ['type' => self::TYPE_FLOAT,  'validate' => 'isFloat'],
            'disk_total_gb'       => ['type' => self::TYPE_FLOAT,  'validate' => 'isFloat'],
            'opcache_used_mb'     => ['type' => self::TYPE_FLOAT,  'validate' => 'isFloat'],
            'top_processes'       => ['type' => self::TYPE_HTML,   'allow_html' => true],
            'top_modules_opcache' => ['type' => self::TYPE_HTML,   'allow_html' => true],
        ],
    ];

    public static function getCreateTableSql(): string
    {
        return '
            CREATE TABLE IF NOT EXISTS `' . _DB_PREFIX_ . 'sc_alwaysdata_resources_samples` (
                `id_sample`           int(11) UNSIGNED NOT NULL AUTO_INCREMENT,
                `sampled_at`          datetime NOT NULL,
                `bucket_key`          int(11) UNSIGNED NOT NULL,
                `ram_used_mb`         int(11) UNSIGNED NOT NULL DEFAULT 0,
                `ram_total_mb`        int(11) UNSIGNED NOT NULL DEFAULT 2048,
                `cpu_load_1`          decimal(5,2) UNSIGNED NOT NULL DEFAULT 0.00,
                `cpu_load_5`          decimal(5,2) UNSIGNED NOT NULL DEFAULT 0.00,
                `cpu_load_15`         decimal(5,2) UNSIGNED NOT NULL DEFAULT 0.00,
                `disk_used_gb`        decimal(8,2) UNSIGNED NOT NULL DEFAULT 0.00,
                `disk_total_gb`       decimal(8,2) UNSIGNED NOT NULL DEFAULT 100.00,
                `opcache_used_mb`     decimal(6,1) UNSIGNED NOT NULL DEFAULT 0.0,
                `top_processes`       text NULL,
                `top_modules_opcache` text NULL,
                PRIMARY KEY (`id_sample`),
                UNIQUE KEY `idx_bucket_key` (`bucket_key`),
                KEY `idx_sampled_at` (`sampled_at`)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
        ';
    }

    public static function getCountByBucketKey(int $bucketKey): int
    {
        return (int) \Db::getInstance()->getValue(
            'SELECT COUNT(*) FROM `' . _DB_PREFIX_ . 'sc_alwaysdata_resources_samples`
             WHERE `bucket_key` = ' . $bucketKey
        );
    }
}

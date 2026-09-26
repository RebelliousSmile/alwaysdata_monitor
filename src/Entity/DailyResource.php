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

class DailyResource extends \ObjectModel
{
    /** @var string Y-m-d */
    public $resource_date;

    /** @var int RAM utilisée en Mo */
    public $ram_used_mb = 0;

    /** @var int RAM totale en Mo (plafond forfait) */
    public $ram_total_mb = 2048;

    /** @var float Load average 1 min */
    public $cpu_load_1 = 0.0;

    /** @var float Load average 5 min */
    public $cpu_load_5 = 0.0;

    /** @var float Load average 15 min */
    public $cpu_load_15 = 0.0;

    /** @var float Disque utilisé en Go */
    public $disk_used_gb = 0.0;

    /** @var float Disque total en Go */
    public $disk_total_gb = 100.0;

    /** @var string */
    public $date_add;

    public static $definition = [
        'table'   => 'sc_alwaysdata_resources_daily',
        'primary' => 'id_resource',
        'fields'  => [
            'resource_date' => ['type' => self::TYPE_DATE,  'validate' => 'isDate',         'required' => true],
            'ram_used_mb'   => ['type' => self::TYPE_INT,   'validate' => 'isUnsignedInt'],
            'ram_total_mb'  => ['type' => self::TYPE_INT,   'validate' => 'isUnsignedInt'],
            'cpu_load_1'    => ['type' => self::TYPE_FLOAT, 'validate' => 'isFloat'],
            'cpu_load_5'    => ['type' => self::TYPE_FLOAT, 'validate' => 'isFloat'],
            'cpu_load_15'   => ['type' => self::TYPE_FLOAT, 'validate' => 'isFloat'],
            'disk_used_gb'  => ['type' => self::TYPE_FLOAT, 'validate' => 'isFloat'],
            'disk_total_gb' => ['type' => self::TYPE_FLOAT, 'validate' => 'isFloat'],
            'date_add'      => ['type' => self::TYPE_DATE,  'validate' => 'isDate'],
        ],
    ];

    /**
     * Returns the SQL to create the resources table.
     */
    public static function getCreateTableSql(): string
    {
        return '
            CREATE TABLE IF NOT EXISTS `' . _DB_PREFIX_ . 'sc_alwaysdata_resources_daily` (
                `id_resource`   int(11) UNSIGNED NOT NULL AUTO_INCREMENT,
                `resource_date` date NOT NULL,
                `ram_used_mb`   int(11) UNSIGNED NOT NULL DEFAULT 0,
                `ram_total_mb`  int(11) UNSIGNED NOT NULL DEFAULT 2048,
                `cpu_load_1`    decimal(5,2) UNSIGNED NOT NULL DEFAULT 0.00,
                `cpu_load_5`    decimal(5,2) UNSIGNED NOT NULL DEFAULT 0.00,
                `cpu_load_15`   decimal(5,2) UNSIGNED NOT NULL DEFAULT 0.00,
                `disk_used_gb`  decimal(8,2) UNSIGNED NOT NULL DEFAULT 0.00,
                `disk_total_gb` decimal(8,2) UNSIGNED NOT NULL DEFAULT 100.00,
                `date_add`      datetime NOT NULL,
                PRIMARY KEY (`id_resource`),
                UNIQUE KEY `idx_resource_date` (`resource_date`)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
        ';
    }

    /**
     * Find a row by date. Returns null if not found.
     */
    public static function getByDate(string $date): ?self
    {
        $id = (int) \Db::getInstance()->getValue(
            'SELECT `id_resource` FROM `' . _DB_PREFIX_ . 'sc_alwaysdata_resources_daily`
             WHERE `resource_date` = \'' . pSQL($date) . '\''
        );

        if (!$id) {
            return null;
        }

        $obj = new self($id);

        return \Validate::isLoadedObject($obj) ? $obj : null;
    }
}

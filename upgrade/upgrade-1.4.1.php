<?php
/**
 * SC Alwaysdata - PrestaShop 8 Module
 *
 * Upgrade to 1.4.1 — ajoute la colonne `php_errors` sur sc_alwaysdata_stats_daily
 * pour stocker un snapshot JSON des erreurs PHP agrégées au moment du cron J-1.
 *
 * @author    Scriptami
 * @copyright Scriptami
 * @license   Academic Free License version 3.0
 */

declare(strict_types=1);

if (!defined('_PS_VERSION_')) {
    exit;
}

function upgrade_module_1_4_1(sc_alwaysdata $module): bool
{
    $columnExists = (bool) Db::getInstance()->getValue(
        "SELECT COUNT(*) FROM information_schema.COLUMNS
         WHERE TABLE_SCHEMA = DATABASE()
           AND TABLE_NAME   = '" . _DB_PREFIX_ . "sc_alwaysdata_stats_daily'
           AND COLUMN_NAME  = 'php_errors'"
    );

    if ($columnExists) {
        return true;
    }

    return (bool) Db::getInstance()->execute(
        'ALTER TABLE `' . _DB_PREFIX_ . 'sc_alwaysdata_stats_daily`
         ADD COLUMN `php_errors` text NULL AFTER `hourly_breakdown`'
    );
}

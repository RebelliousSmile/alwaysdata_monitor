<?php
/**
 * SC Alwaysdata - Upgrade 1.2.0
 * Adds errors_500_pages column.
 */

if (!defined('_PS_VERSION_')) {
    exit;
}

function upgrade_module_1_2_0(sc_alwaysdata $module): bool
{
    $table = _DB_PREFIX_ . 'sc_alwaysdata_stats_daily';

    $columnExists = (bool) Db::getInstance()->getValue(
        'SELECT COUNT(*) FROM information_schema.COLUMNS
         WHERE TABLE_SCHEMA = DATABASE()
         AND TABLE_NAME = \'' . pSQL($table) . '\'
         AND COLUMN_NAME = \'errors_500_pages\''
    );

    if (!$columnExists) {
        Db::getInstance()->execute(
            'ALTER TABLE `' . pSQL($table) . '`
             ADD COLUMN `errors_500_pages` TEXT NULL AFTER `errors_500_checkout_detail`'
        );
    }

    return true;
}

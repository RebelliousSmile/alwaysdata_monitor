<?php
/**
 * SC Alwaysdata - PrestaShop 8 Module
 *
 * Upgrade to 1.5.0 — ajoute la colonne `process_summary` sur
 * sc_alwaysdata_resources_samples. Elle stocke, par nom de process, le nombre
 * d'instances vivantes et la RSS cumulée, ce que `top_processes` ne permet pas
 * de déduire : distinguer « beaucoup de workers » de « peu de gros workers ».
 *
 * @author    Scriptami
 * @copyright Scriptami
 * @license   Academic Free License version 3.0
 */

declare(strict_types=1);

if (!defined('_PS_VERSION_')) {
    exit;
}

function upgrade_module_1_5_0(sc_alwaysdata $module): bool
{
    $columnExists = (bool) Db::getInstance()->getValue(
        "SELECT COUNT(*) FROM information_schema.COLUMNS
         WHERE TABLE_SCHEMA = DATABASE()
           AND TABLE_NAME   = '" . _DB_PREFIX_ . "sc_alwaysdata_resources_samples'
           AND COLUMN_NAME  = 'process_summary'"
    );

    if ($columnExists) {
        return true;
    }

    return (bool) Db::getInstance()->execute(
        'ALTER TABLE `' . _DB_PREFIX_ . 'sc_alwaysdata_resources_samples`
         ADD COLUMN `process_summary` text NULL AFTER `top_modules_opcache`'
    );
}

<?php
/**
 * SC Alwaysdata - PrestaShop 8 Module — Upgrade 1.0.0 → 1.1.0
 *
 * Adds: sc_alwaysdata_stats_daily table + cron token config.
 *
 * @author    Scriptami
 * @copyright Scriptami
 * @license   Academic Free License version 3.0
 */

if (!defined('_PS_VERSION_')) {
    exit;
}

function upgrade_module_1_1_0(sc_alwaysdata $module): bool
{
    require_once __DIR__ . '/../src/Entity/DailyStat.php';

    $tableCreated = Db::getInstance()->execute(
        \ScAlwaysdata\Entity\DailyStat::getCreateTableSql()
    );

    if (!$tableCreated) {
        return false;
    }

    if (!Configuration::get(sc_alwaysdata::CONFIG_CRON_TOKEN)) {
        Configuration::set(sc_alwaysdata::CONFIG_CRON_TOKEN, Tools::passwdGen(32));
    }

    return true;
}

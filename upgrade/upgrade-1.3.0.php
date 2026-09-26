<?php
/**
 * SC Alwaysdata - Upgrade 1.3.0
 * Crée la table sc_alwaysdata_resources_daily.
 */

if (!defined('_PS_VERSION_')) {
    exit;
}

function upgrade_module_1_3_0(sc_alwaysdata $module): bool
{
    require_once __DIR__ . '/../src/Entity/DailyResource.php';

    return (bool) Db::getInstance()->execute(
        \ScAlwaysdata\Entity\DailyResource::getCreateTableSql()
    );
}

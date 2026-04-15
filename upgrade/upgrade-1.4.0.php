<?php
/**
 * SC Alwaysdata - PrestaShop 8 Module
 *
 * Upgrade to 1.4.0 — create sc_alwaysdata_resources_samples table for
 * high-frequency (15 min) sampling of RAM / CPU / disk / OPcache metrics.
 *
 * @author    Scriptami
 * @copyright Scriptami
 * @license   Academic Free License version 3.0
 */

declare(strict_types=1);

if (!defined('_PS_VERSION_')) {
    exit;
}

function upgrade_module_1_4_0(sc_alwaysdata $module): bool
{
    require_once __DIR__ . '/../src/Entity/ResourceSample.php';

    return (bool) Db::getInstance()->execute(
        \ScAlwaysdata\Entity\ResourceSample::getCreateTableSql()
    );
}

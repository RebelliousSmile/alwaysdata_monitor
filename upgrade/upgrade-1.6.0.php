<?php
/**
 * SC Alwaysdata - PrestaShop 8 Module
 *
 * Upgrade to 1.6.0 — registers actionAdminMetaAfterWriteRobotsFile so the managed
 * robots.txt block survives PrestaShop's "Generate robots.txt", which truncates the file.
 *
 * @author    Scriptami
 * @copyright Scriptami
 * @license   Academic Free License version 3.0
 */

declare(strict_types=1);

if (!defined('_PS_VERSION_')) {
    exit;
}

function upgrade_module_1_6_0(sc_alwaysdata $module): bool
{
    return $module->registerHook('actionAdminMetaAfterWriteRobotsFile');
}

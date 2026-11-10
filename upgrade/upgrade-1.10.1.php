<?php

/**
 * SC Alwaysdata - PrestaShop 8 Module
 *
 * Upgrade to 1.10.1 — the .htaccess path is no longer configurable: the module always
 * works on PrestaShop's own .htaccess (and the robots.txt next to it). The stored path,
 * which an attacker could have pointed at any writable file, is dropped.
 *
 * @author    Scriptami
 * @copyright Scriptami
 * @license   Academic Free License version 3.0
 */

declare(strict_types=1);

if (!defined('_PS_VERSION_')) {
    exit;
}

function upgrade_module_1_10_1(sc_alwaysdata $module): bool
{
    Configuration::deleteByName('SC_ALWAYSDATA_HTACCESS_PATH');

    return true;
}

<?php
/**
 * SC Alwaysdata - PrestaShop 8 Module
 *
 * Upgrade to 1.10.0 — adds requests_scrapers to the daily stats table: the cron
 * now excludes refused requests and scraper-profile IPs from the human count.
 *
 * @author    Scriptami
 * @copyright Scriptami
 * @license   Academic Free License version 3.0
 */

declare(strict_types=1);

use ScAlwaysdata\Entity\DailyStat;

if (!defined('_PS_VERSION_')) {
    exit;
}

function upgrade_module_1_10_0(sc_alwaysdata $module): bool
{
    return DailyStat::ensureScrapersColumn();
}

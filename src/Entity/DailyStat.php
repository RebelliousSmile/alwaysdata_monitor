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

class DailyStat extends \ObjectModel
{
    /** @var string Y-m-d */
    public $stat_date;

    /** @var int */
    public $requests_total = 0;

    /** @var int */
    public $requests_human = 0;

    /** @var int */
    public $mobile = 0;

    /** @var int */
    public $desktop = 0;

    /** @var int */
    public $views_product = 0;

    /** @var int */
    public $cart_adds = 0;

    /** @var int */
    public $views_cart = 0;

    /** @var int */
    public $views_checkout = 0;

    /** @var int */
    public $post_checkout = 0;

    /** @var int Commandes avec order_state.paid = 1 */
    public $orders_confirmed = 0;

    /** @var int */
    public $errors_500_front = 0;

    /** @var int */
    public $errors_500_bo = 0;

    /** @var int */
    public $errors_500_checkout = 0;

    /** @var string JSON [{path, ip, datetime}] */
    public $errors_500_checkout_detail = '[]';

    /** @var string JSON {front: {path: count}, bo: {path: count}} */
    public $errors_500_pages = '{}';

    /** @var string JSON [{path, count}] top 20 */
    public $top_pages = '[]';

    /** @var string JSON [{ip, count}] top 20 */
    public $top_ips = '[]';

    /** @var string JSON {0: count, 1: count, ..., 23: count} */
    public $hourly_breakdown = '{}';

    /** @var string */
    public $date_add;

    public static $definition = [
        'table' => 'sc_alwaysdata_stats_daily',
        'primary' => 'id_stat',
        'fields' => [
            'stat_date' => ['type' => self::TYPE_DATE, 'validate' => 'isDate', 'required' => true],
            'requests_total' => ['type' => self::TYPE_INT, 'validate' => 'isUnsignedInt'],
            'requests_human' => ['type' => self::TYPE_INT, 'validate' => 'isUnsignedInt'],
            'mobile' => ['type' => self::TYPE_INT, 'validate' => 'isUnsignedInt'],
            'desktop' => ['type' => self::TYPE_INT, 'validate' => 'isUnsignedInt'],
            'views_product' => ['type' => self::TYPE_INT, 'validate' => 'isUnsignedInt'],
            'cart_adds' => ['type' => self::TYPE_INT, 'validate' => 'isUnsignedInt'],
            'views_cart' => ['type' => self::TYPE_INT, 'validate' => 'isUnsignedInt'],
            'views_checkout' => ['type' => self::TYPE_INT, 'validate' => 'isUnsignedInt'],
            'post_checkout' => ['type' => self::TYPE_INT, 'validate' => 'isUnsignedInt'],
            'orders_confirmed' => ['type' => self::TYPE_INT, 'validate' => 'isUnsignedInt'],
            'errors_500_front' => ['type' => self::TYPE_INT, 'validate' => 'isUnsignedInt'],
            'errors_500_bo' => ['type' => self::TYPE_INT, 'validate' => 'isUnsignedInt'],
            'errors_500_checkout' => ['type' => self::TYPE_INT, 'validate' => 'isUnsignedInt'],
            'errors_500_checkout_detail' => ['type' => self::TYPE_HTML, 'allow_html' => true],
            'errors_500_pages' => ['type' => self::TYPE_HTML, 'allow_html' => true],
            'top_pages' => ['type' => self::TYPE_HTML, 'allow_html' => true],
            'top_ips' => ['type' => self::TYPE_HTML, 'allow_html' => true],
            'hourly_breakdown' => ['type' => self::TYPE_HTML, 'allow_html' => true],
            'date_add' => ['type' => self::TYPE_DATE, 'validate' => 'isDate'],
        ],
    ];

    /**
     * Returns the SQL to create the stats table.
     */
    public static function getCreateTableSql(): string
    {
        return '
            CREATE TABLE IF NOT EXISTS `' . _DB_PREFIX_ . 'sc_alwaysdata_stats_daily` (
                `id_stat` int(11) UNSIGNED NOT NULL AUTO_INCREMENT,
                `stat_date` date NOT NULL,
                `requests_total` int(11) UNSIGNED NOT NULL DEFAULT 0,
                `requests_human` int(11) UNSIGNED NOT NULL DEFAULT 0,
                `mobile` int(11) UNSIGNED NOT NULL DEFAULT 0,
                `desktop` int(11) UNSIGNED NOT NULL DEFAULT 0,
                `views_product` int(11) UNSIGNED NOT NULL DEFAULT 0,
                `cart_adds` int(11) UNSIGNED NOT NULL DEFAULT 0,
                `views_cart` int(11) UNSIGNED NOT NULL DEFAULT 0,
                `views_checkout` int(11) UNSIGNED NOT NULL DEFAULT 0,
                `post_checkout` int(11) UNSIGNED NOT NULL DEFAULT 0,
                `orders_confirmed` int(11) UNSIGNED NOT NULL DEFAULT 0,
                `errors_500_front` int(11) UNSIGNED NOT NULL DEFAULT 0,
                `errors_500_bo` int(11) UNSIGNED NOT NULL DEFAULT 0,
                `errors_500_checkout` int(11) UNSIGNED NOT NULL DEFAULT 0,
                `errors_500_checkout_detail` text NULL,
                `errors_500_pages` text NULL,
                `top_pages` text NULL,
                `top_ips` text NULL,
                `hourly_breakdown` text NULL,
                `date_add` datetime NOT NULL,
                PRIMARY KEY (`id_stat`),
                UNIQUE KEY `idx_stat_date` (`stat_date`)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
        ';
    }

    /**
     * Find a row by date. Returns null if not found.
     */
    public static function getByDate(string $date): ?self
    {
        $id = (int) \Db::getInstance()->getValue(
            'SELECT `id_stat` FROM `' . _DB_PREFIX_ . 'sc_alwaysdata_stats_daily`
             WHERE `stat_date` = \'' . pSQL($date) . '\''
        );

        if (!$id) {
            return null;
        }

        $obj = new self($id);

        return \Validate::isLoadedObject($obj) ? $obj : null;
    }
}

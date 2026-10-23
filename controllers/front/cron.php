<?php

/**
 * SC Alwaysdata - PrestaShop 8 Module — Cron front controller
 *
 * Called nightly by Alwaysdata cron:
 *   https://site-a.example/module/sc_alwaysdata/cron?token={SC_ALWAYSDATA_CRON_TOKEN}
 *   (or, preferred, without the query string and with the header
 *   X-Cron-Token: {SC_ALWAYSDATA_CRON_TOKEN}, e.g. curl -H "X-Cron-Token: ...")
 *
 * @author    Scriptami
 * @copyright Scriptami
 * @license   Academic Free License version 3.0
 */

declare(strict_types=1);

use ScAlwaysdata\Entity\DailyStat;
use ScAlwaysdata\Service\CrawlerAnalyserService;
use ScAlwaysdata\Service\CronTokenGuard;
use ScAlwaysdata\Service\HttpLogParserService;
use ScAlwaysdata\Service\LogReaderService;
use ScAlwaysdata\Service\PhpErrorAnalyserService;

class Sc_alwaysdataCronModuleFrontController extends ModuleFrontController
{
    /** @var bool No login required */
    public $auth = false;

    /** @var array<string, mixed> */
    private $responseData = [];

    /** @var int */
    private $responseHttpCode = 200;

    public function initContent(): void
    {
        $token = CronTokenGuard::provided($_SERVER, (string) Tools::getValue('token'));
        $storedToken = (string) Configuration::get(sc_alwaysdata::CONFIG_CRON_TOKEN);

        if (!CronTokenGuard::isValid($storedToken, $token)) {
            $this->responseData = ['error' => 'Forbidden'];
            $this->responseHttpCode = 403;

            return;
        }

        $date = date('Y-m-d', strtotime('yesterday'));

        // MySQL lock names are server-wide: prefix with the database, 64 chars max
        $lockName = pSQL(substr(_DB_NAME_ . ':sc_alwaysdata_cron_stats', 0, 64));
        $locked = false;

        try {
            $existing = DailyStat::getByDate($date);
            if ($existing !== null) {
                $this->responseData = ['skipped' => true, 'date' => $date];

                return;
            }

            // Cron and BO button must never parse the same day twice in parallel
            // GET_LOCK answers 1 (taken), 0 (held elsewhere) or NULL (MySQL error)
            $lockAnswer = (string) Db::getInstance()->getValue('SELECT GET_LOCK(\'' . $lockName . '\', 0)', false);
            if ($lockAnswer !== '0' && $lockAnswer !== '1') {
                throw new RuntimeException('Cannot acquire cron lock');
            }
            $locked = $lockAnswer === '1';
            if (!$locked) {
                $this->responseData = ['running' => true, 'date' => $date];
                $this->responseHttpCode = 409;

                return;
            }

            // The call holding the lock may have finished in between
            if (DailyStat::getByDate($date) !== null) {
                $this->responseData = ['skipped' => true, 'date' => $date];

                return;
            }

            $logReaderService = new LogReaderService();
            $logPath = $logReaderService->findHttpLogPath($date);

            if ($logPath === null) {
                PrestaShopLogger::addLog(
                    '[sc_alwaysdata] Cron: log introuvable pour ' . $date,
                    3,
                    null,
                    'sc_alwaysdata'
                );
                $this->responseData = ['error' => 'Log not found for ' . $date, 'date' => $date];
                $this->responseHttpCode = 404;

                return;
            }

            DailyStat::ensureScrapersColumn();

            $crawlerService = new CrawlerAnalyserService();
            $parserService = new HttpLogParserService($crawlerService);
            $metrics = $parserService->parse($logPath);

            // Parse PHP error log for the same date (J-1) to snapshot errors alongside HTTP stats
            $phpErrorAnalyser = new PhpErrorAnalyserService();
            $phpSource = $logReaderService->readPhpLogForDate($date);
            $phpErrors = $phpErrorAnalyser->analyse([$phpSource]);

            $ordersConfirmed = (int) Db::getInstance()->getValue(
                'SELECT COUNT(*) FROM `' . _DB_PREFIX_ . 'orders` o
                 JOIN `' . _DB_PREFIX_ . 'order_state` os ON o.current_state = os.id_order_state
                 WHERE o.date_add >= \'' . pSQL($date) . ' 00:00:00\'
                   AND o.date_add < \'' . pSQL($date) . '\' + INTERVAL 1 DAY
                   AND os.paid = 1'
            );

            $stat = new DailyStat();
            $stat->stat_date = $date;
            $stat->requests_total = $metrics['requests_total'];
            $stat->requests_human = $metrics['requests_human'];
            $stat->requests_scrapers = $metrics['requests_scrapers'];
            $stat->mobile = $metrics['mobile'];
            $stat->desktop = $metrics['desktop'];
            $stat->views_product = $metrics['views_product'];
            $stat->cart_adds = $metrics['cart_adds'];
            $stat->views_cart = $metrics['views_cart'];
            $stat->views_checkout = $metrics['views_checkout'];
            $stat->post_checkout = $metrics['post_checkout'];
            $stat->orders_confirmed = $ordersConfirmed;
            $stat->errors_500_front = $metrics['errors_500_front'];
            $stat->errors_500_bo = $metrics['errors_500_bo'];
            $stat->errors_500_checkout = $metrics['errors_500_checkout'];
            $stat->errors_500_checkout_detail = json_encode($metrics['errors_500_checkout_detail']);
            $stat->errors_500_pages = json_encode([
                'front' => $metrics['errors_500_front_pages'],
                'bo' => $metrics['errors_500_bo_pages'],
            ]);
            $stat->top_pages = json_encode(
                array_map(
                    fn ($path, $count) => ['path' => $path, 'count' => $count],
                    array_keys($metrics['page_counts']),
                    array_values($metrics['page_counts'])
                )
            );
            $stat->top_ips = json_encode(
                array_map(
                    fn ($ip, $count) => ['ip' => $ip, 'count' => $count],
                    array_keys($metrics['ip_counts']),
                    array_values($metrics['ip_counts'])
                )
            );
            $stat->hourly_breakdown = json_encode($metrics['hourly_product_views']);
            $stat->php_errors = json_encode($phpErrors);
            $stat->date_add = date('Y-m-d H:i:s');

            if (!$stat->add()) {
                throw new RuntimeException('Failed to insert DailyStat for ' . $date);
            }

            $purged = Db::getInstance()->execute(
                'DELETE FROM `' . _DB_PREFIX_ . 'sc_alwaysdata_stats_daily`
                 WHERE stat_date < DATE_SUB(NOW(), INTERVAL 90 DAY)'
            );
            $purgedRows = $purged ? (int) Db::getInstance()->Affected_Rows() : 0;

            $this->responseData = [
                'date' => $date,
                'requests_total' => (int) $stat->requests_total,
                'requests_human' => (int) $stat->requests_human,
                'requests_scrapers' => (int) $stat->requests_scrapers,
                'views_product' => (int) $stat->views_product,
                'cart_adds' => (int) $stat->cart_adds,
                'orders_confirmed' => (int) $stat->orders_confirmed,
                'errors_500_front' => (int) $stat->errors_500_front,
                'php_errors_count' => count($phpErrors),
                'purged_rows' => $purgedRows,
            ];
        } catch (Throwable $e) {
            PrestaShopLogger::addLog(
                '[sc_alwaysdata] Cron error for ' . $date . ': ' . $e->getMessage(),
                3,
                null,
                'sc_alwaysdata'
            );
            $this->responseData = ['error' => $e->getMessage(), 'date' => $date];
            $this->responseHttpCode = 500;
        } finally {
            if ($locked) {
                // A failure here must not replace the response; MySQL frees the lock with the connection anyway
                try {
                    Db::getInstance()->getValue('SELECT RELEASE_LOCK(\'' . $lockName . '\')', false);
                } catch (Throwable $e) {
                }
            }
        }
    }

    public function display(): void
    {
        http_response_code($this->responseHttpCode);
        header('Content-Type: application/json');
        $json = json_encode($this->responseData);
        echo $json !== false ? $json : '{"error":"json_encode failed"}';
    }
}

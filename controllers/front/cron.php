<?php
/**
 * SC Alwaysdata - PrestaShop 8 Module — Cron front controller
 *
 * Called nightly by Alwaysdata cron:
 *   https://site-a.example/module/sc_alwaysdata/cron?token={SC_ALWAYSDATA_CRON_TOKEN}
 *
 * @author    Scriptami
 * @copyright Scriptami
 * @license   Academic Free License version 3.0
 */

declare(strict_types=1);

use ScAlwaysdata\Entity\DailyStat;
use ScAlwaysdata\Service\CrawlerAnalyserService;
use ScAlwaysdata\Service\HttpLogParserService;
use ScAlwaysdata\Service\LogReaderService;

class Sc_alwaysdataCronModuleFrontController extends ModuleFrontController
{
    /** @var bool No login required */
    public $auth = false;

    public function initContent(): void
    {
        $token = (string) Tools::getValue('token');
        $storedToken = (string) Configuration::get(sc_alwaysdata::CONFIG_CRON_TOKEN);

        if ($storedToken === '' || !hash_equals($storedToken, $token)) {
            $this->jsonResponse(['error' => 'Forbidden'], 403);
        }

        $date = date('Y-m-d', strtotime('yesterday'));

        try {
            $this->run($date);
        } catch (\Throwable $e) {
            PrestaShopLogger::addLog(
                '[sc_alwaysdata] Cron error for ' . $date . ': ' . $e->getMessage(),
                3,
                null,
                'sc_alwaysdata'
            );
            $this->jsonResponse(['error' => $e->getMessage(), 'date' => $date], 500);
        }
    }

    private function run(string $date): void
    {
        // --- Idempotence check ---
        $existing = DailyStat::getByDate($date);
        if ($existing !== null) {
            $this->jsonResponse(['skipped' => true, 'date' => $date]);
        }

        // --- Resolve log file ---
        $logReaderService = new LogReaderService();
        $logPath = $logReaderService->findHttpLogPath($date);

        if ($logPath === null) {
            PrestaShopLogger::addLog(
                '[sc_alwaysdata] Cron: log introuvable pour ' . $date,
                3,
                null,
                'sc_alwaysdata'
            );
            $this->jsonResponse(['error' => 'Log not found for ' . $date, 'date' => $date], 404);
        }

        // --- Parse log ---
        $crawlerService = new CrawlerAnalyserService();
        $parserService = new HttpLogParserService($crawlerService);
        $metrics = $parserService->parse($logPath);

        // --- Orders confirmed from DB ---
        $ordersConfirmed = (int) Db::getInstance()->getValue(
            'SELECT COUNT(*) FROM `' . _DB_PREFIX_ . 'orders` o
             JOIN `' . _DB_PREFIX_ . 'order_state` os ON o.current_state = os.id_order_state
             WHERE DATE(o.date_add) = \'' . pSQL($date) . '\' AND os.paid = 1'
        );

        // --- Insert row ---
        $stat = new DailyStat();
        $stat->stat_date                    = $date;
        $stat->requests_total               = $metrics['requests_total'];
        $stat->requests_human               = $metrics['requests_human'];
        $stat->mobile                       = $metrics['mobile'];
        $stat->desktop                      = $metrics['desktop'];
        $stat->views_product                = $metrics['views_product'];
        $stat->cart_adds                    = $metrics['cart_adds'];
        $stat->views_cart                   = $metrics['views_cart'];
        $stat->views_checkout               = $metrics['views_checkout'];
        $stat->post_checkout                = $metrics['post_checkout'];
        $stat->orders_confirmed             = $ordersConfirmed;
        $stat->errors_500_front             = $metrics['errors_500_front'];
        $stat->errors_500_bo                = $metrics['errors_500_bo'];
        $stat->errors_500_checkout          = $metrics['errors_500_checkout'];
        $stat->errors_500_checkout_detail   = json_encode($metrics['errors_500_checkout_detail']);
        $stat->top_pages                    = json_encode(
            array_map(
                fn ($path, $count) => ['path' => $path, 'count' => $count],
                array_keys($metrics['page_counts']),
                array_values($metrics['page_counts'])
            )
        );
        $stat->top_ips                      = json_encode(
            array_map(
                fn ($ip, $count) => ['ip' => $ip, 'count' => $count],
                array_keys($metrics['ip_counts']),
                array_values($metrics['ip_counts'])
            )
        );
        $stat->hourly_breakdown             = json_encode($metrics['hourly_counts']);
        $stat->date_add                     = date('Y-m-d H:i:s');

        if (!$stat->add()) {
            throw new \RuntimeException('Failed to insert DailyStat for ' . $date);
        }

        // --- Purge rows older than 90 days ---
        $purged = Db::getInstance()->execute(
            'DELETE FROM `' . _DB_PREFIX_ . 'sc_alwaysdata_stats_daily`
             WHERE stat_date < DATE_SUB(NOW(), INTERVAL 90 DAY)'
        );
        $purgedRows = $purged ? (int) Db::getInstance()->Affected_Rows() : 0;

        $this->jsonResponse([
            'date'             => $date,
            'requests_total'   => $stat->requests_total,
            'requests_human'   => $stat->requests_human,
            'views_product'    => $stat->views_product,
            'cart_adds'        => $stat->cart_adds,
            'orders_confirmed' => $stat->orders_confirmed,
            'errors_500_front' => $stat->errors_500_front,
            'purged_rows'      => $purgedRows,
        ]);
    }

    /**
     * Output JSON response and stop execution.
     *
     * @param array<string, mixed> $data
     */
    private function jsonResponse(array $data, int $httpCode = 200): never
    {
        http_response_code($httpCode);
        header('Content-Type: application/json');
        die(json_encode($data));
    }
}

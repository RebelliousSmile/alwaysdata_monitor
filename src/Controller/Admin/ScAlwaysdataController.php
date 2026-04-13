<?php
/**
 * SC Alwaysdata - PrestaShop 8 Module
 *
 * @author    Scriptami
 * @copyright Scriptami
 * @license   Academic Free License version 3.0
 */

declare(strict_types=1);

namespace ScAlwaysdata\Controller\Admin;

use Configuration;
use Db;
use PrestaShopBundle\Controller\Admin\FrameworkBundleAdminController;
use PrestaShopBundle\Security\Annotation\AdminSecurity;
use ScAlwaysdata\Entity\DailyStat;
use ScAlwaysdata\Service\CrawlerAnalyserService;
use ScAlwaysdata\Service\HtaccessService;
use ScAlwaysdata\Service\LogReaderService;
use ScAlwaysdata\Service\PhpErrorAnalyserService;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;

class ScAlwaysdataController extends FrameworkBundleAdminController
{
    private LogReaderService $logReaderService;
    private CrawlerAnalyserService $crawlerAnalyserService;
    private PhpErrorAnalyserService $phpErrorAnalyserService;
    private HtaccessService $htaccessService;

    public function __construct(
        LogReaderService $logReaderService,
        CrawlerAnalyserService $crawlerAnalyserService,
        PhpErrorAnalyserService $phpErrorAnalyserService,
        HtaccessService $htaccessService
    ) {
        $this->logReaderService = $logReaderService;
        $this->crawlerAnalyserService = $crawlerAnalyserService;
        $this->phpErrorAnalyserService = $phpErrorAnalyserService;
        $this->htaccessService = $htaccessService;
    }

    /**
     * @AdminSecurity(
     *     "is_granted('read', request.get('_legacy_controller'))",
     *     message="You do not have permission to access this.",
     *     redirectRoute="admin_dashboard"
     * )
     */
    public function indexAction(Request $request): Response
    {
        $this->ensureStatsTable();

        if ($request->isMethod('POST')) {
            if (!$this->isCsrfTokenValid('sc_alwaysdata_index', $request->request->get('_token'))) {
                $this->addFlash('error', $this->trans('Jeton CSRF invalide.', 'Modules.Scalwaysdata.Admin'));

                return $this->redirectToRoute('sc_alwaysdata_index');
            }

            $logsPath = rtrim(trim((string) $request->request->get('logs_path', '')), '/') . '/';
            $htaccessPath = trim((string) $request->request->get('htaccess_path', ''));

            if ($logsPath === '/') {
                $this->addFlash(
                    'error',
                    $this->trans('Le chemin des logs ne peut pas être vide.', 'Modules.Scalwaysdata.Admin')
                );
            } else {
                Configuration::updateValue('SC_ALWAYSDATA_LOGS_PATH', $logsPath);
                Configuration::updateValue('SC_ALWAYSDATA_HTACCESS_PATH', $htaccessPath);
                foreach (['apache', 'http', 'php', 'sites'] as $dir) {
                    $val = max(100, (int) $request->request->get('lines_' . $dir, 5000));
                    Configuration::updateValue('SC_ALWAYSDATA_LINES_' . strtoupper($dir), $val);
                }
                $this->addFlash(
                    'success',
                    $this->trans('Configuration sauvegardée.', 'Modules.Scalwaysdata.Admin')
                );
            }
        }

        $logsPath = (string) Configuration::get('SC_ALWAYSDATA_LOGS_PATH');
        $htaccessPath = (string) Configuration::get('SC_ALWAYSDATA_HTACCESS_PATH');
        $logsPathHint = ($_SERVER['HOME'] ?? '') . '/admin/logs/';
        $defaults = ['apache' => 5000, 'http' => 10000, 'php' => 5000, 'sites' => 2000];
        $linesPerSource = [];
        foreach ($defaults as $dir => $default) {
            $v = (int) Configuration::get('SC_ALWAYSDATA_LINES_' . strtoupper($dir));
            $linesPerSource[$dir] = $v > 0 ? $v : $default;
        }

        return $this->render(
            '@Modules/sc_alwaysdata/views/templates/admin/index.html.twig',
            [
                'layoutTitle'   => $this->trans('Alwaysdata Log Viewer', 'Modules.Scalwaysdata.Admin'),
                'enableSidebar' => true,
                'help_link'     => false,
                'logsPath'      => $logsPath,
                'htaccessPath'  => $htaccessPath,
                'logsPathHint'  => $logsPathHint,
                'linesPerSource' => $linesPerSource,
                'statsUrl'      => $this->generateUrl('sc_alwaysdata_stats'),
                'conversionUrl' => $this->generateUrl('sc_alwaysdata_conversion'),
            ]
        );
    }

    /**
     * @AdminSecurity(
     *     "is_granted('read', request.get('_legacy_controller'))",
     *     message="You do not have permission to access this.",
     *     redirectRoute="admin_dashboard"
     * )
     */
    public function analyseAction(): JsonResponse
    {
        try {
            $sources = $this->logReaderService->readTodayLogs();

            $crawlers = $this->crawlerAnalyserService->analyse($sources);
            $blockedIps = $this->htaccessService->readBlockedIps();
            $blockedUAs = $this->htaccessService->readBlockedUAs();
            $phpErrors = $this->phpErrorAnalyserService->analyse($sources);

            foreach ($crawlers as &$entry) {
                $ips = $entry['ips'] ?? [];
                $ipBlocked = !empty(array_intersect($ips, $blockedIps));
                $uaBlocked = false;
                if (!empty($entry['matched_bot'])) {
                    foreach ($blockedUAs as $blockedUa) {
                        if (stripos($entry['matched_bot'], $blockedUa) !== false
                            || stripos($blockedUa, $entry['matched_bot']) !== false) {
                            $uaBlocked = true;
                            break;
                        }
                    }
                }
                if (!$uaBlocked) {
                    foreach ($entry['user_agents'] as $ua) {
                        foreach ($blockedUAs as $blockedUa) {
                            if (stripos($ua, $blockedUa) !== false) {
                                $uaBlocked = true;
                                break 2;
                            }
                        }
                    }
                }
                $entry['already_blocked'] = $ipBlocked || $uaBlocked;
            }
            unset($entry);

            $sourcesInfo = array_map(function (array $source): array {
                $lines = $source['lines'] ?? [];

                return [
                    'source'     => $source['source'],
                    'truncated'  => $source['truncated'] ?? false,
                    'error'      => $source['error'],
                    'line_count' => count($lines),
                    'preview'    => array_slice($lines, -100),
                ];
            }, $sources);

            return new JsonResponse([
                'crawlers'    => $crawlers,
                'php_errors'  => $phpErrors,
                'sources'     => $sourcesInfo,
                'blocked_ips' => $blockedIps,
                'blocked_uas' => $blockedUAs,
            ]);
        } catch (\Throwable $e) {
            return new JsonResponse(['error' => $e->getMessage()], 500);
        }
    }

    /**
     * @AdminSecurity(
     *     "is_granted('read', request.get('_legacy_controller'))",
     *     message="You do not have permission to access this.",
     *     redirectRoute="admin_dashboard"
     * )
     */
    public function statsAction(Request $request): JsonResponse
    {
        $date = $this->resolveDate((string) $request->query->get('date', ''));
        $period = $this->resolvePeriod((int) $request->query->get('period', 30));

        $snapshot = DailyStat::getByDate($date);

        $rows = Db::getInstance()->executeS(
            'SELECT stat_date, requests_human, views_product, errors_500_front, errors_500_bo, errors_500_checkout
             FROM `' . _DB_PREFIX_ . 'sc_alwaysdata_stats_daily`
             WHERE stat_date >= DATE_SUB(\'' . pSQL($date) . '\', INTERVAL ' . $period . ' DAY)
             AND stat_date <= \'' . pSQL($date) . '\'
             ORDER BY stat_date ASC'
        );

        $cronToken = (string) Configuration::get(\sc_alwaysdata::CONFIG_CRON_TOKEN);
        $baseUrl = (string) \Tools::getShopDomainSsl(true);

        return new JsonResponse([
            'snapshot'  => $snapshot ? $this->serializeStat($snapshot) : null,
            'period'    => $rows ?: [],
            'cronToken' => $cronToken,
            'cronUrl'   => $baseUrl . '/module/sc_alwaysdata/cron?token=' . urlencode($cronToken),
        ]);
    }

    /**
     * @AdminSecurity(
     *     "is_granted('read', request.get('_legacy_controller'))",
     *     message="You do not have permission to access this.",
     *     redirectRoute="admin_dashboard"
     * )
     */
    public function conversionAction(Request $request): JsonResponse
    {
        $date = $this->resolveDate((string) $request->query->get('date', ''));
        $period = $this->resolvePeriod((int) $request->query->get('period', 30));

        $snapshot = DailyStat::getByDate($date);

        $rows = Db::getInstance()->executeS(
            'SELECT stat_date, views_product, cart_adds, views_cart, views_checkout, post_checkout, orders_confirmed
             FROM `' . _DB_PREFIX_ . 'sc_alwaysdata_stats_daily`
             WHERE stat_date >= DATE_SUB(\'' . pSQL($date) . '\', INTERVAL ' . $period . ' DAY)
             AND stat_date <= \'' . pSQL($date) . '\'
             ORDER BY stat_date ASC'
        );

        return new JsonResponse([
            'snapshot' => $snapshot ? $this->serializeStat($snapshot) : null,
            'period'   => $rows ?: [],
        ]);
    }

    /**
     * @AdminSecurity(
     *     "is_granted('update', request.get('_legacy_controller'))",
     *     message="You do not have permission to modify this.",
     *     redirectRoute="admin_dashboard"
     * )
     */
    public function applyBlockAction(Request $request): JsonResponse
    {
        if (!$this->isCsrfTokenValid('sc_alwaysdata_apply_block', $request->request->get('_token'))) {
            return new JsonResponse(['success' => false, 'message' => 'Invalid CSRF token'], 403);
        }

        $type = (string) $request->request->get('type', '');
        $value = (string) $request->request->get('value', '');

        try {
            if ($type === 'ip') {
                $this->htaccessService->blockIp($value);
            } elseif ($type === 'ua') {
                $this->htaccessService->blockUserAgent($value);
            } else {
                return new JsonResponse(['success' => false, 'message' => 'Unknown block type: ' . $type]);
            }
        } catch (\InvalidArgumentException $e) {
            return new JsonResponse(['success' => false, 'message' => $e->getMessage()]);
        } catch (\RuntimeException $e) {
            return new JsonResponse(['success' => false, 'message' => $e->getMessage()]);
        }

        return new JsonResponse(['success' => true, 'message' => 'Blocked successfully']);
    }

    /**
     * @AdminSecurity(
     *     "is_granted('update', request.get('_legacy_controller'))",
     *     message="You do not have permission to modify this.",
     *     redirectRoute="admin_dashboard"
     * )
     */
    public function applyUnblockAction(Request $request): JsonResponse
    {
        if (!$this->isCsrfTokenValid('sc_alwaysdata_apply_block', $request->request->get('_token'))) {
            return new JsonResponse(['success' => false, 'message' => 'Invalid CSRF token'], 403);
        }

        $type = (string) $request->request->get('type', '');
        $value = (string) $request->request->get('value', '');

        try {
            if ($type === 'ip') {
                $this->htaccessService->unblockIp($value);
            } elseif ($type === 'ua') {
                $this->htaccessService->unblockUserAgent($value);
            } else {
                return new JsonResponse(['success' => false, 'message' => 'Unknown unblock type: ' . $type]);
            }
        } catch (\InvalidArgumentException $e) {
            return new JsonResponse(['success' => false, 'message' => $e->getMessage()]);
        } catch (\RuntimeException $e) {
            return new JsonResponse(['success' => false, 'message' => $e->getMessage()]);
        }

        return new JsonResponse(['success' => true, 'message' => 'Unblocked successfully']);
    }

    private function resolveDate(string $raw): string
    {
        if (preg_match('/^\d{4}-\d{2}-\d{2}$/', $raw)) {
            return $raw;
        }

        return date('Y-m-d', strtotime('yesterday'));
    }

    private function resolvePeriod(int $raw): int
    {
        return in_array($raw, [7, 30], true) ? $raw : 30;
    }

    private function serializeStat(DailyStat $stat): array
    {
        return [
            'stat_date'                  => $stat->stat_date,
            'requests_total'             => (int) $stat->requests_total,
            'requests_human'             => (int) $stat->requests_human,
            'mobile'                     => (int) $stat->mobile,
            'desktop'                    => (int) $stat->desktop,
            'views_product'              => (int) $stat->views_product,
            'cart_adds'                  => (int) $stat->cart_adds,
            'views_cart'                 => (int) $stat->views_cart,
            'views_checkout'             => (int) $stat->views_checkout,
            'post_checkout'              => (int) $stat->post_checkout,
            'orders_confirmed'           => (int) $stat->orders_confirmed,
            'errors_500_front'           => (int) $stat->errors_500_front,
            'errors_500_bo'              => (int) $stat->errors_500_bo,
            'errors_500_checkout'        => (int) $stat->errors_500_checkout,
            'errors_500_checkout_detail' => json_decode($stat->errors_500_checkout_detail ?: '[]', true),
            'top_pages'                  => json_decode($stat->top_pages ?: '[]', true),
            'top_ips'                    => json_decode($stat->top_ips ?: '[]', true),
            'hourly_breakdown'           => json_decode($stat->hourly_breakdown ?: '{}', true),
        ];
    }

    private function ensureStatsTable(): void
    {
        $tableExists = (bool) Db::getInstance()->getValue(
            'SELECT COUNT(*) FROM information_schema.TABLES
             WHERE TABLE_SCHEMA = DATABASE()
             AND TABLE_NAME = \'' . _DB_PREFIX_ . 'sc_alwaysdata_stats_daily\''
        );

        if (!$tableExists) {
            Db::getInstance()->execute(DailyStat::getCreateTableSql());
        }
    }
}

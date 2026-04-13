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
use PrestaShopBundle\Controller\Admin\FrameworkBundleAdminController;
use PrestaShopBundle\Security\Annotation\AdminSecurity;
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
     * Index action: settings form + analysis trigger
     *
     * @AdminSecurity(
     *     "is_granted('read', request.get('_legacy_controller'))",
     *     message="You do not have permission to access this.",
     *     redirectRoute="admin_dashboard"
     * )
     */
    public function indexAction(Request $request): Response
    {
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
                'layoutTitle' => $this->trans('Alwaysdata Log Viewer', 'Modules.Scalwaysdata.Admin'),
                'enableSidebar' => true,
                'help_link' => false,
                'logsPath' => $logsPath,
                'htaccessPath' => $htaccessPath,
                'logsPathHint' => $logsPathHint,
                'linesPerSource' => $linesPerSource,
            ]
        );
    }

    /**
     * Analyse action: run log analysis
     *
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
                // Check matched_bot name against blocked UAs
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
                    'source' => $source['source'],
                    'truncated' => $source['truncated'] ?? false,
                    'error' => $source['error'],
                    'line_count' => count($lines),
                    'preview' => array_slice($lines, -100),
                ];
            }, $sources);

            // --- DEBUG (remove after diagnosis) ---
            $httpLines  = [];
            $phpLines   = [];
            foreach ($sources as $src) {
                if ($src['source'] === 'http' && empty($src['error'])) {
                    $httpLines = array_slice($src['lines'] ?? [], 0, 5);
                }
                if ($src['source'] === 'php' && empty($src['error'])) {
                    $phpLines = array_slice($src['lines'] ?? [], 0, 10);
                }
            }
            $crawlerPattern = '/^(?:\S+\s+)?(\d[\d.:a-fA-F]+)\s+\S+\s+\S+\s+\[.*?\]\s+"[^"]*"\s+\d+\s+\S+(?:\s+"[^"]*"\s+"([^"]*)")?/';
            $phpPattern     = '/\bPHP\s+(?P<level>Fatal error|Parse error|Warning|Notice|Deprecated|Strict Standards):/i';
            $crawlerSample  = array_map(function (string $l) use ($crawlerPattern): array {
                preg_match($crawlerPattern, $l, $m);
                return ['line' => substr($l, 0, 120), 'ip' => $m[1] ?? null, 'ua' => $m[2] ?? null];
            }, $httpLines);
            $phpSample = array_map(function (string $l) use ($phpPattern): array {
                return ['line' => substr($l, 0, 120), 'match' => (bool) preg_match($phpPattern, $l)];
            }, $phpLines);
            // --- END DEBUG ---

            return new JsonResponse([
                'crawlers'    => $crawlers,
                'php_errors'  => $phpErrors,
                'sources'     => $sourcesInfo,
                'blocked_ips' => $blockedIps,
                'blocked_uas' => $blockedUAs,
                '_debug' => [
                    'htaccess_path'    => (string) \Configuration::get('SC_ALWAYSDATA_HTACCESS_PATH'),
                    'htaccess_snippet' => $this->htaccessService->readSnippet(),
                    'crawler_sample'   => $crawlerSample,
                    'php_sample'       => $phpSample,
                ],
            ]);
        } catch (\Throwable $e) {
            return new JsonResponse(['error' => $e->getMessage()], 500);
        }
    }

    /**
     * Apply block action: write .htaccess block rules
     *
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
     * Apply unblock action: remove blocking rules from .htaccess
     *
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
}

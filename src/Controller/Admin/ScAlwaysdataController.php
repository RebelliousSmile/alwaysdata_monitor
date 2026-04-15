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
use ScAlwaysdata\Entity\DailyResource;
use ScAlwaysdata\Entity\DailyStat;
use ScAlwaysdata\Entity\ResourceSample;
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
        $this->ensureResourcesTable();

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

        $cronToken = (string) Configuration::get('SC_ALWAYSDATA_CRON_TOKEN');
        if (!$cronToken) {
            $cronToken = \Tools::passwdGen(32);
            Configuration::updateValue('SC_ALWAYSDATA_CRON_TOKEN', $cronToken);
        }
        $baseUrl = (string) \Tools::getShopDomainSsl(true);
        $cronUrl = $baseUrl . '/module/sc_alwaysdata/cron?token=' . urlencode($cronToken);
        $cronResourcesUrl = $baseUrl . '/module/sc_alwaysdata/cron_resources?token=' . urlencode($cronToken);
        $cronResourcesSampleUrl = $baseUrl . '/module/sc_alwaysdata/cron_resources_sample?token=' . urlencode($cronToken);

        return $this->render(
            '@Modules/sc_alwaysdata/views/templates/admin/index.html.twig',
            [
                'layoutTitle'            => $this->trans('Alwaysdata Log Viewer', 'Modules.Scalwaysdata.Admin'),
                'enableSidebar'          => true,
                'help_link'              => false,
                'logsPath'               => $logsPath,
                'htaccessPath'           => $htaccessPath,
                'logsPathHint'           => $logsPathHint,
                'linesPerSource'         => $linesPerSource,
                'statsUrl'               => $this->generateUrl('sc_alwaysdata_stats'),
                'conversionUrl'          => $this->generateUrl('sc_alwaysdata_conversion'),
                'resourcesStatsUrl'      => $this->generateUrl('sc_alwaysdata_resources_stats'),
                'cronUrl'                => $cronUrl,
                'cronResourcesUrl'       => $cronResourcesUrl,
                'cronResourcesSampleUrl' => $cronResourcesSampleUrl,
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
        try {
            $date = $this->resolveDate((string) $request->request->get('date', ''));
            $period = $this->resolvePeriod((int) $request->request->get('period', 30));

            $snapshot = DailyStat::getByDate($date);

            $rows = Db::getInstance()->executeS(
                'SELECT stat_date, requests_human, views_product, errors_500_front, errors_500_bo, errors_500_checkout
                 FROM `' . _DB_PREFIX_ . 'sc_alwaysdata_stats_daily`
                 WHERE stat_date >= DATE_SUB(\'' . pSQL($date) . '\', INTERVAL ' . $period . ' DAY)
                 AND stat_date <= \'' . pSQL($date) . '\'
                 ORDER BY stat_date ASC'
            );

            $cronToken = (string) Configuration::get('SC_ALWAYSDATA_CRON_TOKEN');
            $baseUrl = (string) \Tools::getShopDomainSsl(true);

            return new JsonResponse([
                'snapshot'  => $snapshot ? $this->serializeStat($snapshot) : null,
                'period'    => $rows ?: [],
                'cronToken' => $cronToken,
                'cronUrl'   => $baseUrl . '/module/sc_alwaysdata/cron?token=' . urlencode($cronToken),
            ]);
        } catch (\Throwable $e) {
            return new JsonResponse(['error' => $e->getMessage(), 'trace' => $e->getFile() . ':' . $e->getLine()], 500);
        }
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
        try {
            $date = $this->resolveDate((string) $request->request->get('date', ''));
            $period = $this->resolvePeriod((int) $request->request->get('period', 30));

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
        } catch (\Throwable $e) {
            return new JsonResponse(['error' => $e->getMessage(), 'trace' => $e->getFile() . ':' . $e->getLine()], 500);
        }
    }

    /**
     * @AdminSecurity(
     *     "is_granted('read', request.get('_legacy_controller'))",
     *     message="You do not have permission to access this.",
     *     redirectRoute="admin_dashboard"
     * )
     */
    public function resourcesStatsAction(Request $request): JsonResponse
    {
        try {
            $date   = $this->resolveDate((string) $request->request->get('date', ''), true);
            $period = $this->resolvePeriod((int) $request->request->get('period', 7));

            $stats      = $this->fetchResourceStats($date, $period);
            $series     = $this->fetchResourceSeries($date, $period);
            $latest     = $this->fetchLatestSample();
            $topPages   = $this->fetchMergedTopPages($date, $period);
            $daily      = $this->fetchDailyStats($date, $period);
            $report     = $this->buildHealthReport($stats, $latest, $period);

            return new JsonResponse([
                'stats'      => $stats,
                'series'     => $series,
                'latest'     => $latest,
                'top_pages'  => $topPages,
                'daily'      => $daily,
                'report'     => $report,
            ]);
        } catch (\Throwable $e) {
            return new JsonResponse(['error' => $e->getMessage(), 'trace' => $e->getFile() . ':' . $e->getLine()], 500);
        }
    }

    /**
     * @return array<string, mixed>
     */
    private function fetchResourceStats(string $date, int $period): array
    {
        $row = Db::getInstance()->getRow(
            'SELECT
                COUNT(*) AS samples,
                ROUND(AVG(ram_used_mb))  AS ram_avg_mb,
                MAX(ram_used_mb)         AS ram_peak_mb,
                MAX(ram_total_mb)        AS ram_total_mb,
                SUM(CASE WHEN ram_total_mb > 0 AND ram_used_mb * 100 >= ram_total_mb * 95 THEN 1 ELSE 0 END) AS peaks_95,
                SUM(CASE WHEN ram_total_mb > 0 AND ram_used_mb * 100 >= ram_total_mb * 80 THEN 1 ELSE 0 END) AS peaks_80,
                ROUND(AVG(cpu_load_1), 2) AS cpu_avg,
                MAX(cpu_load_1)           AS cpu_peak,
                ROUND(AVG(opcache_used_mb), 1) AS opcache_avg
             FROM `' . _DB_PREFIX_ . 'sc_alwaysdata_resources_samples`
             WHERE sampled_at >= DATE_SUB(\'' . pSQL($date) . '\', INTERVAL ' . $period . ' DAY)
               AND sampled_at <  DATE_ADD(\'' . pSQL($date) . '\', INTERVAL 1 DAY)'
        );

        return [
            'samples'      => (int) ($row['samples'] ?? 0),
            'ram_avg_mb'   => (int) ($row['ram_avg_mb'] ?? 0),
            'ram_peak_mb'  => (int) ($row['ram_peak_mb'] ?? 0),
            'ram_total_mb' => (int) ($row['ram_total_mb'] ?? 0),
            'peaks_95'     => (int) ($row['peaks_95'] ?? 0),
            'peaks_80'     => (int) ($row['peaks_80'] ?? 0),
            'cpu_avg'      => (float) ($row['cpu_avg'] ?? 0),
            'cpu_peak'     => (float) ($row['cpu_peak'] ?? 0),
            'opcache_avg'  => (float) ($row['opcache_avg'] ?? 0),
        ];
    }

    /**
     * Produit des constats "état actuel à l'instant T", factuels, sans verdict
     * sur une tendance (utilisé quand on n'a pas assez de samples pour conclure).
     *
     * @param array<string, mixed> $latest
     * @return array<int, array<string, mixed>>
     */
    private function buildInstantSnapshotFindings(array $latest): array
    {
        $findings = [];

        // RAM à l'instant
        $ramTotal = max(1, (int) $latest['ram_total_mb']);
        $ramPct   = (int) round($latest['ram_used_mb'] * 100 / $ramTotal);

        if ($ramPct < 60) {
            $ramQualif = 'confortable';
        } elseif ($ramPct < 80) {
            $ramQualif = 'à un niveau modéré';
        } elseif ($ramPct < 95) {
            $ramQualif = 'à un niveau élevé';
        } else {
            $ramQualif = 'proche de la saturation';
        }
        $findings[] = [
            'severity' => 'info',
            'category' => 'RAM',
            'title'    => 'Mémoire vive à l\'instant',
            'detail'   => sprintf(
                'À l\'instant de la dernière mesure, la RAM utilisée est de %d%% (%d Mo sur %d Mo), soit %s. Pour savoir si c\'est votre niveau habituel ou un pic ponctuel, il faut attendre plusieurs heures de mesures.',
                $ramPct,
                (int) $latest['ram_used_mb'],
                $ramTotal,
                $ramQualif
            ),
        ];

        // CPU à l'instant
        $cpu = (float) $latest['cpu_load_1'];
        if ($cpu < 0.8) {
            $cpuQualif = 'faible';
        } elseif ($cpu < 1.5) {
            $cpuQualif = 'modérée';
        } elseif ($cpu < 2.0) {
            $cpuQualif = 'élevée';
        } else {
            $cpuQualif = 'très élevée';
        }
        $findings[] = [
            'severity' => 'info',
            'category' => 'CPU',
            'title'    => 'Charge du processeur à l\'instant',
            'detail'   => sprintf(
                'La charge CPU instantanée est de %.2f (%s sur un serveur 2 cœurs). Attention : ce chiffre peut tomber pile pendant le passage d\'un robot de moteur de recherche ou un cron interne — il ne reflète pas forcément votre état habituel.',
                $cpu,
                $cpuQualif
            ),
        ];

        // Disque à l'instant (factuel)
        if ((float) $latest['disk_total_gb'] > 0) {
            $diskPct = (int) round($latest['disk_used_gb'] * 100 / $latest['disk_total_gb']);
            $findings[] = [
                'severity' => 'info',
                'category' => 'Disque',
                'title'    => 'Espace disque occupé',
                'detail'   => sprintf(
                    'Votre site occupe %d%% de l\'espace disque disponible (%.1f Go sur %.1f Go). Cette valeur évolue très lentement, elle est donc fiable même avec peu de mesures.',
                    $diskPct,
                    (float) $latest['disk_used_gb'],
                    (float) $latest['disk_total_gb']
                ),
            ];
        }

        // Top processus instantané
        if (!empty($latest['top_processes']) && is_array($latest['top_processes'])) {
            $top = $latest['top_processes'][0] ?? null;
            if ($top && isset($top['name'], $top['rss_mb'])) {
                $findings[] = [
                    'severity' => 'info',
                    'category' => 'Processus',
                    'title'    => 'Processus le plus gourmand à l\'instant',
                    'detail'   => sprintf(
                        'Le processus qui consomme le plus de mémoire en ce moment est "%s" avec %d Mo. C\'est généralement normal : PHP garde en mémoire le code compilé des pages consultées pour accélérer les suivantes.',
                        (string) $top['name'],
                        (int) $top['rss_mb']
                    ),
                ];
            }
        }

        // Top module OPcache non-core (éducatif, même avec peu de samples)
        if (!empty($latest['top_modules_opcache']) && is_array($latest['top_modules_opcache'])) {
            $coreBuckets = ['[vendor]', '[core classes]', '[core controllers]', '[core src]', '[themes]', '[other]', '[admin]', '[modules-root]'];
            foreach ($latest['top_modules_opcache'] as $module) {
                if (!isset($module['module'], $module['size_mb'])) {
                    continue;
                }
                if (in_array($module['module'], $coreBuckets, true)) {
                    continue;
                }
                if ((float) $module['size_mb'] >= 3.0) {
                    $findings[] = [
                        'severity'       => 'info',
                        'category'       => 'Modules',
                        'title'          => 'Module le plus volumineux en mémoire',
                        'detail'         => sprintf(
                            'Parmi vos modules installés, "%s" est actuellement le plus lourd dans la mémoire PHP (%.1f Mo). C\'est une observation factuelle, pas forcément un problème — les modules les plus gros ne sont pas toujours ceux qui consomment le plus de CPU.',
                            (string) $module['module'],
                            (float) $module['size_mb']
                        ),
                        'recommendation' => sprintf(
                            'Si vous n\'utilisez pas "%s" au quotidien, le désactiver peut libérer un peu de mémoire. Vérifiez d\'abord qu\'il n\'est pas nécessaire au bon fonctionnement du site.',
                            (string) $module['module']
                        ),
                    ];
                    break;
                }
            }
        }

        return $findings;
    }

    /**
     * Convertit un nombre de minutes en durée lisible par un humain.
     */
    private function formatDuration(int $minutes): string
    {
        if ($minutes < 60) {
            return $minutes . ' min';
        }
        if ($minutes < 60 * 24) {
            $hours = (int) floor($minutes / 60);
            $mins  = $minutes % 60;
            return $mins > 0
                ? sprintf('%dh%02d', $hours, $mins)
                : sprintf('%d h', $hours);
        }
        $days  = (int) floor($minutes / (60 * 24));
        $hours = (int) floor(($minutes % (60 * 24)) / 60);
        return $hours > 0
            ? sprintf('%d j %d h', $days, $hours)
            : sprintf('%d j', $days);
    }

    /**
     * Construit un rapport d'état lisible par un admin non-technicien :
     * verdict global + constats + recommandations actionables.
     *
     * @param array<string, mixed>      $stats
     * @param array<string, mixed>|null $latest
     * @return array<string, mixed>
     */
    private function buildHealthReport(array $stats, ?array $latest, int $period): array
    {
        $findings = [];

        // --- Aucune donnée ---
        if ((int) $stats['samples'] === 0) {
            return [
                'overall'       => 'info',
                'overall_label' => 'Aucune donnée collectée',
                'overall_icon'  => 'hourglass_empty',
                'findings'      => [[
                    'severity'       => 'info',
                    'category'       => 'Collecte',
                    'title'          => 'Aucun sample enregistré',
                    'detail'         => 'Aucune donnée n\'a encore été collectée pour la période sélectionnée.',
                    'recommendation' => 'Configurez la tâche planifiée Alwaysdata (toutes les 15 min) ou cliquez sur « Sample now » pour démarrer la collecte.',
                ]],
            ];
        }

        // --- Couverture des samples ---
        $expectedSamples = $period * 96; // 96 samples/jour à 15 min
        $samplesCount    = (int) $stats['samples'];
        $minutesOfData   = $samplesCount * 15; // 1 sample = 15 minutes de mesure
        $confidenceLow   = $samplesCount < 10; // moins de 2h30 de données → pas assez pour conclure

        if ($confidenceLow) {
            $findings[] = [
                'severity'       => 'info',
                'category'       => 'Patience',
                'title'          => 'Données insuffisantes pour un diagnostic fiable',
                'detail'         => sprintf(
                    '%s de mesures disponibles sur les %d jour(s) visé(s). C\'est trop peu pour distinguer un vrai problème d\'un instant exceptionnel (ex: un crawler qui passe pile au moment de la mesure).',
                    $this->formatDuration($minutesOfData),
                    $period
                ),
                'recommendation' => 'Revenez dans quelques heures (idéalement après 24 h complètes). La qualité du diagnostic s\'améliore automatiquement avec chaque nouvelle mesure.',
            ];

            // On donne quand même une photo factuelle de l'instant présent
            if ($latest) {
                $findings = array_merge($findings, $this->buildInstantSnapshotFindings($latest));
            }

            return [
                'overall'       => 'info',
                'overall_label' => 'Diagnostic en cours — photo instantanée ci-dessous',
                'overall_icon'  => 'hourglass_bottom',
                'findings'      => $findings,
            ];
        }

        if ($samplesCount < ($expectedSamples * 0.5)) {
            $findings[] = [
                'severity'       => 'info',
                'category'       => 'Données',
                'title'          => 'Analyse basée sur des mesures partielles',
                'detail'         => sprintf(
                    '%s de mesures disponibles sur les %d jour(s) visé(s). Les tendances ci-dessous sont fiables mais gagneront en précision dans les prochains jours.',
                    $this->formatDuration($minutesOfData),
                    $period
                ),
            ];
        }

        // --- Analyse RAM ---
        $ramTotal   = max(1, (int) $stats['ram_total_mb']);
        $ramAvgPct  = (int) round($stats['ram_avg_mb']  * 100 / $ramTotal);
        $ramPeakPct = (int) round($stats['ram_peak_mb'] * 100 / $ramTotal);

        if ($ramPeakPct > 100) {
            $findings[] = [
                'severity'       => 'critical',
                'category'       => 'RAM',
                'title'          => 'Dépassement de la limite RAM du plan',
                'detail'         => sprintf(
                    'Un ou plusieurs samples montrent une RAM utilisée supérieure au plafond (%d Mo sur %d Mo autorisés). Cela peut provoquer des erreurs 500 aléatoires et des kills de processus.',
                    (int) $stats['ram_peak_mb'],
                    $ramTotal
                ),
                'recommendation' => 'Vérifier les modules récemment installés, désactiver ceux qui ne sont pas essentiels, ou upgrader le plan Alwaysdata vers une formule avec plus de RAM.',
            ];
        } elseif ($ramAvgPct > 85) {
            $findings[] = [
                'severity'       => 'critical',
                'category'       => 'RAM',
                'title'          => 'RAM très sollicitée en moyenne',
                'detail'         => sprintf(
                    'La RAM utilisée est en moyenne à %d%% de la capacité (%d Mo sur %d Mo). Le serveur n\'a plus de marge pour absorber un pic de trafic.',
                    $ramAvgPct,
                    (int) $stats['ram_avg_mb'],
                    $ramTotal
                ),
                'recommendation' => 'Désactiver les modules non essentiels et surveiller les tendances des prochains jours.',
            ];
        } elseif ($ramAvgPct > 70) {
            $findings[] = [
                'severity'       => 'warning',
                'category'       => 'RAM',
                'title'          => 'RAM bien remplie',
                'detail'         => sprintf(
                    'Moyenne d\'utilisation RAM à %d%%. Le serveur fonctionne mais a peu de marge en cas d\'afflux de visiteurs.',
                    $ramAvgPct
                ),
                'recommendation' => 'Surveiller l\'évolution sur les prochains jours et anticiper un upgrade si la tendance monte.',
            ];
        } else {
            $findings[] = [
                'severity' => 'ok',
                'category' => 'RAM',
                'title'    => 'Utilisation RAM confortable',
                'detail'   => sprintf(
                    'Moyenne à %d%% (%d Mo sur %d Mo). Marge suffisante pour absorber les pics de trafic.',
                    $ramAvgPct,
                    (int) $stats['ram_avg_mb'],
                    $ramTotal
                ),
            ];
        }

        // --- Pics de saturation ---
        $peaks95 = (int) $stats['peaks_95'];
        if ($peaks95 > 5) {
            $findings[] = [
                'severity'       => 'critical',
                'category'       => 'RAM',
                'title'          => 'Pics de saturation fréquents',
                'detail'         => sprintf(
                    '%d samples ont atteint ou dépassé 95%% de RAM utilisée sur la période. Le serveur est régulièrement saturé.',
                    $peaks95
                ),
                'recommendation' => 'À traiter rapidement : identifier les moments de pic (heures, jours), vérifier les logs d\'erreur 500, désactiver les modules ou crawlers suspects.',
            ];
        } elseif ($peaks95 > 0) {
            $findings[] = [
                'severity'       => 'warning',
                'category'       => 'RAM',
                'title'          => 'Pics ponctuels à 95%',
                'detail'         => sprintf('%d samples ponctuels à ≥95%% de RAM.', $peaks95),
                'recommendation' => 'Vérifier si ces pics correspondent à des moments de forte activité normale (flux produits, imports) ou à une anomalie.',
            ];
        }

        // --- Analyse CPU (Alwaysdata Medium = 2 vCPU, load ~2.0 = saturation) ---
        $cpuAvg  = (float) $stats['cpu_avg'];
        $cpuPeak = (float) $stats['cpu_peak'];

        if ($cpuAvg > 1.8) {
            $findings[] = [
                'severity'       => 'critical',
                'category'       => 'CPU',
                'title'          => 'CPU proche de la saturation',
                'detail'         => sprintf(
                    'Charge CPU moyenne à %.2f (pic %.2f). Sur un serveur 2 cœurs, une moyenne au-delà de 1.8 indique une saturation permanente.',
                    $cpuAvg,
                    $cpuPeak
                ),
                'recommendation' => 'Identifier les requêtes lentes via les logs PHP/HTTP, optimiser les hooks lourds, ou upgrader le plan.',
            ];
        } elseif ($cpuAvg > 1.0) {
            $findings[] = [
                'severity' => 'warning',
                'category' => 'CPU',
                'title'    => 'CPU modérément chargé',
                'detail'   => sprintf(
                    'Charge CPU moyenne %.2f, pic %.2f. Le serveur travaille bien mais reste sous contrôle.',
                    $cpuAvg,
                    $cpuPeak
                ),
            ];
        } else {
            $findings[] = [
                'severity' => 'ok',
                'category' => 'CPU',
                'title'    => 'CPU peu sollicité',
                'detail'   => sprintf('Charge CPU moyenne %.2f — aucun problème de performance côté processeur.', $cpuAvg),
            ];
        }

        // --- Analyse disque ---
        if ($latest && (float) $latest['disk_total_gb'] > 0) {
            $diskPct = (int) round($latest['disk_used_gb'] * 100 / $latest['disk_total_gb']);

            if ($diskPct > 90) {
                $findings[] = [
                    'severity'       => 'critical',
                    'category'       => 'Disque',
                    'title'          => 'Espace disque critique',
                    'detail'         => sprintf(
                        '%d%% d\'occupation (%.1f Go sur %.1f Go). Risque de blocage des uploads, des logs et de la base de données.',
                        $diskPct,
                        $latest['disk_used_gb'],
                        $latest['disk_total_gb']
                    ),
                    'recommendation' => 'Vider les logs anciens, supprimer les caches et dumps inutilisés, ou upgrader le quota disque.',
                ];
            } elseif ($diskPct > 80) {
                $findings[] = [
                    'severity'       => 'warning',
                    'category'       => 'Disque',
                    'title'          => 'Espace disque à surveiller',
                    'detail'         => sprintf('%d%% d\'occupation disque.', $diskPct),
                    'recommendation' => 'Prévoir un nettoyage des logs et caches dans les prochains jours.',
                ];
            }
        }

        // --- Module volumineux dans OPcache ---
        if ($latest && !empty($latest['top_modules_opcache']) && is_array($latest['top_modules_opcache'])) {
            $coreBuckets = ['[vendor]', '[core classes]', '[core controllers]', '[core src]', '[themes]', '[other]', '[admin]', '[modules-root]'];
            foreach ($latest['top_modules_opcache'] as $module) {
                if (!isset($module['module'], $module['size_mb'])) {
                    continue;
                }
                if (in_array($module['module'], $coreBuckets, true)) {
                    continue;
                }
                if ((float) $module['size_mb'] >= 5.0) {
                    $findings[] = [
                        'severity'       => 'info',
                        'category'       => 'Modules',
                        'title'          => 'Module volumineux dans OPcache',
                        'detail'         => sprintf(
                            'Le module "%s" occupe %.1f Mo d\'OPcache (%d scripts cachés). Ce module est chargé en mémoire en permanence.',
                            $module['module'],
                            $module['size_mb'],
                            (int) $module['script_count']
                        ),
                        'recommendation' => sprintf(
                            'Si "%s" n\'est pas utilisé au quotidien, désactivez-le pour libérer de la RAM et accélérer les pages.',
                            $module['module']
                        ),
                    ];
                    break; // un seul suffit, on ne spamme pas
                }
            }
        }

        // --- Verdict global ---
        $overall      = 'ok';
        $overallLabel = 'Serveur en bonne santé';
        $overallIcon  = 'check_circle';
        foreach ($findings as $f) {
            if ($f['severity'] === 'critical') {
                $overall      = 'critical';
                $overallLabel = 'Action requise rapidement';
                $overallIcon  = 'error';
                break;
            }
            if ($f['severity'] === 'warning' && $overall !== 'critical') {
                $overall      = 'warning';
                $overallLabel = 'Points de vigilance';
                $overallIcon  = 'warning';
            }
        }

        return [
            'overall'       => $overall,
            'overall_label' => $overallLabel,
            'overall_icon'  => $overallIcon,
            'findings'      => $findings,
        ];
    }

    /**
     * Stats agrégées jour par jour sur la période.
     *
     * @return array<int, array<string, mixed>>
     */
    private function fetchDailyStats(string $date, int $period): array
    {
        $rows = Db::getInstance()->executeS(
            'SELECT
                DATE(sampled_at) AS day,
                COUNT(*)                 AS samples,
                ROUND(AVG(ram_used_mb))   AS ram_avg_mb,
                MAX(ram_used_mb)          AS ram_peak_mb,
                MAX(ram_total_mb)         AS ram_total_mb,
                SUM(CASE WHEN ram_total_mb > 0 AND ram_used_mb * 100 >= ram_total_mb * 95 THEN 1 ELSE 0 END) AS peaks_95,
                SUM(CASE WHEN ram_total_mb > 0 AND ram_used_mb * 100 >= ram_total_mb * 80 THEN 1 ELSE 0 END) AS peaks_80,
                ROUND(AVG(cpu_load_1), 2) AS cpu_avg,
                MAX(cpu_load_1)           AS cpu_peak,
                ROUND(AVG(opcache_used_mb), 1) AS opcache_avg
             FROM `' . _DB_PREFIX_ . 'sc_alwaysdata_resources_samples`
             WHERE sampled_at >= DATE_SUB(\'' . pSQL($date) . '\', INTERVAL ' . $period . ' DAY)
               AND sampled_at <  DATE_ADD(\'' . pSQL($date) . '\', INTERVAL 1 DAY)
             GROUP BY DATE(sampled_at)
             ORDER BY day DESC'
        );

        $result = [];
        foreach ($rows ?: [] as $row) {
            $result[] = [
                'day'          => (string) $row['day'],
                'samples'      => (int) $row['samples'],
                'ram_avg_mb'   => (int) $row['ram_avg_mb'],
                'ram_peak_mb'  => (int) $row['ram_peak_mb'],
                'ram_total_mb' => (int) $row['ram_total_mb'],
                'peaks_95'     => (int) $row['peaks_95'],
                'peaks_80'     => (int) $row['peaks_80'],
                'cpu_avg'      => (float) $row['cpu_avg'],
                'cpu_peak'     => (float) $row['cpu_peak'],
                'opcache_avg'  => (float) $row['opcache_avg'],
            ];
        }

        return $result;
    }

    /**
     * Série temporelle avec downsampling adaptatif.
     * 7j → points bruts (jusqu'à ~672). 30j → buckets de 2h (~360 points).
     *
     * @return array<int, array<string, mixed>>
     */
    private function fetchResourceSeries(string $date, int $period): array
    {
        $bucketSeconds = $period >= 30 ? 7200 : 0;

        if ($bucketSeconds === 0) {
            $rows = Db::getInstance()->executeS(
                'SELECT sampled_at, ram_used_mb, ram_total_mb, cpu_load_1
                 FROM `' . _DB_PREFIX_ . 'sc_alwaysdata_resources_samples`
                 WHERE sampled_at >= DATE_SUB(\'' . pSQL($date) . '\', INTERVAL ' . $period . ' DAY)
                   AND sampled_at <  DATE_ADD(\'' . pSQL($date) . '\', INTERVAL 1 DAY)
                 ORDER BY sampled_at ASC'
            );
            return $rows ?: [];
        }

        $rows = Db::getInstance()->executeS(
            'SELECT
                MIN(sampled_at)           AS sampled_at,
                ROUND(AVG(ram_used_mb))   AS ram_used_mb,
                MAX(ram_used_mb)          AS ram_max_mb,
                MAX(ram_total_mb)         AS ram_total_mb,
                ROUND(AVG(cpu_load_1), 2) AS cpu_load_1
             FROM `' . _DB_PREFIX_ . 'sc_alwaysdata_resources_samples`
             WHERE sampled_at >= DATE_SUB(\'' . pSQL($date) . '\', INTERVAL ' . $period . ' DAY)
               AND sampled_at <  DATE_ADD(\'' . pSQL($date) . '\', INTERVAL 1 DAY)
             GROUP BY FLOOR(UNIX_TIMESTAMP(sampled_at) / ' . $bucketSeconds . ')
             ORDER BY sampled_at ASC'
        );

        return $rows ?: [];
    }

    /**
     * @return array<string, mixed>|null
     */
    private function fetchLatestSample(): ?array
    {
        // Note: Db::getRow() adds LIMIT 1 automatically — do not append it manually.
        $row = Db::getInstance()->getRow(
            'SELECT sampled_at, ram_used_mb, ram_total_mb,
                    cpu_load_1, cpu_load_5, cpu_load_15,
                    disk_used_gb, disk_total_gb, opcache_used_mb,
                    top_processes, top_modules_opcache
             FROM `' . _DB_PREFIX_ . 'sc_alwaysdata_resources_samples`
             ORDER BY sampled_at DESC'
        );

        if (!is_array($row) || empty($row)) {
            return null;
        }

        $row['ram_used_mb']         = (int) $row['ram_used_mb'];
        $row['ram_total_mb']        = (int) $row['ram_total_mb'];
        $row['cpu_load_1']          = (float) $row['cpu_load_1'];
        $row['cpu_load_5']          = (float) $row['cpu_load_5'];
        $row['cpu_load_15']         = (float) $row['cpu_load_15'];
        $row['disk_used_gb']        = (float) $row['disk_used_gb'];
        $row['disk_total_gb']       = (float) $row['disk_total_gb'];
        $row['opcache_used_mb']     = (float) $row['opcache_used_mb'];
        $row['top_processes']       = json_decode($row['top_processes'] ?: '[]', true) ?: [];
        $row['top_modules_opcache'] = json_decode($row['top_modules_opcache'] ?: '[]', true) ?: [];

        return $row;
    }

    /**
     * Merge JSON top_pages over the period. Cap at 7 most recent days to bound CPU.
     *
     * @return array<int, array{path: string, count: int}>
     */
    private function fetchMergedTopPages(string $date, int $period): array
    {
        $cappedPeriod = min($period, 7);

        $rows = Db::getInstance()->executeS(
            'SELECT top_pages
             FROM `' . _DB_PREFIX_ . 'sc_alwaysdata_stats_daily`
             WHERE stat_date >= DATE_SUB(\'' . pSQL($date) . '\', INTERVAL ' . $cappedPeriod . ' DAY)
               AND stat_date <= \'' . pSQL($date) . '\'
             ORDER BY stat_date DESC'
        );

        $merged = [];
        foreach ($rows ?: [] as $row) {
            $pages = json_decode($row['top_pages'] ?: '[]', true);
            if (!is_array($pages)) {
                continue;
            }
            foreach ($pages as $p) {
                if (!isset($p['path'], $p['count'])) {
                    continue;
                }
                $path = (string) $p['path'];
                $merged[$path] = ($merged[$path] ?? 0) + (int) $p['count'];
            }
        }

        arsort($merged);
        $top = array_slice($merged, 0, 10, true);

        $result = [];
        foreach ($top as $path => $count) {
            $result[] = ['path' => $path, 'count' => $count];
        }

        return $result;
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

    private function resolveDate(string $raw, bool $allowToday = false): string
    {
        if (preg_match('/^\d{4}-\d{2}-\d{2}$/', $raw)) {
            return $raw;
        }

        return $allowToday ? date('Y-m-d') : date('Y-m-d', strtotime('yesterday'));
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
            'errors_500_pages'           => json_decode($stat->errors_500_pages ?: '{}', true),
            'top_pages'                  => json_decode($stat->top_pages ?: '[]', true),
            'top_ips'                    => json_decode($stat->top_ips ?: '[]', true),
            'hourly_breakdown'           => json_decode($stat->hourly_breakdown ?: '{}', true),
            'php_errors'                 => json_decode($stat->php_errors ?: '[]', true),
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

    private function ensureResourcesTable(): void
    {
        $dailyExists = (bool) Db::getInstance()->getValue(
            'SELECT COUNT(*) FROM information_schema.TABLES
             WHERE TABLE_SCHEMA = DATABASE()
             AND TABLE_NAME = \'' . _DB_PREFIX_ . 'sc_alwaysdata_resources_daily\''
        );

        if (!$dailyExists) {
            Db::getInstance()->execute(DailyResource::getCreateTableSql());
        }

        $samplesExists = (bool) Db::getInstance()->getValue(
            'SELECT COUNT(*) FROM information_schema.TABLES
             WHERE TABLE_SCHEMA = DATABASE()
             AND TABLE_NAME = \'' . _DB_PREFIX_ . 'sc_alwaysdata_resources_samples\''
        );

        if (!$samplesExists) {
            Db::getInstance()->execute(ResourceSample::getCreateTableSql());
        }
    }
}

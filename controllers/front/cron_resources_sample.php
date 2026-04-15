<?php
/**
 * SC Alwaysdata - PrestaShop 8 Module — Cron sample (15 min) front controller
 *
 * Ce cron est destiné à être appelé toutes les 15 minutes par une tâche planifiée
 * Alwaysdata. Il stocke un sample des ressources en base pour produire des stats
 * (moyennes, pics, séries temporelles) consultables depuis l'onglet Ressources.
 *
 * URL: https://site-a.example/module/sc_alwaysdata/cron_resources_sample?token={SC_ALWAYSDATA_CRON_TOKEN}
 *
 * @author    Scriptami
 * @copyright Scriptami
 * @license   Academic Free License version 3.0
 */

declare(strict_types=1);

use ScAlwaysdata\Entity\ResourceSample;
use ScAlwaysdata\Service\ResourceCollectorService;

class Sc_alwaysdataCron_resources_sampleModuleFrontController extends ModuleFrontController
{
    /** @var bool */
    public $auth = false;

    /** @var array<string, mixed> */
    private $responseData = [];

    /** @var int */
    private $responseHttpCode = 200;

    public function initContent(): void
    {
        $token = (string) Tools::getValue('token');
        $storedToken = (string) Configuration::get(sc_alwaysdata::CONFIG_CRON_TOKEN);

        if ($storedToken === '' || !hash_equals($storedToken, $token)) {
            $this->responseData     = ['error' => 'Forbidden'];
            $this->responseHttpCode = 403;

            return;
        }

        $bucketKey = (int) (floor(time() / 900) * 900);

        try {
            // Fast-path idempotency check before any expensive collection work
            if (ResourceSample::getCountByBucketKey($bucketKey) > 0) {
                $this->responseData = [
                    'skipped'     => true,
                    'bucket_key'  => $bucketKey,
                    'next_bucket_in_seconds' => max(0, ($bucketKey + 900) - time()),
                ];

                return;
            }

            $collector = new ResourceCollectorService();
            $metrics   = $collector->collectSample();

            if ($metrics['ram_used_mb'] > $metrics['ram_total_mb'] * 2) {
                throw new \RuntimeException(sprintf(
                    'Abnormal RAM reading: %d Mo used vs %d Mo total — skipping insert',
                    $metrics['ram_used_mb'],
                    $metrics['ram_total_mb']
                ));
            }

            $sample                      = new ResourceSample();
            $sample->sampled_at          = date('Y-m-d H:i:s');
            $sample->bucket_key          = $bucketKey;
            $sample->ram_used_mb         = (int) $metrics['ram_used_mb'];
            $sample->ram_total_mb        = (int) $metrics['ram_total_mb'];
            $sample->cpu_load_1          = (float) $metrics['cpu_load_1'];
            $sample->cpu_load_5          = (float) $metrics['cpu_load_5'];
            $sample->cpu_load_15         = (float) $metrics['cpu_load_15'];
            $sample->disk_used_gb        = (float) $metrics['disk_used_gb'];
            $sample->disk_total_gb       = (float) $metrics['disk_total_gb'];
            $sample->opcache_used_mb     = (float) $metrics['opcache_used_mb'];
            $sample->top_processes       = (string) json_encode($metrics['top_processes']);
            $sample->top_modules_opcache = (string) json_encode($metrics['top_modules_opcache']);

            try {
                $sample->add();
            } catch (\Throwable $e) {
                // Race window between Phase 1 check and insert — another call just won the bucket
                if (ResourceSample::getCountByBucketKey($bucketKey) > 0) {
                    $this->responseData = [
                        'skipped'    => true,
                        'bucket_key' => $bucketKey,
                        'race'       => true,
                    ];

                    return;
                }
                throw $e;
            }

            $purged     = Db::getInstance()->execute(
                'DELETE FROM `' . _DB_PREFIX_ . 'sc_alwaysdata_resources_samples`
                 WHERE sampled_at < DATE_SUB(NOW(), INTERVAL 30 DAY)'
            );
            $purgedRows = $purged ? (int) Db::getInstance()->Affected_Rows() : 0;

            $this->responseData = [
                'bucket_key'     => $bucketKey,
                'sampled_at'     => $sample->sampled_at,
                'ram_used_mb'    => (int) $sample->ram_used_mb,
                'ram_total_mb'   => (int) $sample->ram_total_mb,
                'cpu_load_1'    => (float) $sample->cpu_load_1,
                'opcache_used_mb' => (float) $sample->opcache_used_mb,
                'purged_rows'    => $purgedRows,
            ];
        } catch (\Throwable $e) {
            PrestaShopLogger::addLog(
                '[sc_alwaysdata] Cron sample error for bucket ' . $bucketKey . ': ' . $e->getMessage(),
                3,
                null,
                'sc_alwaysdata'
            );
            $this->responseData     = ['error' => $e->getMessage(), 'bucket_key' => $bucketKey];
            $this->responseHttpCode = 500;
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

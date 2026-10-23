<?php

/**
 * SC Alwaysdata - PrestaShop 8 Module — Cron ressources (agrégateur journalier)
 *
 * Depuis la version 1.4.0, ce cron ne lit plus directement les métriques système.
 * Il consolide les samples (table sc_alwaysdata_resources_samples) de la veille en
 * une ligne DailyResource, pour garder un historique long (90 jours) au-delà de la
 * fenêtre de rétention des samples (30 jours).
 *
 * Fréquence recommandée : 1 fois par jour à 02h15 (après le cron stats).
 *
 * URL: https://site-a.example/module/sc_alwaysdata/cron_resources?token={SC_ALWAYSDATA_CRON_TOKEN}
 *   (or, preferred, without the query string and with the header
 *   X-Cron-Token: {SC_ALWAYSDATA_CRON_TOKEN}, e.g. curl -H "X-Cron-Token: ...")
 *
 * @author    Scriptami
 * @copyright Scriptami
 * @license   Academic Free License version 3.0
 */

declare(strict_types=1);

use ScAlwaysdata\Entity\DailyResource;
use ScAlwaysdata\Service\CronTokenGuard;

class Sc_alwaysdataCron_resourcesModuleFrontController extends ModuleFrontController
{
    /** @var bool */
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

        try {
            $existing = DailyResource::getByDate($date);
            if ($existing !== null) {
                $this->responseData = ['skipped' => true, 'date' => $date];

                return;
            }

            $row = Db::getInstance()->getRow(
                'SELECT
                    COUNT(*)              AS samples,
                    ROUND(AVG(ram_used_mb))  AS ram_avg_mb,
                    MAX(ram_used_mb)         AS ram_peak_mb,
                    ROUND(AVG(ram_total_mb)) AS ram_total_mb,
                    AVG(cpu_load_1)          AS cpu_load_1,
                    AVG(cpu_load_5)          AS cpu_load_5,
                    AVG(cpu_load_15)         AS cpu_load_15,
                    AVG(disk_used_gb)        AS disk_used_gb,
                    AVG(disk_total_gb)       AS disk_total_gb
                 FROM `' . _DB_PREFIX_ . 'sc_alwaysdata_resources_samples`
                 WHERE DATE(sampled_at) = \'' . pSQL($date) . '\''
            );

            if (!is_array($row) || (int) $row['samples'] === 0) {
                PrestaShopLogger::addLog(
                    '[sc_alwaysdata] Cron resources aggregator: no samples for ' . $date,
                    2,
                    null,
                    'sc_alwaysdata'
                );
                $this->responseData = ['warning' => 'No samples for yesterday', 'date' => $date];
                $this->responseHttpCode = 200;

                return;
            }

            $resource = new DailyResource();
            $resource->resource_date = $date;
            // Use MAX for ram_used_mb to preserve peak visibility in long-term history
            $resource->ram_used_mb = (int) $row['ram_peak_mb'];
            $resource->ram_total_mb = (int) $row['ram_total_mb'];
            $resource->cpu_load_1 = round((float) $row['cpu_load_1'], 2);
            $resource->cpu_load_5 = round((float) $row['cpu_load_5'], 2);
            $resource->cpu_load_15 = round((float) $row['cpu_load_15'], 2);
            $resource->disk_used_gb = round((float) $row['disk_used_gb'], 2);
            $resource->disk_total_gb = round((float) $row['disk_total_gb'], 2);
            $resource->date_add = date('Y-m-d H:i:s');

            if (!$resource->add()) {
                throw new RuntimeException('Failed to insert DailyResource for ' . $date);
            }

            Db::getInstance()->execute(
                'DELETE FROM `' . _DB_PREFIX_ . 'sc_alwaysdata_resources_daily`
                 WHERE resource_date < DATE_SUB(NOW(), INTERVAL 90 DAY)'
            );

            $this->responseData = [
                'date' => $date,
                'samples_aggregated' => (int) $row['samples'],
                'ram_avg_mb' => (int) $row['ram_avg_mb'],
                'ram_peak_mb' => (int) $row['ram_peak_mb'],
                'ram_total_mb' => (int) $row['ram_total_mb'],
            ];
        } catch (Throwable $e) {
            PrestaShopLogger::addLog(
                '[sc_alwaysdata] Cron resources aggregator error for ' . $date . ': ' . $e->getMessage(),
                3,
                null,
                'sc_alwaysdata'
            );
            $this->responseData = ['error' => $e->getMessage(), 'date' => $date];
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

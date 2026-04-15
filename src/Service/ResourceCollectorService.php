<?php
/**
 * SC Alwaysdata - PrestaShop 8 Module
 *
 * @author    Scriptami
 * @copyright Scriptami
 * @license   Academic Free License version 3.0
 */

declare(strict_types=1);

namespace ScAlwaysdata\Service;

if (!defined('_PS_VERSION_')) {
    exit;
}

class ResourceCollectorService
{
    /** Plafond forfait Alwaysdata Medium — utilisé si la limite cgroup n'est pas lisible */
    private const RAM_TOTAL_MB_FALLBACK = 2048;

    /**
     * Collecte RAM, CPU et disque depuis le système.
     *
     * @return array{ram_used_mb: int, ram_total_mb: int, cpu_load_1: float, cpu_load_5: float, cpu_load_15: float, disk_used_gb: float, disk_total_gb: float}
     */
    public function collect(): array
    {
        $cpuLoad   = $this->collectCpuLoad();
        $diskStats = $this->collectDiskStats();
        $cgroupInfo = $this->discoverCgroupInfo();
        [$ramUsed, $ramTotal] = $this->collectRamMb($cgroupInfo);

        return [
            'ram_used_mb'   => $ramUsed,
            'ram_total_mb'  => $ramTotal,
            'cpu_load_1'    => $cpuLoad[0],
            'cpu_load_5'    => $cpuLoad[1],
            'cpu_load_15'   => $cpuLoad[2],
            'disk_used_gb'  => $diskStats['used'],
            'disk_total_gb' => $diskStats['total'],
        ];
    }

    /**
     * Collecte complète pour un sample (cron 15 min) :
     * métriques de base + OPcache + top processes + top modules OPcache.
     *
     * @return array<string, mixed>
     */
    public function collectSample(): array
    {
        $base    = $this->collect();
        $opcache = $this->collectOpcache();

        return array_merge($base, [
            'opcache_used_mb'     => $opcache['used_mb'],
            'top_processes'       => $this->collectTopProcesses(10),
            'top_modules_opcache' => $this->collectTopModulesOpcache(10),
        ]);
    }

    /**
     * Collecte enrichie en temps réel : métriques de base + détails RAM + OPcache.
     *
     * @return array<string, mixed>
     */
    public function collectLive(): array
    {
        $base       = $this->collect();
        $cgroupInfo = $this->discoverCgroupInfo();
        $ramDetail  = $this->collectRamDetail($cgroupInfo);
        $opcache    = $this->collectOpcache();
        $topProcs   = $this->collectTopProcesses(10);

        // Fallback RSS : si pas de cgroup exploitable, on utilise la somme VmRSS de /proc/<pid>/status
        // (déjà calculée par collectRamMb → base['ram_used_mb'] en l'absence de cgroup)
        if ($ramDetail['rss_mb'] === 0 && $cgroupInfo['path'] === null) {
            $ramDetail['rss_mb'] = (int) $base['ram_used_mb'];
        }

        return array_merge($base, [
            'ram_rss_mb'         => $ramDetail['rss_mb'],
            'ram_cache_mb'       => $ramDetail['cache_mb'],
            'opcache_enabled'    => $opcache['enabled'],
            'opcache_used_mb'    => $opcache['used_mb'],
            'opcache_free_mb'    => $opcache['free_mb'],
            'opcache_total_mb'   => $opcache['total_mb'],
            'opcache_strings_mb' => $opcache['strings_mb'],
            'top_processes'      => $topProcs,
            'cgroup_version'     => $cgroupInfo['version'],
            'cgroup_path'        => isset($cgroupInfo['path']) ? (string) $cgroupInfo['path'] : '',
            'collected_at'       => date('Y-m-d H:i:s'),
        ]);
    }

    /**
     * Top N processes du user courant, triés par RSS décroissant.
     *
     * @return array<int, array{name: string, pid: int, rss_mb: int}>
     */
    private function collectTopProcesses(int $limit): array
    {
        if (!function_exists('posix_geteuid')) {
            return [];
        }

        $myUid = posix_geteuid();
        $processes = [];

        $statusFiles = glob('/proc/[0-9]*/status');
        if ($statusFiles === false) {
            return [];
        }

        foreach ($statusFiles as $statusFile) {
            $content = @file_get_contents($statusFile);
            if ($content === false) {
                continue;
            }

            if (!preg_match('/^Uid:\s+(\d+)/m', $content, $uidMatch)) {
                continue;
            }
            if ((int) $uidMatch[1] !== $myUid) {
                continue;
            }

            if (!preg_match('/^Name:\s+(.+)$/m', $content, $nameMatch)) {
                continue;
            }
            if (!preg_match('/^VmRSS:\s+(\d+)\s+kB/m', $content, $rssMatch)) {
                continue;
            }

            $pid = (int) basename(dirname($statusFile));
            $processes[] = [
                'name'   => trim($nameMatch[1]),
                'pid'    => $pid,
                'rss_mb' => (int) round((int) $rssMatch[1] / 1024),
            ];
        }

        usort($processes, function (array $a, array $b): int {
            return $b['rss_mb'] <=> $a['rss_mb'];
        });

        return array_slice($processes, 0, $limit);
    }

    // -------------------------------------------------------------------------
    // RAM
    // -------------------------------------------------------------------------

    /**
     * Retourne [used_mb, total_mb] en testant plusieurs sources dans l'ordre :
     *   1. cgroup (si la limite est raisonnable, sinon rejeté car cgroup racine)
     *   2. Somme VmRSS des fichiers /proc/<pid>/status filtrés sur l'uid courant
     *   3. /proc/meminfo (valeurs host, fallback ultime)
     *
     * @param array{version: int, path: string|null} $cgroupInfo
     * @return array{int, int}
     */
    private function collectRamMb(array $cgroupInfo): array
    {
        $path    = $cgroupInfo['path'];
        $version = $cgroupInfo['version'];

        if ($path !== null) {
            if ($version === 2) {
                $usageFile = $path . '/memory.current';
                $limitFile = $path . '/memory.max';
            } else {
                $usageFile = $path . '/memory.usage_in_bytes';
                $limitFile = $path . '/memory.limit_in_bytes';
            }

            $usedMb  = $this->readBytesFileMb($usageFile);
            $limitMb = $this->readBytesFileMb($limitFile);

            // Accepter le cgroup uniquement si la limite est plausible (ni "max", ni hôte)
            if ($usedMb !== null && $limitMb !== null && $limitMb <= 16384 /* 16 Go max raisonnable */) {
                return [$usedMb, $limitMb];
            }
            // Sinon : cgroup racine ou hôte → on ignore et on passe à /proc/*/status
        }

        // Compte hébergé mutualisé : somme des VmRSS de tous les processus de l'uid courant
        $usedMb = $this->collectRamUsedMbFromProcStatus();
        if ($usedMb !== null) {
            return [$usedMb, self::RAM_TOTAL_MB_FALLBACK];
        }

        // Dernier recours : /proc/meminfo (valeurs host)
        return $this->collectRamMbFromProcMeminfo();
    }

    /**
     * Somme VmRSS des processus de l'uid courant — adapté à l'hébergement mutualisé
     * où le cgroup n'est pas isolé par compte.
     */
    private function collectRamUsedMbFromProcStatus(): ?int
    {
        if (!function_exists('posix_geteuid')) {
            return null;
        }

        $myUid = posix_geteuid();
        $totalKb = 0;
        $found = false;

        $statusFiles = glob('/proc/[0-9]*/status');
        if ($statusFiles === false) {
            return null;
        }

        foreach ($statusFiles as $statusFile) {
            $content = @file_get_contents($statusFile);
            if ($content === false) {
                continue;
            }

            if (!preg_match('/^Uid:\s+(\d+)/m', $content, $uidMatch)) {
                continue;
            }
            if ((int) $uidMatch[1] !== $myUid) {
                continue;
            }

            if (preg_match('/^VmRSS:\s+(\d+)\s+kB/m', $content, $rssMatch)) {
                $totalKb += (int) $rssMatch[1];
                $found = true;
            }
        }

        return $found ? (int) round($totalKb / 1024) : null;
    }

    /**
     * Retourne [rss_mb, cache_mb] depuis memory.stat du cgroup.
     *
     * @param array{version: int, path: string|null} $cgroupInfo
     * @return array{rss_mb: int, cache_mb: int}
     */
    private function collectRamDetail(array $cgroupInfo): array
    {
        $path    = $cgroupInfo['path'];
        $version = $cgroupInfo['version'];

        if ($path !== null) {
            $statFile = $path . '/memory.stat';

            if (is_readable($statFile)) {
                $content = (string) file_get_contents($statFile);

                if ($version === 2) {
                    // cgroup v2 : "anon X" et "file X"
                    preg_match('/^anon (\d+)/m', $content, $rssMatch);
                    preg_match('/^file (\d+)/m', $content, $cacheMatch);
                } else {
                    // cgroup v1 : "rss X" et "cache X"
                    preg_match('/^rss (\d+)/m', $content, $rssMatch);
                    preg_match('/^cache (\d+)/m', $content, $cacheMatch);
                }

                return [
                    'rss_mb'   => isset($rssMatch[1])   ? (int) round((int) $rssMatch[1]   / (1024 * 1024)) : 0,
                    'cache_mb' => isset($cacheMatch[1]) ? (int) round((int) $cacheMatch[1] / (1024 * 1024)) : 0,
                ];
            }
        }

        return ['rss_mb' => 0, 'cache_mb' => 0];
    }

    /**
     * @return array{int, int}
     */
    private function collectRamMbFromProcMeminfo(): array
    {
        if (!is_readable('/proc/meminfo')) {
            return [0, self::RAM_TOTAL_MB_FALLBACK];
        }

        $memInfo = (string) file_get_contents('/proc/meminfo');
        preg_match('/MemTotal:\s+(\d+)\s+kB/', $memInfo, $totalMatch);
        preg_match('/MemAvailable:\s+(\d+)\s+kB/', $memInfo, $availMatch);

        if (empty($totalMatch[1]) || empty($availMatch[1])) {
            return [0, self::RAM_TOTAL_MB_FALLBACK];
        }

        $totalMb = (int) round((int) $totalMatch[1] / 1024);
        $usedMb  = (int) round(((int) $totalMatch[1] - (int) $availMatch[1]) / 1024);

        return [$usedMb, $totalMb];
    }

    // -------------------------------------------------------------------------
    // cgroup auto-découverte
    // -------------------------------------------------------------------------

    /**
     * Détecte la version et le chemin cgroup du processus courant depuis /proc/self/cgroup.
     *
     * @return array{version: int, path: string|null}
     */
    private function discoverCgroupInfo(): array
    {
        if (!is_readable('/proc/self/cgroup')) {
            return ['version' => 0, 'path' => null];
        }

        $content = (string) file_get_contents('/proc/self/cgroup');

        // cgroup v2 (hiérarchie unifiée) : ligne "0::/{path}"
        if (preg_match('/^0::(.+)$/m', $content, $m)) {
            $relPath = trim($m[1]);
            // Remonter vers le premier ancêtre qui expose memory.current
            foreach ([$relPath, dirname($relPath), dirname(dirname($relPath))] as $candidate) {
                $candidate = rtrim($candidate, '/');
                $cgroupPath = '/sys/fs/cgroup' . ($candidate !== '' ? $candidate : '');
                if (is_readable($cgroupPath . '/memory.current')) {
                    return ['version' => 2, 'path' => $cgroupPath];
                }
            }
        }

        // cgroup v1 : chercher le contrôleur memory
        if (preg_match('/^\d+:(?:[^:]*,)?memory(?:,[^:]*)?:(.*)$/m', $content, $m)) {
            $relPath = trim($m[1]);
            // Remonter vers le premier ancêtre qui expose memory.usage_in_bytes
            foreach ([$relPath, dirname($relPath), dirname(dirname($relPath))] as $candidate) {
                $candidate = rtrim($candidate, '/');
                $cgroupPath = '/sys/fs/cgroup/memory' . ($candidate !== '' ? $candidate : '');
                if (is_readable($cgroupPath . '/memory.usage_in_bytes')) {
                    return ['version' => 1, 'path' => $cgroupPath];
                }
            }
        }

        return ['version' => 0, 'path' => null];
    }

    /**
     * Lit un fichier contenant un entier en octets (ou "max") et retourne la valeur en Mo.
     * Retourne null si illisible ou si la valeur est "max" / aberrante.
     */
    private function readBytesFileMb(string $filePath): ?int
    {
        if (!is_readable($filePath)) {
            return null;
        }

        $raw = trim((string) file_get_contents($filePath));

        if ($raw === 'max' || !is_numeric($raw)) {
            return null;
        }

        return (int) round((int) $raw / (1024 * 1024));
    }

    // -------------------------------------------------------------------------
    // CPU
    // -------------------------------------------------------------------------

    /**
     * @return array{0: float, 1: float, 2: float}
     */
    private function collectCpuLoad(): array
    {
        $load = sys_getloadavg();

        if ($load === false) {
            return [0.0, 0.0, 0.0];
        }

        return [
            round((float) $load[0], 2),
            round((float) $load[1], 2),
            round((float) $load[2], 2),
        ];
    }

    // -------------------------------------------------------------------------
    // Disque
    // -------------------------------------------------------------------------

    /**
     * @return array{used: float, total: float}
     */
    private function collectDiskStats(): array
    {
        $path  = $_SERVER['HOME'] ?? '/';
        $total = disk_total_space($path);
        $free  = disk_free_space($path);

        if ($total === false || $free === false) {
            return ['used' => 0.0, 'total' => 100.0];
        }

        return [
            'used'  => round(($total - $free) / (1024 ** 3), 2),
            'total' => round($total / (1024 ** 3), 2),
        ];
    }

    // -------------------------------------------------------------------------
    // OPcache
    // -------------------------------------------------------------------------

    /**
     * @return array{enabled: bool, used_mb: float, free_mb: float, total_mb: float, strings_mb: float}
     */
    private function collectOpcache(): array
    {
        $empty = ['enabled' => false, 'used_mb' => 0.0, 'free_mb' => 0.0, 'total_mb' => 0.0, 'strings_mb' => 0.0];

        if (!function_exists('opcache_get_status')) {
            return $empty;
        }

        $opcacheStatus = @opcache_get_status(false);

        if (!is_array($opcacheStatus) || empty($opcacheStatus['memory_usage'])) {
            return $empty;
        }

        $mem     = $opcacheStatus['memory_usage'];
        $strings = isset($opcacheStatus['interned_strings_usage']) ? $opcacheStatus['interned_strings_usage'] : [];

        $usedBytes   = isset($mem['used_memory'])   ? (int) $mem['used_memory']   : 0;
        $freeBytes   = isset($mem['free_memory'])   ? (int) $mem['free_memory']   : 0;
        $wastedBytes = isset($mem['wasted_memory']) ? (int) $mem['wasted_memory'] : 0;
        $strBytes    = isset($strings['used_memory']) ? (int) $strings['used_memory'] : 0;

        $oneMb = 1024 * 1024;

        return [
            'enabled'    => true,
            'used_mb'    => round(($usedBytes + $wastedBytes) / $oneMb, 1),
            'free_mb'    => round($freeBytes / $oneMb, 1),
            'total_mb'   => round(($usedBytes + $freeBytes + $wastedBytes) / $oneMb, 1),
            'strings_mb' => round($strBytes / $oneMb, 1),
        ];
    }

    /**
     * Top modules par empreinte OPcache, en regroupant les scripts cachés par dossier.
     *
     * @return array<int, array{module: string, size_mb: float, script_count: int}>
     */
    private function collectTopModulesOpcache(int $limit): array
    {
        if (!function_exists('opcache_get_status')) {
            return [];
        }

        $opcacheStatus = @opcache_get_status(true);

        if (!is_array($opcacheStatus) || empty($opcacheStatus['scripts']) || !is_array($opcacheStatus['scripts'])) {
            return [];
        }

        $moduleDir = defined('_PS_MODULE_DIR_') ? rtrim(_PS_MODULE_DIR_, '/') . '/' : '';
        $rootDir   = defined('_PS_ROOT_DIR_')   ? rtrim(_PS_ROOT_DIR_, '/')   . '/' : '';
        $buckets   = [];

        foreach ($opcacheStatus['scripts'] as $path => $info) {
            if (!is_array($info) || !isset($info['memory_consumption'])) {
                continue;
            }
            $bytes = (int) $info['memory_consumption'];
            $name  = $this->classifyOpcachePath((string) $path, $moduleDir, $rootDir);

            if (!isset($buckets[$name])) {
                $buckets[$name] = ['bytes' => 0, 'count' => 0];
            }
            $buckets[$name]['bytes'] += $bytes;
            $buckets[$name]['count'] += 1;
        }

        $oneMb  = 1024 * 1024;
        $result = [];
        foreach ($buckets as $name => $data) {
            $result[] = [
                'module'       => $name,
                'size_mb'      => round($data['bytes'] / $oneMb, 1),
                'script_count' => $data['count'],
            ];
        }

        usort($result, function (array $a, array $b): int {
            return $b['size_mb'] <=> $a['size_mb'];
        });

        return array_slice($result, 0, $limit);
    }

    /**
     * Classifie un chemin cache OPcache dans un bucket lisible (nom de module ou section core).
     */
    private function classifyOpcachePath(string $path, string $moduleDir, string $rootDir): string
    {
        if ($moduleDir !== '' && strpos($path, $moduleDir) === 0) {
            $rest    = substr($path, strlen($moduleDir));
            $segment = strstr($rest, '/', true);

            return $segment !== false ? $segment : ($rest !== '' ? $rest : '[modules-root]');
        }

        if ($rootDir !== '') {
            if (strpos($path, $rootDir . 'vendor/') === 0) {
                return '[vendor]';
            }
            if (strpos($path, $rootDir . 'classes/') === 0) {
                return '[core classes]';
            }
            if (strpos($path, $rootDir . 'controllers/') === 0) {
                return '[core controllers]';
            }
            if (strpos($path, $rootDir . 'src/') === 0) {
                return '[core src]';
            }
            if (strpos($path, $rootDir . 'themes/') === 0) {
                return '[themes]';
            }
            if (strpos($path, $rootDir . 'admin') === 0) {
                return '[admin]';
            }
        }

        return '[other]';
    }
}

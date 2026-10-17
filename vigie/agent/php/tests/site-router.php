<?php

declare(strict_types=1);

// Routeur `php -S` d'un site de test (#13), partagé par AgentTest.php et
// vigie/tests/agent_e2e.rs. Il lit le bloc vigie du .htaccess du dossier
// demandé et en applique les groupes à la place d'Apache : UA « contient,
// sans casse », REMOTE_ADDR, %{TIME} à l'heure du scénario. Le scénario
// (site.json du dossier VIGIE_SITE_DIR) simule les pannes : 500 dans le bac
// à sable, 200 sans la page témoin, horloge décalée, accueil en 500 une fois
// le bloc posé, fichier modifié par un tiers.
$state = (string) getenv('VIGIE_SITE_DIR');
$scenario = json_decode((string) file_get_contents($state . '/site.json'), true);
$root = $_SERVER['DOCUMENT_ROOT'];
$path = (string) parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);
$ua = $_SERVER['HTTP_USER_AGENT'] ?? '';
file_put_contents($state . '/hits.log', "{$path}\t{$ua}\n", FILE_APPEND);
$sandbox = str_starts_with($path, '/vigie-essai-');
if ($sandbox && !empty($scenario['tamper_in_sandbox']) && !is_file($state . '/tampered')) {
    touch($state . '/tampered');
    file_put_contents("{$root}/.htaccess", "# tiers\n", FILE_APPEND);
}
if ($sandbox && !empty($scenario['sandbox_500'])) {
    http_response_code(500);
    return true;
}
if ($sandbox && !empty($scenario['no_nonce'])) {
    echo 'page de repli';
    return true;
}
$dir = $sandbox ? $root . dirname($path) : $root;
$htaccess = is_file("{$dir}/.htaccess") ? file_get_contents("{$dir}/.htaccess") : '';
if (!$sandbox && $path === '/' && !empty($scenario['home_500_with_vigie']) && str_contains($htaccess, '# BEGIN vigie')) {
    if (!empty($scenario['tamper_after_swap'])) {
        file_put_contents("{$root}/.htaccess", "# tiers\n", FILE_APPEND);
    }
    http_response_code(500);
    return true;
}
date_default_timezone_set($scenario['tz']);
$now = date('YmdHis', time() + $scenario['clock_offset']);
$inside = false;
$conds = [];
foreach (explode("\n", $htaccess) as $line) {
    if ($line === '# BEGIN vigie') {
        $inside = true;
    } elseif ($line === '# END vigie') {
        break;
    } elseif (!$inside || str_starts_with($line, '#') || $line === 'RewriteEngine On') {
        continue;
    } elseif (preg_match('/^RewriteCond %\{HTTP_USER_AGENT\} "(.*)" \[NC(,OR)?\]$/', $line, $m)) {
        $conds[] = ['ua', stripslashes($m[1])];
    } elseif (preg_match('/^RewriteCond %\{REMOTE_ADDR\} "\^(.*)\$"$/', $line, $m)) {
        $conds[] = ['ip', stripslashes($m[1])];
    } elseif (preg_match('/^RewriteCond %\{TIME\} <(\d{14})$/', $line, $m)) {
        $conds[] = ['time', $m[1]];
    } elseif ($line === 'RewriteRule ^ - [F,L]') {
        $uaMatch = null;
        $all = true;
        foreach ($conds as [$kind, $value]) {
            if ($kind === 'ua') {
                $uaMatch = ($uaMatch ?? false) || stripos($ua, $value) !== false;
            } elseif ($kind === 'ip') {
                $all = $all && $_SERVER['REMOTE_ADDR'] === $value;
            } else {
                $all = $all && strcmp($now, $value) < 0;
            }
        }
        if (($uaMatch ?? true) && $all) {
            http_response_code(403);
            echo 'Forbidden';
            return true;
        }
        $conds = [];
    }
}
if ($sandbox) {
    if (is_file($root . $path)) {
        header('Content-Type: text/plain');
        readfile($root . $path);
        return true;
    }
    http_response_code(404);
    return true;
}
echo 'accueil';
return true;

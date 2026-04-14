<?php
/**
 * SC Alwaysdata — Path & file verification
 * Usage: https://yourdomain.fr/modules/sc_alwaysdata/tools/test_path.php?token=sc_diag_2026
 * Delete after use.
 */
if (($_GET['token'] ?? '') !== 'sc_diag_2026') {
    http_response_code(403);
    exit('Forbidden');
}

header('Content-Type: text/plain; charset=utf-8');

// 1. Verify which LogReaderService.php is actually on the server
$serviceFile = dirname(__DIR__) . '/src/Service/LogReaderService.php';
echo "=== LogReaderService.php on server ===\n";
echo "Path  : {$serviceFile}\n";
echo "mtime : " . date('Y-m-d H:i:s', (int) filemtime($serviceFile)) . "\n";
echo "size  : " . filesize($serviceFile) . " bytes\n\n";

// Show the readTodayLogs method to confirm which version is deployed
$content = file_get_contents($serviceFile);
$start = strpos($content, 'function readTodayLogs');
if ($start !== false) {
    echo "--- readTodayLogs() source ---\n";
    echo substr($content, $start, 500) . "\n...\n\n";
}

// 2. Direct is_readable test — many candidates
echo "=== Candidate paths ===\n";
$home = $_SERVER['HOME'] ?? '';
$candidates = array_unique(array_filter([
    $home . '/admin/logs/',
    '/home/admin/logs/',
    '/home/logs/',
    '/admin/logs/',
    '~/admin/logs/',
    $home . '/logs/',
    rtrim($home, '/') . '/../admin/logs/',
    // Also try the real path of HOME itself
    $home . '/',
]));

foreach ($candidates as $p) {
    $real = @realpath($p);
    echo sprintf(
        "%-45s is_dir=%-3s is_readable=%-3s realpath=%s\n",
        $p,
        is_dir($p) ? 'YES' : 'NO',
        is_readable($p) ? 'YES' : 'NO',
        $real ?: '(none)'
    );
}
echo "\n";

// 3. Check open_basedir
echo "=== PHP context ===\n";
echo "open_basedir : " . (ini_get('open_basedir') ?: '(none)') . "\n";
echo "PHP user     : " . (function_exists('posix_getpwuid') ? (posix_getpwuid(posix_geteuid())['name'] ?? 'unknown') : get_current_user()) . "\n";

<?php
/**
 * SC Alwaysdata — Diagnostic script
 * Tests PHP access to Alwaysdata log files before relying on them in production.
 *
 * Usage: https://yourdomain.fr/modules/sc_alwaysdata/tools/diagnose.php?token=sc_diag_2026
 * Delete this file after use.
 */

declare(strict_types=1);

// Simple token protection — change or remove after use
if (($_GET['token'] ?? '') !== 'sc_diag_2026') {
    http_response_code(403);
    exit('Forbidden. Add ?token=sc_diag_2026 to the URL.');
}

header('Content-Type: text/plain; charset=utf-8');

$ok = '✅';
$fail = '❌';
$warn = '⚠️ ';

echo "SC ALWAYSDATA — PHP DIAGNOSTIC\n";
echo str_repeat('=', 50) . "\n\n";

// ---------------------------------------------------------------
// 1. Environment
// ---------------------------------------------------------------
echo "## 1. Environment\n\n";

$home = $_SERVER['HOME'] ?? null;
if ($home !== null) {
    echo "{$ok} \$_SERVER['HOME'] = {$home}\n";
} else {
    echo "{$fail} \$_SERVER['HOME'] is NOT set\n";
    echo "   → LogReaderService will fail to auto-suggest the logs path\n";
    echo "   → You must configure SC_ALWAYSDATA_LOGS_PATH manually\n";
}

echo "\n   PHP version: " . PHP_VERSION . "\n";
echo "   Current user: " . (function_exists('posix_getpwuid') ? (posix_getpwuid(posix_geteuid())['name'] ?? 'unknown') : get_current_user()) . "\n";
echo "   Working dir: " . getcwd() . "\n";
echo "   set_time_limit() available: " . (function_exists('set_time_limit') ? $ok : $fail) . "\n\n";

// ---------------------------------------------------------------
// 2. Log base path
// ---------------------------------------------------------------
echo "## 2. Log base path\n\n";

$candidatePaths = [];
if ($home !== null) {
    $candidatePaths[] = $home . '/admin/logs/';
}
$candidatePaths[] = '/home/site-a/admin/logs/';

$basePath = null;
foreach ($candidatePaths as $path) {
    echo "   Testing: {$path}\n";
    if (is_dir($path)) {
        echo "   {$ok} Directory exists\n";
        if (is_readable($path)) {
            echo "   {$ok} Readable\n";
            $basePath = $path;
            break;
        } else {
            echo "   {$fail} NOT readable\n";
        }
    } else {
        echo "   {$fail} Does not exist\n";
    }
}

if ($basePath === null) {
    echo "\n{$fail} No accessible log path found. Cannot continue.\n";
    exit;
}

echo "\n{$ok} Using base path: {$basePath}\n\n";

// ---------------------------------------------------------------
// 3. Subdirectories
// ---------------------------------------------------------------
echo "## 3. Subdirectories (apache / http / php / sites)\n\n";

$today = date('Y-m-d');
$dirs = ['apache', 'http', 'php', 'sites'];

foreach ($dirs as $dir) {
    $dirPath = $basePath . $dir . '/';
    echo "--- {$dir}/ ---\n";

    if (!is_dir($dirPath)) {
        echo "   {$fail} Directory does not exist: {$dirPath}\n\n";
        continue;
    }

    if (!is_readable($dirPath)) {
        echo "   {$fail} Directory not readable\n\n";
        continue;
    }

    echo "   {$ok} Accessible\n";

    // List files
    $allFiles = glob($dirPath . '*') ?: [];
    echo "   Files found: " . count($allFiles) . "\n";

    foreach ($allFiles as $file) {
        if (!is_file($file)) {
            continue;
        }
        $basename = basename($file);
        $size = filesize($file);
        $mtime = date('Y-m-d H:i', (int) filemtime($file));
        $isToday = strpos($basename, $today) !== false;
        $sizeLabel = $size >= 1_048_576
            ? round($size / 1_048_576, 1) . ' MB'
            : round($size / 1024, 1) . ' KB';
        $todayMark = $isToday ? " ← TODAY" : '';

        echo "   [{$sizeLabel}] {$basename} (modified {$mtime}){$todayMark}\n";
    }

    // Try to read today's file
    $todayFiles = glob($dirPath . '*' . $today . '*') ?: [];
    if (empty($todayFiles)) {
        echo "   {$warn} No file matching today ({$today})\n";

        // Try most recent file as fallback
        if (!empty($allFiles)) {
            usort($allFiles, fn ($a, $b) => (int) filemtime($b) - (int) filemtime($a));
            $fallback = $allFiles[0];
            echo "   → Fallback: most recent file = " . basename($fallback) . "\n";
            testFileRead($fallback, $ok, $fail, $warn);
        }
    } else {
        $file = $todayFiles[0];
        echo "   {$ok} Today's file: " . basename($file) . "\n";
        testFileRead($file, $ok, $fail, $warn);
    }

    echo "\n";
}

// ---------------------------------------------------------------
// 4. .htaccess
// ---------------------------------------------------------------
echo "## 4. .htaccess access\n\n";

$htaccessPath = dirname(__DIR__, 3) . '/.htaccess';
echo "   Path tested: {$htaccessPath}\n";

if (!file_exists($htaccessPath)) {
    echo "   {$fail} File does not exist\n";
} elseif (!is_readable($htaccessPath)) {
    echo "   {$fail} Not readable\n";
} else {
    echo "   {$ok} Readable\n";
    $content = file_get_contents($htaccessPath);
    echo "   Size: " . strlen((string) $content) . " bytes\n";

    if ($content !== false) {
        preg_match_all('/Require not ip\s+(\S+)/', $content, $m);
        echo "   'Require not ip' entries: " . count($m[1]) . "\n";
        preg_match_all('/RewriteCond %\{HTTP_USER_AGENT\}/', $content, $m2);
        echo "   UA RewriteCond entries: " . count($m2[0]) . "\n";
    }

    if (is_writable($htaccessPath)) {
        echo "   {$ok} Writable (blocking will work)\n";
    } else {
        echo "   {$fail} NOT writable — blocking will fail\n";
    }
}

echo "\n## Done.\n";
echo "Delete this file after use: modules/sc_alwaysdata/tools/diagnose.php\n";

// ---------------------------------------------------------------
// Helper
// ---------------------------------------------------------------
function testFileRead(string $filePath, string $ok, string $fail, string $warn): void
{
    $size = filesize($filePath);

    if ($size > 5_242_880) {
        echo "   {$warn} File > 5 MB ({$size} bytes) — will be skipped by LogReaderService\n";
        return;
    }

    $fh = @fopen($filePath, 'rb');
    if ($fh === false) {
        echo "   {$fail} fopen() failed — cannot read file\n";
        return;
    }

    fseek($fh, 0, SEEK_END);
    $fileSize = ftell($fh);
    $readPos = max(0, $fileSize - 8192);
    fseek($fh, $readPos);
    $chunk = fread($fh, 8192);
    fclose($fh);

    if ($chunk === false) {
        echo "   {$fail} fread() failed\n";
        return;
    }

    $lines = array_filter(explode("\n", $chunk), fn ($l) => $l !== '');
    $lineCount = count($lines);
    $firstLine = $lines[array_key_first($lines)] ?? '';

    echo "   {$ok} fopen/fseek/fread OK — last chunk has {$lineCount} lines\n";
    echo "   Sample: " . mb_substr($firstLine, 0, 120) . "\n";
}

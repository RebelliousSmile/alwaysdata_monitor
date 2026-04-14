<?php

declare(strict_types=1);

namespace ScAlwaysdata\Tests\Service;

use PHPUnit\Framework\TestCase;
use ScAlwaysdata\Service\HtaccessService;

/**
 * HtaccessService uses \Configuration::get() which is a PrestaShop class.
 * The stub is defined in tests/bootstrap.php.
 */
class HtaccessServiceTest extends TestCase
{
    private string $tmpFile;

    protected function setUp(): void
    {
        $this->tmpFile = tempnam(sys_get_temp_dir(), 'htaccess_test_');
        \Configuration::$testValues['SC_ALWAYSDATA_HTACCESS_PATH'] = $this->tmpFile;
    }

    protected function tearDown(): void
    {
        // Clean up temp files created during tests
        foreach (glob($this->tmpFile . '*') as $f) {
            @unlink($f);
        }
    }

    private function service(): HtaccessService
    {
        return new HtaccessService();
    }

    private function write(string $content): void
    {
        file_put_contents($this->tmpFile, $content);
    }

    // -----------------------------------------------------------------
    // readBlockedIps
    // -----------------------------------------------------------------

    public function testReadBlockedIpsApache24Format(): void
    {
        $this->write("Require all granted\nRequire not ip 1.2.3.4\nRequire not ip 5.6.7.8\n");

        $ips = $this->service()->readBlockedIps();

        $this->assertContains('1.2.3.4', $ips);
        $this->assertContains('5.6.7.8', $ips);
    }

    public function testReadBlockedIpsApache22Format(): void
    {
        $this->write("deny from 10.0.0.1\ndeny from 192.168.1.0/24\n");

        $ips = $this->service()->readBlockedIps();

        $this->assertContains('10.0.0.1', $ips);
    }

    public function testReadBlockedIpsDeduplicates(): void
    {
        $this->write("Require not ip 1.2.3.4\nRequire not ip 1.2.3.4\n");

        $ips = $this->service()->readBlockedIps();

        $this->assertCount(1, $ips);
    }

    public function testReadBlockedIpsEmptyFile(): void
    {
        $this->write('');

        $ips = $this->service()->readBlockedIps();

        $this->assertSame([], $ips);
    }

    // -----------------------------------------------------------------
    // readBlockedUAs
    // -----------------------------------------------------------------

    public function testReadBlockedUAsWithQuotes(): void
    {
        $this->write("RewriteCond %{HTTP_USER_AGENT} \"MJ12bot\" [NC]\nRewriteRule .* - [F,L]\n");

        $uas = $this->service()->readBlockedUAs();

        $this->assertContains('MJ12bot', $uas);
    }

    public function testReadBlockedUAsWithoutQuotes(): void
    {
        $this->write("RewriteCond %{HTTP_USER_AGENT} MJ12bot [NC]\nRewriteRule .* - [F,L]\n");

        $uas = $this->service()->readBlockedUAs();

        $this->assertContains('MJ12bot', $uas);
    }

    public function testReadBlockedUAsSetEnvIfNoCaseWithQuotes(): void
    {
        $this->write("SetEnvIfNoCase User-Agent \"AhrefsBot\" bad_bot\n");

        $uas = $this->service()->readBlockedUAs();

        $this->assertContains('AhrefsBot', $uas);
    }

    public function testReadBlockedUAsSetEnvIfNoCaseWithoutQuotes(): void
    {
        $this->write("SetEnvIfNoCase User-Agent AhrefsBot bad_bot\n");

        $uas = $this->service()->readBlockedUAs();

        $this->assertContains('AhrefsBot', $uas);
    }

    public function testReadBlockedUAsIgnoresNegativePattern(): void
    {
        // !(Mozilla...) is a browser exclusion, NOT a blocked bot — must not appear
        $this->write("RewriteCond %{HTTP_USER_AGENT} !(Mozilla/5.0.*Chrome.*Safari|Mozilla/5.0.*Firefox) [NC]\n");

        $uas = $this->service()->readBlockedUAs();

        $this->assertEmpty($uas);
    }

    public function testReadBlockedUAsIgnoresAnchoredRegex(): void
    {
        // A pattern starting with ^ is not a simple bot name
        $this->write("RewriteCond %{HTTP_USER_AGENT} ^BadBot.* [NC]\n");

        $uas = $this->service()->readBlockedUAs();

        $this->assertEmpty($uas);
    }

    public function testReadBlockedUAsDeduplicates(): void
    {
        $this->write(
            "RewriteCond %{HTTP_USER_AGENT} \"MJ12bot\" [NC]\n"
            . "RewriteCond %{HTTP_USER_AGENT} MJ12bot [NC]\n"
        );

        $uas = $this->service()->readBlockedUAs();

        $this->assertCount(1, $uas);
    }

    // -----------------------------------------------------------------
    // blockIp
    // -----------------------------------------------------------------

    public function testBlockIpAppendsRequireNotIp(): void
    {
        $this->write("Options -Indexes\n");

        $this->service()->blockIp('1.2.3.4');

        $content = file_get_contents($this->tmpFile);
        $this->assertStringContainsString('Require not ip 1.2.3.4', $content);
    }

    public function testBlockIpCreatesBackup(): void
    {
        $this->write("Options -Indexes\n");

        $this->service()->blockIp('1.2.3.4');

        $backups = glob($this->tmpFile . '.*.bak');
        $this->assertNotEmpty($backups, 'A dated backup must be created');
    }

    public function testBlockIpRejectsInvalidIp(): void
    {
        $this->write('');

        $this->expectException(\InvalidArgumentException::class);
        $this->service()->blockIp('not-an-ip');
    }

    public function testBlockIpIsDetectedByReadBlockedIps(): void
    {
        $this->write('');

        $this->service()->blockIp('9.9.9.9');

        $ips = $this->service()->readBlockedIps();
        $this->assertContains('9.9.9.9', $ips);
    }

    // -----------------------------------------------------------------
    // blockUserAgent
    // -----------------------------------------------------------------

    public function testBlockUserAgentAppendsRewriteCond(): void
    {
        $this->write("RewriteEngine On\n");

        $this->service()->blockUserAgent('MJ12bot');

        $content = file_get_contents($this->tmpFile);
        $this->assertStringContainsString('HTTP_USER_AGENT', $content);
        $this->assertStringContainsString('MJ12bot', $content);
    }

    public function testBlockUserAgentInsertsInsideIfModuleRewrite(): void
    {
        $this->write("<IfModule mod_rewrite.c>\nRewriteEngine On\n</IfModule>\n");

        $this->service()->blockUserAgent('SemrushBot');

        $content = file_get_contents($this->tmpFile);
        // Rule must appear BEFORE </IfModule>
        $rulePos = strpos($content, 'SemrushBot');
        $closePos = strpos($content, '</IfModule>');
        $this->assertNotFalse($rulePos);
        $this->assertLessThan($closePos, $rulePos, 'UA rule must be inside <IfModule mod_rewrite.c>');
    }

    public function testBlockUserAgentWrapsInIfModuleWhenNoneExists(): void
    {
        $this->write("Options -Indexes\n");

        $this->service()->blockUserAgent('AhrefsBot');

        $content = file_get_contents($this->tmpFile);
        $this->assertStringContainsString('<IfModule mod_rewrite.c>', $content);
        $this->assertStringContainsString('AhrefsBot', $content);
    }

    public function testBlockUserAgentCreatesBackup(): void
    {
        $this->write("RewriteEngine On\n");

        $this->service()->blockUserAgent('MJ12bot');

        $backups = glob($this->tmpFile . '.*.bak');
        $this->assertNotEmpty($backups);
    }

    public function testBlockUserAgentIsDetectedByReadBlockedUAs(): void
    {
        $this->write("RewriteEngine On\n");

        $this->service()->blockUserAgent('SemrushBot');

        $uas = $this->service()->readBlockedUAs();
        $this->assertContains('SemrushBot', $uas);
    }

    public function testBlockUserAgentStripsQuotes(): void
    {
        $this->write("RewriteEngine On\n");

        // UA containing an embedded quote: MJ12"bot → sanitized to MJ12bot
        $this->service()->blockUserAgent('MJ12"bot');

        $content = file_get_contents($this->tmpFile);
        // The embedded quote must be gone (the surrounding htaccess quotes are fine)
        $this->assertStringNotContainsString('MJ12"bot', $content);
        $this->assertStringContainsString('MJ12bot', $content);
    }

    // -----------------------------------------------------------------
    // unblockIp
    // -----------------------------------------------------------------

    public function testUnblockIpRemovesModuleBlock(): void
    {
        $this->write("Options -Indexes\n");
        $this->service()->blockIp('1.2.3.4');
        $this->assertContains('1.2.3.4', $this->service()->readBlockedIps());

        $this->service()->unblockIp('1.2.3.4');

        $this->assertNotContains('1.2.3.4', $this->service()->readBlockedIps());
    }

    public function testUnblockIpRemovesLooseRequireNotIp(): void
    {
        $this->write("\nRequire not ip 5.5.5.5\n");

        $this->service()->unblockIp('5.5.5.5');

        $content = file_get_contents($this->tmpFile);
        $this->assertStringNotContainsString('5.5.5.5', $content);
    }

    public function testUnblockIpRejectsInvalidIp(): void
    {
        $this->write('');

        $this->expectException(\InvalidArgumentException::class);
        $this->service()->unblockIp('not-an-ip');
    }

    public function testUnblockIpCreatesBackup(): void
    {
        $this->write("\nRequire not ip 9.9.9.9\n");

        $this->service()->unblockIp('9.9.9.9');

        $backups = glob($this->tmpFile . '.*.bak');
        $this->assertNotEmpty($backups);
    }

    // -----------------------------------------------------------------
    // unblockUserAgent
    // -----------------------------------------------------------------

    public function testUnblockUserAgentRemovesModuleBlock(): void
    {
        $this->write("RewriteEngine On\n");
        $this->service()->blockUserAgent('MJ12bot');
        $this->assertContains('MJ12bot', $this->service()->readBlockedUAs());

        $this->service()->unblockUserAgent('MJ12bot');

        $this->assertNotContains('MJ12bot', $this->service()->readBlockedUAs());
    }

    public function testUnblockUserAgentRemovesUnquotedPattern(): void
    {
        $this->write("RewriteEngine On\nRewriteCond %{HTTP_USER_AGENT} AhrefsBot [NC]\nRewriteRule .* - [F,L]\n");

        $this->service()->unblockUserAgent('AhrefsBot');

        $uas = $this->service()->readBlockedUAs();
        $this->assertNotContains('AhrefsBot', $uas);
    }

    public function testUnblockUserAgentCreatesBackup(): void
    {
        $this->write("RewriteEngine On\n");
        $this->service()->blockUserAgent('SemrushBot');

        // Remove backups from blockUserAgent to isolate unblock backup
        foreach (glob($this->tmpFile . '.*.bak') as $f) {
            unlink($f);
        }

        $this->service()->unblockUserAgent('SemrushBot');

        $backups = glob($this->tmpFile . '.*.bak');
        $this->assertNotEmpty($backups);
    }

    // -----------------------------------------------------------------
    // readSnippet
    // -----------------------------------------------------------------

    public function testReadSnippetReturnsContent(): void
    {
        $this->write("Options -Indexes\nRewriteEngine On\n");

        $snippet = $this->service()->readSnippet(100);

        $this->assertStringContainsString('RewriteEngine', $snippet);
    }

    public function testReadSnippetRespectMaxLength(): void
    {
        $this->write(str_repeat('x', 5000));

        $snippet = $this->service()->readSnippet(100);

        $this->assertLessThanOrEqual(100, strlen($snippet));
    }
}

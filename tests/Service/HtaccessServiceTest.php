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
        $this->write("Require all granted\nRequire not ip 203.0.113.14\nRequire not ip 203.0.113.15\n");

        $ips = $this->service()->readBlockedIps();

        $this->assertContains('203.0.113.14', $ips);
        $this->assertContains('203.0.113.15', $ips);
    }

    public function testReadBlockedIpsApache22Format(): void
    {
        $this->write("deny from 10.0.0.1\ndeny from 192.168.1.0/24\n");

        $ips = $this->service()->readBlockedIps();

        $this->assertContains('10.0.0.1', $ips);
    }

    public function testReadBlockedIpsDeduplicates(): void
    {
        $this->write("Require not ip 203.0.113.14\nRequire not ip 203.0.113.14\n");

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

        $this->service()->blockIp('203.0.113.14');

        $content = file_get_contents($this->tmpFile);
        $this->assertStringContainsString('Require not ip 203.0.113.14', $content);
    }

    public function testBlockIpCreatesBackup(): void
    {
        $this->write("Options -Indexes\n");

        $this->service()->blockIp('203.0.113.14');

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

        $this->service()->blockIp('203.0.113.9');

        $ips = $this->service()->readBlockedIps();
        $this->assertContains('203.0.113.9', $ips);
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
        $this->service()->blockIp('203.0.113.14');
        $this->assertContains('203.0.113.14', $this->service()->readBlockedIps());

        $this->service()->unblockIp('203.0.113.14');

        $this->assertNotContains('203.0.113.14', $this->service()->readBlockedIps());
    }

    public function testUnblockIpRemovesLooseRequireNotIp(): void
    {
        $this->write("\nRequire not ip 203.0.113.5\n");

        $this->service()->unblockIp('203.0.113.5');

        $content = file_get_contents($this->tmpFile);
        $this->assertStringNotContainsString('203.0.113.5', $content);
    }

    public function testUnblockIpRejectsInvalidIp(): void
    {
        $this->write('');

        $this->expectException(\InvalidArgumentException::class);
        $this->service()->unblockIp('not-an-ip');
    }

    public function testUnblockIpCreatesBackup(): void
    {
        $this->write("\nRequire not ip 203.0.113.9\n");

        $this->service()->unblockIp('203.0.113.9');

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
    // Protection block
    // -----------------------------------------------------------------

    private const DOMAINS = ['www.site-a.example', 'www.site-a.test'];

    public function testApplyProtectionPrependsBlockBeforeExistingRules(): void
    {
        $this->write("# ~~start~~ PrestaShop\nRewriteEngine on\n");

        $this->service()->applyProtection(self::DOMAINS, true, 3);

        $content = file_get_contents($this->tmpFile);
        $this->assertStringStartsWith('# BEGIN sc_alwaysdata protection', $content);
        $this->assertLessThan(strpos($content, '~~start~~'), strpos($content, '# END sc_alwaysdata protection'));
    }

    public function testApplyProtectionWhitelistsEveryShopDomainAsReferer(): void
    {
        $this->write('');

        $this->service()->applyProtection(self::DOMAINS, true, 0);

        $content = file_get_contents($this->tmpFile);
        $this->assertStringContainsString(
            'RewriteCond %{HTTP_REFERER} !^https?://(www\.site-a\.example|www\.site-a\.test)(:\d+)?/ [NC]',
            $content
        );
        $this->assertStringNotContainsString('(/|%2F)', $content);
    }

    public function testFacetDepthPatternBlocksOneGroupAboveLimit(): void
    {
        $block = $this->service()->buildProtectionBlock(self::DOMAINS, false, 3);

        preg_match('/^RewriteCond %\{QUERY_STRING\} (\S+) \[NC\]$/m', $block, $m);
        $regex = '#' . $m[1] . '#i';

        $this->assertSame(0, preg_match($regex, 'q=Taille-S/Couleur-Rouge/Marque-X'));
        $this->assertSame(1, preg_match($regex, 'q=Taille-S/Couleur-Rouge/Marque-X/Prix-10-20'));
        $this->assertSame(1, preg_match($regex, 'order=a&q=Taille-S%2FCouleur-Rouge%2FMarque-X%2FPrix-1'));
        $this->assertSame(0, preg_match($regex, 'foo=a/b/c/d&q=Taille-S'));
    }

    public function testApplyProtectionReplacesExistingBlockInPlace(): void
    {
        $this->write("RewriteEngine on\n");
        $this->service()->applyProtection(self::DOMAINS, true, 3);

        $this->service()->applyProtection(self::DOMAINS, false, 5);

        $content = file_get_contents($this->tmpFile);
        $this->assertSame(1, substr_count($content, '# BEGIN sc_alwaysdata protection'));
        $this->assertStringNotContainsString('HTTP_REFERER', $content);
        $this->assertStringContainsString("RewriteEngine on\n", $content);
    }

    public function testReadProtectionRoundTrip(): void
    {
        $this->write('');
        $this->assertFalse($this->service()->readProtection()['installed']);

        $this->service()->applyProtection(self::DOMAINS, true, 4);

        $this->assertSame(
            ['installed' => true, 'facet_referer' => true, 'facet_max_filters' => 4],
            $this->service()->readProtection()
        );
    }

    public function testApplyProtectionWithEverythingOffRemovesBlock(): void
    {
        $this->write("RewriteEngine on\n");
        $this->service()->applyProtection(self::DOMAINS, true, 3);

        $this->service()->applyProtection(self::DOMAINS, false, 0);

        $this->assertSame("RewriteEngine on\n", file_get_contents($this->tmpFile));
    }

    public function testApplyProtectionRefusesEmptyDomainListForReferer(): void
    {
        $this->write('');

        $this->expectException(\InvalidArgumentException::class);
        $this->service()->applyProtection([], true, 0);
    }

    public function testApplyProtectionRejectsInjectedDomain(): void
    {
        $this->write('');

        $this->expectException(\InvalidArgumentException::class);
        $this->service()->applyProtection(["evil.com)|(.*\nRewriteRule"], true, 0);
    }

    public function testBlockUserAgentSkipsProtectionBlock(): void
    {
        $this->write("<IfModule mod_rewrite.c>\nRewriteEngine on\n</IfModule>\n");
        $this->service()->applyProtection(self::DOMAINS, true, 3);

        $this->service()->blockUserAgent('PetalBot');
        $this->service()->applyProtection(self::DOMAINS, true, 2);

        $this->assertContains('PetalBot', $this->service()->readBlockedUAs());
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

    // -----------------------------------------------------------------
    // Undo: backups, restore, unblock
    // -----------------------------------------------------------------

    public function testBackupsWrittenInSameSecondDoNotOverwriteEachOther(): void
    {
        $this->write("RewriteEngine On\n");

        $this->service()->blockUserAgent('AhrefsBot');
        $this->service()->blockUserAgent('DotBot');
        $this->service()->blockUserAgent('PetalBot');

        $this->assertCount(3, $this->service()->listBackups());
    }

    public function testListBackupsNewestFirstWithRestoreDiff(): void
    {
        $this->write("RewriteEngine On\n");
        $this->service()->blockUserAgent('AhrefsBot');
        $this->service()->blockUserAgent('DotBot');

        $backups = $this->service()->listBackups();

        // Newest backup = state before DotBot: restoring it removes only the DotBot rule
        $this->assertStringContainsString('DotBot', implode("\n", $backups[0]['removed']));
        $this->assertStringNotContainsString('AhrefsBot', implode("\n", $backups[0]['removed']));
        $this->assertSame([], $backups[0]['restored']);
        $this->assertMatchesRegularExpression('/^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$/', $backups[0]['date']);
    }

    public function testRestoreBackupUndoesLastActionAndIsItselfUndoable(): void
    {
        $this->write("RewriteEngine On\n");
        $this->service()->blockUserAgent('AhrefsBot');
        $blocked = file_get_contents($this->tmpFile);

        $this->service()->restoreBackup($this->service()->listBackups()[0]['name']);
        $this->assertSame("RewriteEngine On\n", file_get_contents($this->tmpFile));

        // The restore backed up the blocked state: restoring it redoes the block
        $this->service()->restoreBackup($this->service()->listBackups()[0]['name']);
        $this->assertSame($blocked, file_get_contents($this->tmpFile));
    }

    public function testRestoreBackupRejectsForeignFile(): void
    {
        $this->write("RewriteEngine On\n");

        $this->expectException(\InvalidArgumentException::class);
        $this->service()->restoreBackup('../../etc/passwd');
    }

    public function testUnblockUnknownUserAgentThrowsWithoutWriting(): void
    {
        $this->write("RewriteEngine On\n");

        try {
            $this->service()->unblockUserAgent('NotBlockedBot');
            $this->fail('Expected RuntimeException');
        } catch (\RuntimeException $e) {
            $this->assertSame([], glob($this->tmpFile . '.*.bak'));
        }
    }

    public function testBlockUserAgentGoesBeforePrestashopSection(): void
    {
        $this->write("# ~~start~~\n<IfModule mod_rewrite.c>\nRewriteEngine on\n"
            . "RewriteRule ^.*$ %{ENV:REWRITEBASE}index.php [NC,L]\n</IfModule>\n# ~~end~~\n");

        $this->service()->blockUserAgent('MJ12bot');

        $content = file_get_contents($this->tmpFile);
        $this->assertLessThan(strpos($content, '# ~~start~~'), strpos($content, 'MJ12bot'));
        $this->assertSame([], $this->service()->diagnose());
    }

    public function testRepairFixesDeadRuleAndCanBeUndone(): void
    {
        $original = "# ~~start~~\n<IfModule mod_rewrite.c>\nRewriteEngine on\n"
            . "RewriteRule ^.*$ %{ENV:REWRITEBASE}index.php [NC,L]\n</IfModule>\n# ~~end~~\n"
            . "RewriteCond %{HTTP_USER_AGENT} \"MJ12bot\" [NC]\nRewriteRule .* - [F,L]\n";
        $this->write($original);
        $this->assertSame('dead_ua_rules', $this->service()->diagnose()[0]['code']);

        $this->service()->repair('dead_ua_rules');
        $this->assertSame([], $this->service()->diagnose());

        $this->service()->restoreBackup($this->service()->listBackups()[0]['name']);
        $this->assertSame($original, file_get_contents($this->tmpFile));
    }

    public function testPurgeKeepsTheMostRecentBackups(): void
    {
        $this->write("RewriteEngine On\n");
        foreach (['AhrefsBot', 'DotBot', 'PetalBot', 'SemrushBot'] as $ua) {
            $this->service()->blockUserAgent($ua);
        }
        $newest = array_column($this->service()->listBackups(), 'name');
        $current = file_get_contents($this->tmpFile);

        $this->assertSame(2, $this->service()->purgeBackups(2));

        $this->assertSame(2, $this->service()->countBackups());
        $this->assertSame(array_slice($newest, 0, 2), array_column($this->service()->listBackups(), 'name'));
        $this->assertSame($current, file_get_contents($this->tmpFile), 'the live .htaccess is never touched');
    }

    public function testPurgeLeavesUnrelatedFilesAlone(): void
    {
        $this->write("RewriteEngine On\n");
        $this->service()->blockUserAgent('AhrefsBot');
        $foreign = $this->tmpFile . '.manual-copy.bak';
        file_put_contents($foreign, 'keep me');

        $this->service()->purgeBackups(1);

        $this->assertFileExists($foreign);
        $this->assertSame(0, $this->service()->purgeBackups(1));
    }

    public function testPurgeRefusesToDeleteEveryBackup(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->service()->purgeBackups(0);
    }

    public function testBlockUserAgentsWritesAllRulesOnceAndSkipsExisting(): void
    {
        $this->write('RewriteEngine on
');
        $this->service()->blockUserAgent('GPTBot');
        $backupsBefore = count(glob($this->tmpFile . '.*.bak') ?: []);

        $this->service()->blockUserAgents(['gptbot', 'ClaudeBot', 'Bytespider', '']);

        $uas = $this->service()->readBlockedUAs();
        $this->assertSame(['GPTBot', 'ClaudeBot', 'Bytespider'], $uas);
        $this->assertLessThanOrEqual($backupsBefore + 1, count(glob($this->tmpFile . '.*.bak') ?: []));
    }

    public function testBlockUserAgentsWithNothingNewLeavesFileUntouched(): void
    {
        $this->write('RewriteEngine on
');
        $this->service()->blockUserAgent('GPTBot');
        $before = file_get_contents($this->tmpFile);

        $this->service()->blockUserAgents(['GPTBot', '  ']);

        $this->assertSame($before, file_get_contents($this->tmpFile));
    }
}

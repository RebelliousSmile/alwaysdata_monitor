<?php

declare(strict_types=1);

namespace ScAlwaysdata\Tests\Service;

use PHPUnit\Framework\TestCase;
use ScAlwaysdata\Service\HtaccessDoctor;

class HtaccessDoctorTest extends TestCase
{
    private const PROTECTION = "# BEGIN sc_alwaysdata protection\n"
        . "# Managed by sc_alwaysdata (Back-office > Scriptami > Alwaysdata). Manual edits are overwritten.\n"
        . "# sc_alwaysdata options: {\"facet_referer\":true,\"facet_max_filters\":3}\n"
        . "<IfModule mod_rewrite.c>\n"
        . "RewriteEngine on\n"
        . "RewriteCond %{QUERY_STRING} (^|&)q= [NC]\n"
        . "RewriteCond %{HTTP_REFERER} !^https?://(www\\.kelenaya\\.fr)(:\\d+)?/ [NC]\n"
        . "RewriteRule .* - [F,L]\n"
        . "</IfModule>\n"
        . "# END sc_alwaysdata protection\n";

    private const MANUAL = "# Block aggressive crawlers causing server overload\n"
        . "<IfModule mod_rewrite.c>\n"
        . "RewriteEngine On\n"
        . "RewriteCond %{HTTP_USER_AGENT} SERankingBacklinksBot [NC]\n"
        . "RewriteRule .* - [F,L]\n"
        . "RewriteCond %{HTTP_USER_AGENT} Bytespider [NC]\n"
        . "RewriteRule .* - [F,L]\n"
        . "# Block MJ12bot (Majestic SEO)\n"
        . "# Block faceted navigation crawler trap (?q= parameter) for non-browsers\n"
        . "RewriteCond %{HTTP_USER_AGENT} !(Mozilla/5.0.*Chrome.*Safari|Mozilla/5.0.*Firefox|Mozilla/5.0.*Safari) [NC]\n"
        . "RewriteCond %{QUERY_STRING} (^|&)q= [NC]\n"
        . "RewriteRule .* - [F,L]\n"
        . "RewriteCond %{QUERY_STRING} resultsPerPage=([5-9][0-9]{3,}|[0-9]{5,}) [NC]\n"
        . "RewriteRule .* - [F,L]\n"
        . "\n"
        . "# sc_alwaysdata block UA: facebookexternalhit\n"
        . "RewriteCond %{HTTP_USER_AGENT} \"facebookexternalhit\" [NC]\n"
        . "RewriteRule .* - [F,L]\n"
        . "</IfModule>\n";

    private const PRESTASHOP = "# ~~start~~ Do not remove this comment, Prestashop will keep automatically the code outside this comment when .htaccess will be generated again\n"
        . "<IfModule mod_rewrite.c>\n"
        . "RewriteEngine on\n"
        . "RewriteCond %{HTTP_HOST} ^www.kelenaya.fr$\n"
        . "RewriteRule . - [E=REWRITEBASE:/]\n"
        . "RewriteCond %{REQUEST_FILENAME} -s [OR]\n"
        . "RewriteCond %{REQUEST_FILENAME} -d\n"
        . "RewriteRule ^.*$ - [NC,L]\n"
        . "RewriteCond %{HTTP_HOST} ^www.kelenaya.fr$\n"
        . "RewriteRule ^.*$ %{ENV:REWRITEBASE}index.php [NC,L]\n"
        . "</IfModule>\n"
        . "# ~~end~~ Do not remove this comment, Prestashop will keep automatically the code outside this comment when .htaccess will be generated again\n";

    private const DEAD_MJ12 = "\n# sc_alwaysdata block UA: MJ12bot\n"
        . "RewriteCond %{HTTP_USER_AGENT} \"MJ12bot\" [NC]\n"
        . "RewriteRule .* - [F,L]\n";

    private const REFERER_ON = ['facet_referer' => true];

    private function doctor(): HtaccessDoctor
    {
        return new HtaccessDoctor();
    }

    private function prod(): string
    {
        return self::PROTECTION . "\n" . self::MANUAL . "\n" . self::PRESTASHOP . self::DEAD_MJ12;
    }

    /**
     * @return string[]
     */
    private function codes(array $findings): array
    {
        return array_column($findings, 'code');
    }

    private function find(array $findings, string $code): ?array
    {
        foreach ($findings as $f) {
            if ($f['code'] === $code) {
                return $f;
            }
        }

        return null;
    }

    public function testCleanFileHasNoFinding(): void
    {
        $this->assertSame([], $this->doctor()->analyse(self::PROTECTION . "\n" . self::PRESTASHOP, self::REFERER_ON));
    }

    public function testProdFileFindings(): void
    {
        $findings = $this->doctor()->analyse($this->prod(), self::REFERER_ON);

        $this->assertSame(
            [HtaccessDoctor::DEAD_UA_RULES, HtaccessDoctor::SOCIAL_PREVIEW_BLOCKED, HtaccessDoctor::BROWSER_ONLY_RULE],
            $this->codes($findings)
        );
        $this->assertSame(['MJ12bot'], $this->find($findings, HtaccessDoctor::DEAD_UA_RULES)['items']);
        $this->assertContains('Instagram iOS', $this->find($findings, HtaccessDoctor::BROWSER_ONLY_RULE)['items']);
        $this->assertNotContains('Chrome Windows', $this->find($findings, HtaccessDoctor::BROWSER_ONLY_RULE)['items']);
    }

    public function testRepairMovesDeadRuleBeforePrestashop(): void
    {
        $repaired = $this->doctor()->repair($this->prod(), HtaccessDoctor::DEAD_UA_RULES, self::REFERER_ON);

        $mj12 = strpos($repaired, '"MJ12bot"');
        $this->assertNotFalse($mj12);
        $this->assertLessThan(strpos($repaired, '# ~~start~~'), $mj12);
        $this->assertGreaterThan(strpos($repaired, '# END sc_alwaysdata protection'), $mj12);
        $this->assertSame(1, substr_count($repaired, 'MJ12bot"'));
        $this->assertStringEndsWith("# ~~end~~ Do not remove this comment, Prestashop will keep automatically the code outside this comment when .htaccess will be generated again\n", $repaired);
        $this->assertNotContains(HtaccessDoctor::DEAD_UA_RULES, $this->codes($this->doctor()->analyse($repaired, self::REFERER_ON)));
    }

    public function testRepairDropsEmptyWrapperOfOldFallback(): void
    {
        $content = self::PRESTASHOP . "\n<IfModule mod_rewrite.c>\nRewriteEngine On" . self::DEAD_MJ12 . "</IfModule>\n";

        $repaired = $this->doctor()->repair($content, HtaccessDoctor::DEAD_UA_RULES);

        $tail = substr($repaired, strpos($repaired, '# ~~end~~'));
        $this->assertStringNotContainsString('<IfModule', $tail);
        $this->assertStringStartsWith(HtaccessDoctor::BLOCKS_BEGIN, $repaired);
    }

    public function testDeadNonUaRuleIsReportedButNotFixable(): void
    {
        $content = self::PRESTASHOP . "RewriteCond %{QUERY_STRING} foo= [NC]\nRewriteRule .* - [F,L]\n";

        $finding = $this->find($this->doctor()->analyse($content), HtaccessDoctor::DEAD_OTHER_RULES);

        $this->assertNotNull($finding);
        $this->assertFalse($finding['fixable']);
    }

    public function testRepairRemovesBrowserOnlyRuleAndKeepsNeighbours(): void
    {
        $repaired = $this->doctor()->repair($this->prod(), HtaccessDoctor::BROWSER_ONLY_RULE, self::REFERER_ON);

        $this->assertStringNotContainsString('!(Mozilla', $repaired);
        $this->assertStringNotContainsString('for non-browsers', $repaired);
        $this->assertStringContainsString('# Block MJ12bot (Majestic SEO)', $repaired);
        $this->assertStringContainsString('resultsPerPage=', $repaired);
        $this->assertStringContainsString('Bytespider', $repaired);
    }

    public function testBrowserOnlyRuleNotFixableWithoutRefererProtection(): void
    {
        $finding = $this->find($this->doctor()->analyse(self::MANUAL . self::PRESTASHOP), HtaccessDoctor::BROWSER_ONLY_RULE);

        $this->assertFalse($finding['fixable']);
        $this->expectException(\InvalidArgumentException::class);
        $this->doctor()->repair(self::MANUAL . self::PRESTASHOP, HtaccessDoctor::BROWSER_ONLY_RULE);
    }

    public function testRepairUnblocksSocialPreview(): void
    {
        $repaired = $this->doctor()->repair($this->prod(), HtaccessDoctor::SOCIAL_PREVIEW_BLOCKED, self::REFERER_ON);

        $this->assertStringNotContainsString('facebookexternalhit', $repaired);
        $this->assertStringContainsString('Bytespider', $repaired);
    }

    public function testSearchEngineCaughtByBroadPattern(): void
    {
        $content = "<IfModule mod_rewrite.c>\nRewriteEngine on\nRewriteCond %{HTTP_USER_AGENT} \"bot\" [NC]\nRewriteRule .* - [F,L]\n</IfModule>\n" . self::PRESTASHOP;

        $findings = $this->doctor()->analyse($content);

        $this->assertSame(HtaccessDoctor::SEARCH_ENGINE_BLOCKED, $findings[0]['code']);
        $this->assertSame(HtaccessDoctor::SEVERITY_CRITICAL, $findings[0]['severity']);
        $repaired = $this->doctor()->repair($content, HtaccessDoctor::SEARCH_ENGINE_BLOCKED);
        $this->assertStringNotContainsString('"bot"', $repaired);
    }

    public function testBrowserBlockedByMozillaPattern(): void
    {
        $content = "SetEnvIfNoCase User-Agent \"Mozilla\" bad_bot\n";

        $this->assertContains(HtaccessDoctor::BROWSER_BLOCKED, $this->codes($this->doctor()->analyse($content)));
    }

    public function testOrChainIsReportedButRepairRefuses(): void
    {
        $content = "RewriteCond %{HTTP_USER_AGENT} Googlebot [NC,OR]\nRewriteCond %{HTTP_USER_AGENT} AhrefsBot [NC]\nRewriteRule .* - [F,L]\n";

        $this->assertContains(HtaccessDoctor::SEARCH_ENGINE_BLOCKED, $this->codes($this->doctor()->analyse($content)));
        $this->expectException(\RuntimeException::class);
        $this->doctor()->repair($content, HtaccessDoctor::SEARCH_ENGINE_BLOCKED);
    }

    public function testStructureProblems(): void
    {
        $content = "<IfModule mod_rewrite.c>\nRewriteCond %{HTTP_HOST} ^x$\nOptions -Indexes\n";

        $codes = $this->codes($this->doctor()->analyse($content));

        $this->assertContains(HtaccessDoctor::IFMODULE_UNBALANCED, $codes);
        $this->assertContains(HtaccessDoctor::DANGLING_REWRITECOND, $codes);
    }

    public function testDuplicateUaIsInfo(): void
    {
        $rule = "RewriteCond %{HTTP_USER_AGENT} Bytespider [NC]\nRewriteRule .* - [F,L]\n";

        $finding = $this->find($this->doctor()->analyse($rule . $rule), HtaccessDoctor::DUPLICATE_UA);

        $this->assertSame(HtaccessDoctor::SEVERITY_INFO, $finding['severity']);
    }

    public function testProtectionAfterPrestashopIsMovedToTop(): void
    {
        $content = self::PRESTASHOP . "\n" . self::PROTECTION;

        $repaired = $this->doctor()->repair($content, HtaccessDoctor::PROTECTION_AFTER_PRESTASHOP);

        $this->assertStringStartsWith('# BEGIN sc_alwaysdata protection', $repaired);
        $this->assertSame(1, substr_count($repaired, '# BEGIN sc_alwaysdata protection'));
    }

    public function testRepairWithNothingToDoThrows(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->doctor()->repair(self::PRESTASHOP, HtaccessDoctor::DEAD_UA_RULES);
    }

    public function testAddUaRulesCreatesSectionAfterProtectionAndDeduplicates(): void
    {
        $content = self::PROTECTION . "\n" . self::PRESTASHOP;

        $once = $this->doctor()->addUaRules($content, ['AhrefsBot']);
        $twice = $this->doctor()->addUaRules($once, ['ahrefsbot', 'DotBot']);

        $this->assertSame(1, substr_count($twice, HtaccessDoctor::BLOCKS_BEGIN));
        $this->assertSame(1, substr_count($twice, '"AhrefsBot"'));
        $this->assertStringNotContainsString('"ahrefsbot"', $twice);
        $this->assertLessThan(strpos($twice, HtaccessDoctor::BLOCKS_BEGIN), strpos($twice, '# END sc_alwaysdata protection'));
        $this->assertLessThan(strpos($twice, '# ~~start~~'), strpos($twice, '"DotBot"'));
        $this->assertSame([], $this->doctor()->analyse($twice, self::REFERER_ON));
    }

    public function testAddThenRemoveRestoresRules(): void
    {
        $content = $this->doctor()->addUaRules(self::PRESTASHOP, ['AhrefsBot']);

        $removed = $this->doctor()->removeUaRules($content, 'AhrefsBot');

        $this->assertStringNotContainsString('AhrefsBot', $removed);
        $this->assertStringContainsString(HtaccessDoctor::BLOCKS_BEGIN, $removed);
    }

    /**
     * Le bloc `# BEGIN vigie` de Vigie (#13), au-dessus ou au-dessous du bloc
     * du module : retirer une règle d'UA du module le laisse intact, même
     * pour un robot qu'il bloque aussi.
     */
    public function testRemoveUaRulesLeavesTheVigieBlockIntact(): void
    {
        $vigie = "# BEGIN vigie\n"
            . "# Gere par Vigie (vigie site recommend) : ne pas modifier a la main.\n"
            . "RewriteEngine On\n"
            . "# ua jusqu'au 2026-07-15 12:00:00\n"
            . "RewriteCond %{HTTP_USER_AGENT} \"Bytespider\" [NC,OR]\n"
            . "RewriteCond %{HTTP_USER_AGENT} \"AhrefsBot\" [NC]\n"
            . "RewriteCond %{TIME} <20260715120000\n"
            . "RewriteRule ^ - [F,L]\n"
            . "# ip jusqu'au 2026-06-16 12:00:00\n"
            . "RewriteCond %{REMOTE_ADDR} \"^203\\.0\\.113\\.7$\"\n"
            . "RewriteCond %{TIME} <20260616120000\n"
            . "RewriteRule ^ - [F,L]\n"
            . "# END vigie\n";
        $module = $this->doctor()->addUaRules(self::PROTECTION . "\n" . self::PRESTASHOP, ['AhrefsBot', 'Bytespider']);
        foreach ([$vigie . $module, $module . $vigie] as $content) {
            $removed = $this->doctor()->removeUaRules($this->doctor()->removeUaRules($content, 'AhrefsBot'), 'Bytespider');

            $this->assertStringContainsString($vigie, $removed);
            $this->assertStringNotContainsString('block UA: AhrefsBot', $removed);
            $this->assertStringNotContainsString('block UA: Bytespider', $removed);
        }
    }
}

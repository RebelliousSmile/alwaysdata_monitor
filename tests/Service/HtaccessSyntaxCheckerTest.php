<?php

declare(strict_types=1);

namespace ScAlwaysdata\Tests\Service;

use PHPUnit\Framework\TestCase;
use ScAlwaysdata\Service\HtaccessSyntaxChecker;

class HtaccessSyntaxCheckerTest extends TestCase
{
    private HtaccessSyntaxChecker $checker;

    protected function setUp(): void
    {
        $this->checker = new HtaccessSyntaxChecker();
    }

    /**
     * @return list<string>
     */
    private function codes(string $content): array
    {
        return array_column($this->checker->check($content), 'code');
    }

    public function testRealisticPrestashopFileHasNoProblem(): void
    {
        $content = <<<'HTACCESS'
# ~~start~~ Do not remove this comment, PrestaShop will keep automatically the code outside this comment when .htaccess will be generated again
<IfModule mod_rewrite.c>
<IfModule mod_env.c>
SetEnv HTTP_MOD_REWRITE On
</IfModule>

RewriteEngine on

RewriteRule . - [E=REWRITEBASE:/]
RewriteRule ^api(?:/(.*))?$ %{ENV:REWRITEBASE}webservice/dispatcher.php?url=$1 [QSA,L]

RewriteCond %{HTTP_HOST} ^www.site-a.example$
RewriteRule ^(.*)$ https://site-a.example/$1 [R=301,L]

RewriteCond %{HTTP_USER_AGENT} "AhrefsBot|SemrushBot" [NC]
RewriteRule .* - [F,L]
</IfModule>

<IfModule mod_expires.c>
ExpiresActive On
AddType application/font-woff2 .woff2
</IfModule>

<FilesMatch "\.(ico|jpe?g|png|gif)$">
    Header set Cache-Control "max-age=31536000, public"
</FilesMatch>

<Files ~ "\.(tpl|log)$">
    <IfModule mod_authz_core.c>
        Require all denied
    </IfModule>
</Files>
SetEnvIfNoCase User-Agent "^bad bot" blocked \
    ignored_flag
HTACCESS;

        $this->assertSame([], $this->checker->check($content));
    }

    public function testEmptyContentHasNoProblem(): void
    {
        $this->assertSame([], $this->checker->check(''));
        $this->assertSame([], $this->checker->check("# only a comment\n\n"));
    }

    public function testUnclosedSectionIsReportedAtItsOpeningLine(): void
    {
        $problems = $this->checker->check("RewriteEngine on\n<IfModule mod_rewrite.c>\nRewriteRule . - [L]\n");

        $this->assertSame([HtaccessSyntaxChecker::UNCLOSED_SECTION], array_column($problems, 'code'));
        $this->assertSame(2, $problems[0]['line']);
    }

    public function testStrayClosingTagIsReported(): void
    {
        $this->assertSame([HtaccessSyntaxChecker::STRAY_CLOSING_TAG], $this->codes("RewriteEngine on\n</IfModule>\n"));
    }

    public function testMismatchedClosingTagIsReported(): void
    {
        $codes = $this->codes("<IfModule mod_rewrite.c>\n<Files x>\n</IfModule>\n</Files>\n");

        $this->assertContains(HtaccessSyntaxChecker::STRAY_CLOSING_TAG, $codes);
    }

    public function testSectionNamesAreCaseInsensitive(): void
    {
        $this->assertSame([], $this->checker->check("<ifmodule mod_rewrite.c>\nRewriteEngine on\n</IfModule>\n"));
    }

    public function testMalformedTagIsReported(): void
    {
        $this->assertSame([HtaccessSyntaxChecker::MALFORMED_TAG], $this->codes("<IfModule mod_rewrite.c\nRewriteEngine on\n"));
    }

    public function testUnterminatedQuoteIsReported(): void
    {
        $this->assertSame(
            [HtaccessSyntaxChecker::UNTERMINATED_QUOTE],
            $this->codes("SetEnvIfNoCase User-Agent \"Bad bot blocked\n")
        );
    }

    public function testEscapedQuoteDoesNotCount(): void
    {
        $this->assertSame([], $this->checker->check("RewriteCond %{HTTP_REFERER} \"a\\\"b\" [NC]\nRewriteRule . - [F]\n"));
    }

    public function testRewriteCondAndRuleNeedTwoArguments(): void
    {
        $this->assertSame(
            [HtaccessSyntaxChecker::MISSING_ARGUMENTS, HtaccessSyntaxChecker::MISSING_ARGUMENTS],
            $this->codes("RewriteCond %{HTTP_HOST}\nRewriteRule ^(.*)$\n")
        );
    }

    public function testQuotedArgumentWithSpacesCountsAsOne(): void
    {
        $this->assertSame([], $this->checker->check("RewriteCond %{HTTP_USER_AGENT} \"Bad Bot|Other Bot\" [NC]\nRewriteRule .* - [F]\n"));
    }

    public function testRewriteEngineNeedsOnOrOff(): void
    {
        $this->assertSame([], $this->checker->check("RewriteEngine On\nRewriteEngine off\n"));
        $this->assertSame([HtaccessSyntaxChecker::BAD_ENGINE_VALUE], $this->codes("RewriteEngine maybe\n"));
        $this->assertSame([HtaccessSyntaxChecker::BAD_ENGINE_VALUE], $this->codes("RewriteEngine\n"));
    }

    public function testContinuationLineJoinsArgumentsAndKeepsFirstLineNumber(): void
    {
        $this->assertSame([], $this->checker->check("RewriteCond %{HTTP_HOST} \\\n    ^site-a\\.example$\nRewriteRule . - [L]\n"));

        $problems = $this->checker->check("\n\nRewriteCond %{HTTP_HOST} \\\n\nRewriteRule . - [L]\nRewriteRule \"x\n");
        $this->assertSame(6, $problems[count($problems) - 1]['line']);
    }

    public function testCommentedDirectivesAreIgnored(): void
    {
        $this->assertSame([], $this->checker->check("# <IfModule mod_rewrite.c>\n#RewriteRule\n  # RewriteEngine maybe\n"));
    }

    public function testCrLfLineEndingsAreHandled(): void
    {
        $this->assertSame([], $this->checker->check("<IfModule mod_rewrite.c>\r\nRewriteEngine on\r\n</IfModule>\r\n"));
    }

    public function testIntroducedIgnoresProblemsTheFileAlreadyHad(): void
    {
        $before = $this->checker->check("<IfModule a>\n");
        $after = $this->checker->check("<IfModule a>\nRewriteEngine on\n");

        $this->assertSame([], $this->checker->introduced($before, $after));
    }

    public function testIntroducedReportsAWorseFile(): void
    {
        $before = $this->checker->check("<IfModule a>\n");
        $after = $this->checker->check("<IfModule a>\n<Files x>\n");

        $introduced = $this->checker->introduced($before, $after);

        $this->assertCount(1, $introduced);
        $this->assertSame(HtaccessSyntaxChecker::UNCLOSED_SECTION, $introduced[0]['code']);
    }

    public function testIntroducedReportsANewKindOfProblem(): void
    {
        $before = $this->checker->check("<IfModule a>\n");
        $after = $this->checker->check("<IfModule a>\nRewriteRule x\n");

        $this->assertSame([HtaccessSyntaxChecker::MISSING_ARGUMENTS], array_column($this->checker->introduced($before, $after), 'code'));
    }
}

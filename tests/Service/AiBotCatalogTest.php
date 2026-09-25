<?php

declare(strict_types=1);

namespace ScAlwaysdata\Tests\Service;

use PHPUnit\Framework\TestCase;
use ScAlwaysdata\Service\AiBotCatalog;

class AiBotCatalogTest extends TestCase
{
    public function testFilterKeepsCatalogNamesInCanonicalSpelling(): void
    {
        $this->assertSame(
            ['GPTBot', 'meta-externalagent'],
            (new AiBotCatalog())->filter(['gptbot', ' META-ExternalAgent ', 'Googlebot', 'GPTBot', '<script>'])
        );
    }

    public function testRobotsOnlyTokensGetNoUserAgentRule(): void
    {
        $this->assertSame(['GPTBot'], (new AiBotCatalog())->withUserAgent(['Google-Extended', 'GPTBot', 'Applebot-Extended']));
    }

    public function testNamesAreValidRobotsTokensAndNeverSearchEngines(): void
    {
        foreach ((new AiBotCatalog())->all() as $bot) {
            $this->assertMatchesRegularExpression('/^[A-Za-z0-9._-]+$/', $bot['name']);
            $this->assertNotContains(strtolower($bot['name']), ['googlebot', 'bingbot', 'applebot', 'facebookexternalhit']);
            $this->assertContains($bot['purpose'], [AiBotCatalog::PURPOSE_TRAINING, AiBotCatalog::PURPOSE_SEARCH, AiBotCatalog::PURPOSE_USER]);
        }
    }
}

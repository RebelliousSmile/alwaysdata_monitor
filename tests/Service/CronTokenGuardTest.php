<?php

declare(strict_types=1);

namespace ScAlwaysdata\Tests\Service;

use PHPUnit\Framework\TestCase;
use ScAlwaysdata\Service\CronTokenGuard;

class CronTokenGuardTest extends TestCase
{
    public function testHeaderIsPreferredOverQueryParameter(): void
    {
        $this->assertSame(
            'from-header',
            CronTokenGuard::provided(['HTTP_X_CRON_TOKEN' => 'from-header'], 'from-query')
        );
    }

    public function testQueryParameterIsTheFallback(): void
    {
        $this->assertSame('from-query', CronTokenGuard::provided([], 'from-query'));
        $this->assertSame('from-query', CronTokenGuard::provided(['HTTP_X_CRON_TOKEN' => ''], 'from-query'));
    }

    public function testNonStringHeaderValueIsIgnored(): void
    {
        $this->assertSame('from-query', CronTokenGuard::provided(['HTTP_X_CRON_TOKEN' => ['x']], 'from-query'));
    }

    public function testNothingProvidedGivesAnEmptyToken(): void
    {
        $this->assertSame('', CronTokenGuard::provided([], ''));
    }

    public function testMatchingTokenIsValid(): void
    {
        $this->assertTrue(CronTokenGuard::isValid('s3cret', 's3cret'));
    }

    public function testWrongTokenIsRejected(): void
    {
        $this->assertFalse(CronTokenGuard::isValid('s3cret', 'other'));
    }

    public function testEmptyStoredTokenNeverAuthorizes(): void
    {
        $this->assertFalse(CronTokenGuard::isValid('', ''));
        $this->assertFalse(CronTokenGuard::isValid('', 'anything'));
    }
}

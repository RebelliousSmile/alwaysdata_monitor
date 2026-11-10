<?php

declare(strict_types=1);

namespace ScAlwaysdata\Tests\Service;

use PHPUnit\Framework\TestCase;
use ScAlwaysdata\Service\DiagnosticBusyException;
use ScAlwaysdata\Service\DiagnosticCache;

class DiagnosticCacheTest extends TestCase
{
    private string $dir;
    private int $now = 1_800_000_000;

    protected function setUp(): void
    {
        $this->dir = sys_get_temp_dir() . '/sc_diag_cache_' . uniqid('', true) . '/';
    }

    protected function tearDown(): void
    {
        foreach (glob($this->dir . '*') ?: [] as $file) {
            @unlink($file);
        }
        @rmdir($this->dir);
    }

    private function cache(): DiagnosticCache
    {
        return new DiagnosticCache($this->dir, function (): int {
            return $this->now;
        });
    }

    public function testPastDayIsComputedOnceWhileTheSignatureHolds(): void
    {
        $calls = 0;
        $compute = function () use (&$calls): array {
            ++$calls;

            return ['n' => $calls];
        };

        $first = $this->cache()->remember('diagnostic-2026-11-09', 'sig-a', false, $compute);
        $this->now += 86400 * 3;
        $second = $this->cache()->remember('diagnostic-2026-11-09', 'sig-a', false, $compute);

        $this->assertSame(['n' => 1], $first);
        $this->assertSame(['n' => 1], $second);
        $this->assertSame(1, $calls);
    }

    public function testPastDayIsRecomputedWhenTheLogChanges(): void
    {
        $this->cache()->remember('diagnostic-2026-11-09', 'sig-a', false, fn (): array => ['v' => 'old']);
        $result = $this->cache()->remember('diagnostic-2026-11-09', 'sig-b', false, fn (): array => ['v' => 'new']);

        $this->assertSame(['v' => 'new'], $result);
    }

    public function testCurrentDayIsServedFromCacheWithinTheTtlDespiteAGrowingLog(): void
    {
        $this->cache()->remember('diagnostic-2026-11-10', 'size-100', true, fn (): array => ['v' => 'first']);
        $this->now += DiagnosticCache::TODAY_TTL - 1;
        $result = $this->cache()->remember('diagnostic-2026-11-10', 'size-200', true, fn (): array => ['v' => 'second']);

        $this->assertSame(['v' => 'first'], $result);
    }

    public function testCurrentDayIsRecomputedOnceTheTtlHasElapsed(): void
    {
        $this->cache()->remember('diagnostic-2026-11-10', 'size-100', true, fn (): array => ['v' => 'first']);
        $this->now += DiagnosticCache::TODAY_TTL;
        $result = $this->cache()->remember('diagnostic-2026-11-10', 'size-200', true, fn (): array => ['v' => 'second']);

        $this->assertSame(['v' => 'second'], $result);
    }

    public function testASecondRequestWhileComputingGetsBusyInsteadOfAnotherPass(): void
    {
        mkdir($this->dir, 0755, true);
        $held = fopen($this->dir . 'diagnostic-2026-11-10.lock', 'c');
        $this->assertNotFalse($held);
        $this->assertTrue(flock($held, LOCK_EX | LOCK_NB));

        $computed = false;
        try {
            $this->cache()->remember('diagnostic-2026-11-10', 'sig', true, function () use (&$computed): array {
                $computed = true;

                return [];
            });
            $this->fail('DiagnosticBusyException expected');
        } catch (DiagnosticBusyException $e) {
            $this->assertFalse($computed, 'The log must not be read a second time');
        } finally {
            flock($held, LOCK_UN);
            fclose($held);
        }
    }

    public function testAFreshEntryIsServedEvenWhileAnotherRequestHoldsTheLock(): void
    {
        $this->cache()->remember('diagnostic-2026-11-09', 'sig', false, fn (): array => ['v' => 1]);
        $held = fopen($this->dir . 'diagnostic-2026-11-09.lock', 'c');
        flock($held, LOCK_EX | LOCK_NB);

        try {
            $result = $this->cache()->remember('diagnostic-2026-11-09', 'sig', false, fn (): array => ['v' => 2]);
            $this->assertSame(['v' => 1], $result);
        } finally {
            flock($held, LOCK_UN);
            fclose($held);
        }
    }

    public function testTheLockIsReleasedWhenTheComputationFails(): void
    {
        try {
            $this->cache()->remember('diagnostic-2026-11-09', 'sig', false, function (): array {
                throw new \RuntimeException('log unreadable');
            });
        } catch (\RuntimeException $e) {
            $this->assertSame('log unreadable', $e->getMessage());
        }

        $result = $this->cache()->remember('diagnostic-2026-11-09', 'sig', false, fn (): array => ['v' => 'ok']);
        $this->assertSame(['v' => 'ok'], $result);
    }

    public function testKeysThatCouldLeaveTheCacheDirectoryAreRefused(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->cache()->remember('../../config/settings', 'sig', false, fn (): array => []);
    }

    public function testPurgeRemovesOnlyEntriesOlderThanThirtyDays(): void
    {
        $this->cache()->remember('diagnostic-old', 'sig', false, fn (): array => []);
        $this->cache()->remember('diagnostic-recent', 'sig', false, fn (): array => []);
        touch($this->dir . 'diagnostic-old.json', $this->now - 31 * 86400);
        touch($this->dir . 'diagnostic-old.lock', $this->now - 31 * 86400);
        touch($this->dir . 'diagnostic-recent.json', $this->now - 29 * 86400);
        touch($this->dir . 'diagnostic-recent.lock', $this->now - 29 * 86400);

        $this->assertSame(2, $this->cache()->purge());
        $this->assertFileDoesNotExist($this->dir . 'diagnostic-old.json');
        $this->assertFileExists($this->dir . 'diagnostic-recent.json');
    }
}

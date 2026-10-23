<?php

declare(strict_types=1);

namespace ScAlwaysdata\Tests\Service;

use PHPUnit\Framework\TestCase;
use ScAlwaysdata\Service\ExecutableFinder;

class ExecutableFinderTest extends TestCase
{
    private string $dir;

    protected function setUp(): void
    {
        $this->dir = sys_get_temp_dir() . '/sc_alwaysdata_finder_' . bin2hex(random_bytes(4));
        mkdir($this->dir);
    }

    protected function tearDown(): void
    {
        foreach (glob($this->dir . '/*') ?: [] as $file) {
            unlink($file);
        }
        rmdir($this->dir);
    }

    private function install(string $name, int $mode): string
    {
        $file = $this->dir . '/' . $name;
        file_put_contents($file, "#!/bin/sh\n");
        chmod($file, $mode);

        return $file;
    }

    public function testFindsAnExecutableInTheGivenPath(): void
    {
        $file = $this->install('fakectl', 0755);

        $this->assertSame($file, ExecutableFinder::find('fakectl', '/nonexistent' . PATH_SEPARATOR . $this->dir));
    }

    public function testIgnoresAFileThatIsNotExecutable(): void
    {
        $this->install('fakectl', 0644);

        $this->assertNull(ExecutableFinder::find('fakectl', $this->dir));
    }

    public function testReturnsNullWhenAbsent(): void
    {
        $this->assertNull(ExecutableFinder::find('fakectl', $this->dir));
        $this->assertNull(ExecutableFinder::find('fakectl', ''));
    }

    public function testRejectsNamesThatAreNotBareCommands(): void
    {
        $this->install('fakectl', 0755);

        $this->assertNull(ExecutableFinder::find('', $this->dir));
        $this->assertNull(ExecutableFinder::find('../fakectl', $this->dir));
        $this->assertNull(ExecutableFinder::find($this->dir . '/fakectl', $this->dir));
        $this->assertNull(ExecutableFinder::find("fakectl\0x", $this->dir));
    }
}

<?php

declare(strict_types=1);

namespace Tests;

use EzPhp\WebauthnMetadata\FileBlobCache;

/**
 * @package Tests
 */
final class FileBlobCacheTest extends TestCase
{
    private string $directory;

    protected function setUp(): void
    {
        $this->directory = sys_get_temp_dir() . '/ez-php-wm-cache-' . bin2hex(random_bytes(4));
    }

    protected function tearDown(): void
    {
        foreach (glob($this->directory . '/{,*/}*', GLOB_BRACE) ?: [] as $file) {
            is_file($file) && unlink($file);
        }

        @rmdir($this->directory . '/nested');
        @rmdir($this->directory);
    }

    public function testMissingFileYieldsNull(): void
    {
        self::assertNull((new FileBlobCache($this->directory . '/blob.jwt'))->get());
    }

    public function testRoundTripCreatesDirectory(): void
    {
        $cache = new FileBlobCache($this->directory . '/nested/blob.jwt');
        $cache->put('a.b.c');

        self::assertSame('a.b.c', $cache->get());
    }

    public function testEmptyFileYieldsNull(): void
    {
        mkdir($this->directory);
        file_put_contents($this->directory . '/blob.jwt', '');

        self::assertNull((new FileBlobCache($this->directory . '/blob.jwt'))->get());
    }

    public function testUnwritableLocationThrows(): void
    {
        mkdir($this->directory);
        file_put_contents($this->directory . '/file', 'x');

        $this->expectException(\RuntimeException::class);

        (new FileBlobCache($this->directory . '/file/sub/blob.jwt'))->put('a.b.c');
    }

    public function testFailedRenameThrowsAndLeavesNoTempFile(): void
    {
        mkdir($this->directory . '/nested', 0o775, true);

        try {
            (new FileBlobCache($this->directory . '/nested'))->put('a.b.c');
            self::fail('Expected exception');
        } catch (\RuntimeException) {
            self::assertSame([], glob($this->directory . '/*.tmp') ?: []);
        }
    }
}

<?php

declare(strict_types=1);

namespace Tests;

use EzPhp\WebauthnMetadata\CurlBlobFetcher;
use EzPhp\WebauthnMetadata\Exception\BlobFetchException;

/**
 * @package Tests
 */
final class CurlBlobFetcherTest extends TestCase
{
    public function testRejectsNonHttpsUrl(): void
    {
        $this->expectException(BlobFetchException::class);
        $this->expectExceptionMessage('https://');

        (new CurlBlobFetcher())->fetch('http://example.test/');
    }

    public function testUnreachableHostRaisesFetchException(): void
    {
        $this->expectException(BlobFetchException::class);

        (new CurlBlobFetcher(timeoutSeconds: 2))->fetch('https://127.0.0.1:1/');
    }
}

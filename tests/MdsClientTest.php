<?php

declare(strict_types=1);

namespace Tests;

use EzPhp\WebauthnMetadata\Exception\BlobFetchException;
use EzPhp\WebauthnMetadata\Exception\BlobVerificationException;
use EzPhp\WebauthnMetadata\MdsClient;
use EzPhp\WebauthnMetadata\MetadataBlobVerifier;
use Tests\Support\ArrayBlobCache;
use Tests\Support\FakeBlobFetcher;
use Tests\Support\TestJwt;
use Tests\Support\TestPki;

/**
 * @package Tests
 */
final class MdsClientTest extends TestCase
{
    private string $rootPem;

    private string $rootDer;

    /** @var array{cert: \OpenSSLCertificate, key: \OpenSSLAsymmetricKey} */
    private array $leaf;

    protected function setUp(): void
    {
        $root = TestPki::issue('Root', null, true);
        $this->leaf = TestPki::issue('Signer', $root, false);
        $this->rootPem = TestPki::pem($root['cert']);
        $this->rootDer = TestPki::der($root['cert']);
    }

    private function jwt(string $nextUpdate = '2999-01-01'): string
    {
        return TestJwt::build(TestJwt::payload('a-b', $this->rootDer, $nextUpdate), [TestPki::der($this->leaf['cert'])], $this->leaf['key']);
    }

    private function client(FakeBlobFetcher $fetcher, ArrayBlobCache $cache): MdsClient
    {
        return new MdsClient($fetcher, $cache, new MetadataBlobVerifier($this->rootPem));
    }

    public function testDownloadsVerifiesAndCachesWhenCacheIsEmpty(): void
    {
        $jwt = $this->jwt();
        $fetcher = new FakeBlobFetcher($jwt . "\n");
        $cache = new ArrayBlobCache();

        $blob = $this->client($fetcher, $cache)->blob();

        self::assertSame(7, $blob->number);
        self::assertSame(1, $fetcher->calls);
        self::assertSame($jwt, $cache->jwt);
    }

    public function testValidCacheAvoidsNetwork(): void
    {
        $fetcher = new FakeBlobFetcher(null);

        $blob = $this->client($fetcher, new ArrayBlobCache($this->jwt()))->blob();

        self::assertSame(7, $blob->number);
        self::assertSame(0, $fetcher->calls);
    }

    public function testCorruptCacheIsReplacedByFreshDownload(): void
    {
        $jwt = $this->jwt();
        $fetcher = new FakeBlobFetcher($jwt);
        $cache = new ArrayBlobCache('tampered.cache.contents');

        $this->client($fetcher, $cache)->blob();

        self::assertSame(1, $fetcher->calls);
        self::assertSame($jwt, $cache->jwt);
    }

    public function testCacheThatPassedNextUpdateIsRefetched(): void
    {
        $fresh = $this->jwt();
        $fetcher = new FakeBlobFetcher($fresh);
        $cache = new ArrayBlobCache($this->jwt('2020-01-01'));

        $this->client($fetcher, $cache)->blob();

        self::assertSame(1, $fetcher->calls);
        self::assertSame($fresh, $cache->jwt);
    }

    public function testDownloadFailurePropagatesInsteadOfServingStaleBlob(): void
    {
        $this->expectException(BlobFetchException::class);

        $this->client(new FakeBlobFetcher(null), new ArrayBlobCache($this->jwt('2020-01-01')))->blob();
    }

    public function testInvalidDownloadIsNeverCached(): void
    {
        $cache = new ArrayBlobCache();

        try {
            $this->client(new FakeBlobFetcher('forged.blob.data'), $cache)->blob();
            self::fail('Expected BlobVerificationException');
        } catch (BlobVerificationException) {
            self::assertNull($cache->jwt);
        }
    }
}

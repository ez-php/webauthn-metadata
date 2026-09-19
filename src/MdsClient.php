<?php

declare(strict_types=1);

namespace EzPhp\WebauthnMetadata;

use EzPhp\WebauthnMetadata\Exception\BlobFetchException;
use EzPhp\WebauthnMetadata\Exception\BlobVerificationException;

/**
 * Supplies a verified, fresh MetadataBlob: cache first, download when the
 * cache is empty, invalid or past nextUpdate.
 *
 * The cache is never trusted — cached bytes are re-verified on every load, so
 * a tampered cache file degrades to a re-download instead of a trust bypass.
 * If a needed download fails, the failure propagates; a stale blob is never
 * silently served.
 *
 * @package EzPhp\WebauthnMetadata
 */
final class MdsClient
{
    public const string DEFAULT_URL = 'https://mds3.fidoalliance.org/';

    public function __construct(
        private readonly BlobFetcherInterface $fetcher,
        private readonly BlobCacheInterface $cache,
        private readonly MetadataBlobVerifier $verifier,
        private readonly string $url = self::DEFAULT_URL,
    ) {
    }

    /**
     * @throws BlobFetchException
     * @throws BlobVerificationException
     */
    public function blob(?\DateTimeImmutable $now = null): MetadataBlob
    {
        $now ??= new \DateTimeImmutable();
        $cached = $this->cache->get();

        if ($cached !== null) {
            try {
                return $this->verifier->verify($cached, $now);
            } catch (BlobVerificationException) {
                // Stale or corrupt cache — fall through to a fresh download.
            }
        }

        $jwt = trim($this->fetcher->fetch($this->url));
        $blob = $this->verifier->verify($jwt, $now);
        $this->cache->put($jwt);

        return $blob;
    }
}

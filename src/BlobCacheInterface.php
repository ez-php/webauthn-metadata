<?php

declare(strict_types=1);

namespace EzPhp\WebauthnMetadata;

/**
 * Stores the raw (JWT) metadata blob between requests. The cache holds
 * untrusted bytes: MdsClient re-verifies whatever it returns.
 *
 * @package EzPhp\WebauthnMetadata
 */
interface BlobCacheInterface
{
    /**
     * Return the cached metadata BLOB (JWT), or null when nothing is cached.
     */
    public function get(): ?string;

    /**
     * Store the metadata BLOB (JWT).
     */
    public function put(string $jwt): void;
}

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
    public function get(): ?string;

    public function put(string $jwt): void;
}

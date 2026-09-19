<?php

declare(strict_types=1);

namespace Tests\Support;

use EzPhp\WebauthnMetadata\BlobCacheInterface;

/**
 * @package Tests\Support
 */
final class ArrayBlobCache implements BlobCacheInterface
{
    public function __construct(
        public ?string $jwt = null,
    ) {
    }

    public function get(): ?string
    {
        return $this->jwt;
    }

    public function put(string $jwt): void
    {
        $this->jwt = $jwt;
    }
}

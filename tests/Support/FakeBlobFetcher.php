<?php

declare(strict_types=1);

namespace Tests\Support;

use EzPhp\WebauthnMetadata\BlobFetcherInterface;
use EzPhp\WebauthnMetadata\Exception\BlobFetchException;

/**
 * @package Tests\Support
 */
final class FakeBlobFetcher implements BlobFetcherInterface
{
    public int $calls = 0;

    public function __construct(
        private readonly ?string $body,
    ) {
    }

    public function fetch(string $url): string
    {
        $this->calls++;

        return $this->body ?? throw new BlobFetchException('offline');
    }
}

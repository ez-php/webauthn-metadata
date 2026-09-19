<?php

declare(strict_types=1);

namespace EzPhp\WebauthnMetadata;

use EzPhp\WebauthnMetadata\Exception\BlobFetchException;

/**
 * Downloads the raw metadata blob. The only seam in this module that touches
 * the network, so tests and applications can substitute their own transport.
 *
 * @package EzPhp\WebauthnMetadata
 */
interface BlobFetcherInterface
{
    /**
     * @throws BlobFetchException
     */
    public function fetch(string $url): string;
}

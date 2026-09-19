<?php

declare(strict_types=1);

namespace EzPhp\WebauthnMetadata;

use EzPhp\WebauthnMetadata\Exception\BlobFetchException;

/**
 * cURL-based blob fetcher. HTTPS only; TLS peer verification is never
 * disabled. Integrity of the payload is additionally guaranteed by the JWT
 * signature check in MetadataBlobVerifier.
 *
 * @package EzPhp\WebauthnMetadata
 */
final class CurlBlobFetcher implements BlobFetcherInterface
{
    public function __construct(
        private readonly int $timeoutSeconds = 30,
    ) {
    }

    public function fetch(string $url): string
    {
        if (!str_starts_with($url, 'https://')) {
            throw new BlobFetchException('Metadata blob URL must use https://.');
        }

        $handle = curl_init($url);

        if ($handle === false) {
            throw new BlobFetchException('Could not initialise cURL.');
        }

        curl_setopt_array($handle, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_TIMEOUT => $this->timeoutSeconds,
            CURLOPT_FOLLOWLOCATION => false,
            CURLOPT_PROTOCOLS => CURLPROTO_HTTPS,
            CURLOPT_SSL_VERIFYPEER => true,
            CURLOPT_SSL_VERIFYHOST => 2,
        ]);

        $body = curl_exec($handle);
        $status = curl_getinfo($handle, CURLINFO_RESPONSE_CODE);
        $error = curl_error($handle);

        if (!is_string($body) || $status !== 200) {
            throw new BlobFetchException("Metadata blob download failed (HTTP {$status}): {$error}");
        }

        return $body;
    }
}

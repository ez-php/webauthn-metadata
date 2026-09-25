<?php

declare(strict_types=1);

namespace EzPhp\WebauthnMetadata;

/**
 * The verified, parsed FIDO MDS3 blob payload.
 *
 * @package EzPhp\WebauthnMetadata
 */
final readonly class MetadataBlob
{
    /**
     * @param array<string, MetadataEntry> $entriesByAaguid
     */
    public function __construct(
        public int $number,
        public \DateTimeImmutable $nextUpdate,
        private array $entriesByAaguid,
    ) {
    }

    /**
     * Look up the metadata entry for an authenticator AAGUID, or null when unknown.
     */
    public function findByAaguid(string $aaguid): ?MetadataEntry
    {
        return $this->entriesByAaguid[strtolower($aaguid)] ?? null;
    }

    /**
     * Number of entries in the BLOB.
     */
    public function count(): int
    {
        return count($this->entriesByAaguid);
    }
}

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

    public function findByAaguid(string $aaguid): ?MetadataEntry
    {
        return $this->entriesByAaguid[strtolower($aaguid)] ?? null;
    }

    public function count(): int
    {
        return count($this->entriesByAaguid);
    }
}

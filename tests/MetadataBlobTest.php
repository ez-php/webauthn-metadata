<?php

declare(strict_types=1);

namespace Tests;

use EzPhp\WebauthnMetadata\MetadataBlob;
use EzPhp\WebauthnMetadata\MetadataEntry;

/**
 * @package Tests
 */
final class MetadataBlobTest extends TestCase
{
    private function makeBlob(): MetadataBlob
    {
        $entry = new MetadataEntry('aaaaaaaa-0000-0000-0000-000000000001', 'Key', [], ['FIDO_CERTIFIED']);

        return new MetadataBlob(7, new \DateTimeImmutable('2030-01-01'), [$entry->aaguid => $entry]);
    }

    public function testFindsEntryByAaguidCaseInsensitively(): void
    {
        $blob = $this->makeBlob();

        self::assertSame('Key', $blob->findByAaguid('AAAAAAAA-0000-0000-0000-000000000001')?->description);
    }

    public function testUnknownAaguidReturnsNull(): void
    {
        self::assertNull($this->makeBlob()->findByAaguid('ffffffff-0000-0000-0000-000000000000'));
    }

    public function testCountAndMetadata(): void
    {
        $blob = $this->makeBlob();

        self::assertSame(1, $blob->count());
        self::assertSame(7, $blob->number);
        self::assertSame('2030-01-01', $blob->nextUpdate->format('Y-m-d'));
    }
}

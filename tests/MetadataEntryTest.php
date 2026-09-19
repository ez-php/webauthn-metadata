<?php

declare(strict_types=1);

namespace Tests;

use EzPhp\WebauthnMetadata\MetadataEntry;

/**
 * @package Tests
 */
final class MetadataEntryTest extends TestCase
{
    public function testCertifiedStatusIsNotUntrusted(): void
    {
        self::assertNull((new MetadataEntry('a', 'd', [], ['FIDO_CERTIFIED_L1', 'UPDATE_AVAILABLE']))->untrustedStatus());
    }

    public function testReturnsFirstCompromiseStatus(): void
    {
        $entry = new MetadataEntry('a', 'd', [], ['FIDO_CERTIFIED', 'ATTESTATION_KEY_COMPROMISE', 'REVOKED']);

        self::assertSame('ATTESTATION_KEY_COMPROMISE', $entry->untrustedStatus());
    }
}

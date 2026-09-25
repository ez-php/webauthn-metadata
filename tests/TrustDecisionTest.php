<?php

declare(strict_types=1);

namespace Tests;

use EzPhp\WebauthnMetadata\MetadataEntry;
use EzPhp\WebauthnMetadata\TrustDecision;

/**
 * @package Tests
 */
final class TrustDecisionTest extends TestCase
{
    public function testEntryDefaultsToNull(): void
    {
        $decision = new TrustDecision(false, 'unknown authenticator');

        self::assertFalse($decision->trusted);
        self::assertSame('unknown authenticator', $decision->reason);
        self::assertNull($decision->entry);
    }

    public function testCarriesTheMatchedEntry(): void
    {
        $entry = new MetadataEntry('a', 'd', [], []);
        $decision = new TrustDecision(true, 'chain verified', $entry);

        self::assertTrue($decision->trusted);
        self::assertSame($entry, $decision->entry);
    }
}

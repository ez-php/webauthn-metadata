<?php

declare(strict_types=1);

namespace Tests;

use EzPhp\WebauthnMetadata\Aaguid;

/**
 * @package Tests
 */
final class AaguidTest extends TestCase
{
    public function testFormatsSixteenBytesAsDashedUuid(): void
    {
        self::assertSame(
            '00112233-4455-6677-8899-aabbccddeeff',
            Aaguid::fromBinary(hex2bin('00112233445566778899aabbccddeeff') ?: ''),
        );
    }

    public function testRejectsWrongLength(): void
    {
        $this->expectException(\InvalidArgumentException::class);

        Aaguid::fromBinary('short');
    }
}

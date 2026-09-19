<?php

declare(strict_types=1);

namespace EzPhp\WebauthnMetadata;

/**
 * Converts the 16 raw AAGUID bytes from authenticatorData into the lowercase
 * dashed UUID string FIDO MDS uses as its entry key.
 *
 * @package EzPhp\WebauthnMetadata
 */
final class Aaguid
{
    public static function fromBinary(string $bytes): string
    {
        if (strlen($bytes) !== 16) {
            throw new \InvalidArgumentException('An AAGUID is exactly 16 bytes.');
        }

        $hex = bin2hex($bytes);

        return substr($hex, 0, 8) . '-' . substr($hex, 8, 4) . '-' . substr($hex, 12, 4)
            . '-' . substr($hex, 16, 4) . '-' . substr($hex, 20, 12);
    }
}

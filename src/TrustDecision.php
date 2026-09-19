<?php

declare(strict_types=1);

namespace EzPhp\WebauthnMetadata;

/**
 * Outcome of evaluating an attestation chain against FIDO MDS. Meant to be
 * combined with — not to replace — the cryptographic result of
 * ez-php/webauthn (`AttestationResult::$trusted`).
 *
 * @package EzPhp\WebauthnMetadata
 */
final readonly class TrustDecision
{
    public function __construct(
        public bool $trusted,
        public string $reason,
        public ?MetadataEntry $entry = null,
    ) {
    }
}

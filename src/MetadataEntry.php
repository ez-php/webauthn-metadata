<?php

declare(strict_types=1);

namespace EzPhp\WebauthnMetadata;

/**
 * One authenticator model in the metadata blob: its trust-anchor
 * certificates and its FIDO status history.
 *
 * @package EzPhp\WebauthnMetadata
 */
final readonly class MetadataEntry
{
    /** Statuses that mean attestations from this model must no longer be trusted. */
    private const array UNTRUSTED_STATUSES = [
        'REVOKED',
        'ATTESTATION_KEY_COMPROMISE',
        'USER_VERIFICATION_BYPASS',
        'USER_KEY_REMOTE_COMPROMISE',
        'USER_KEY_PHYSICAL_COMPROMISE',
    ];

    /**
     * @param list<string> $rootCertificatesDer DER-encoded attestation root certificates
     * @param list<string> $statuses            status values from the entry's statusReports
     */
    public function __construct(
        public string $aaguid,
        public string $description,
        public array $rootCertificatesDer,
        public array $statuses,
    ) {
    }

    /**
     * The first untrusted status reported for this model, or null.
     */
    public function untrustedStatus(): ?string
    {
        foreach ($this->statuses as $status) {
            if (in_array($status, self::UNTRUSTED_STATUSES, true)) {
                return $status;
            }
        }

        return null;
    }
}

<?php

declare(strict_types=1);

namespace EzPhp\WebauthnMetadata;

/**
 * Decides whether an authenticator's attestation certificate chain leads to a
 * trust anchor FIDO MDS lists for that authenticator's AAGUID, and whether MDS
 * reports the model as compromised or revoked.
 *
 * @package EzPhp\WebauthnMetadata
 */
final class AttestationTrustVerifier
{
    public function __construct(
        private readonly MdsClient $client,
    ) {
    }

    /**
     * @param string       $aaguid  lowercase dashed UUID (see Aaguid::fromBinary())
     * @param list<string> $x5cDer  attestation certificate chain from attStmt['x5c'], leaf first, DER-encoded
     *
     * @throws \EzPhp\WebauthnMetadata\Exception\MetadataException if the blob cannot be obtained/verified
     */
    public function verify(string $aaguid, array $x5cDer, ?\DateTimeImmutable $now = null): TrustDecision
    {
        $now ??= new \DateTimeImmutable();
        $entry = $this->client->blob($now)->findByAaguid($aaguid);

        if ($entry === null) {
            return new TrustDecision(false, "AAGUID {$aaguid} is not listed in FIDO MDS.");
        }

        $status = $entry->untrustedStatus();

        if ($status !== null) {
            return new TrustDecision(false, "FIDO MDS reports status {$status} for this authenticator.", $entry);
        }

        if (!CertificateChain::verifiesTo($x5cDer, $entry->rootCertificatesDer, $now, false)) {
            return new TrustDecision(false, 'Attestation chain does not lead to a FIDO MDS trust anchor for this AAGUID.', $entry);
        }

        return new TrustDecision(true, 'Attestation chain leads to a FIDO MDS trust anchor.', $entry);
    }
}

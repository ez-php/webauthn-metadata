<?php

declare(strict_types=1);

namespace EzPhp\WebauthnMetadata;

/**
 * Signature-chain validation over DER certificates using ext-openssl.
 *
 * Checks that each certificate is currently valid and signed by the next one,
 * and that the last certificate is (or is signed by) one of the given anchors.
 * No revocation checking and no name/EKU policy — scope is deliberately the
 * minimum a trust-anchor lookup needs.
 *
 * @package EzPhp\WebauthnMetadata
 */
final class CertificateChain
{
    /**
     * @param list<string> $chainDer   leaf first, DER-encoded
     * @param list<string> $anchorsDer DER-encoded trust anchors
     * @param bool         $requireCa  demand basicConstraints CA:TRUE on every non-leaf certificate
     */
    public static function verifiesTo(array $chainDer, array $anchorsDer, \DateTimeImmutable $now, bool $requireCa): bool
    {
        if ($chainDer === [] || $anchorsDer === []) {
            return false;
        }

        $certificates = [];

        foreach ($chainDer as $index => $der) {
            // Malformed input is an expected outcome here (returns false), not a warning.
            $certificate = self::readCertificate(self::derToPem($der));

            if ($certificate === false) {
                return false;
            }

            $parsed = openssl_x509_parse($certificate);

            if ($parsed === false
                || $parsed['validFrom_time_t'] > $now->getTimestamp()
                || $parsed['validTo_time_t'] < $now->getTimestamp()
            ) {
                return false;
            }

            if ($requireCa && $index > 0) {
                $constraints = $parsed['extensions']['basicConstraints'] ?? '';

                if (!is_string($constraints) || !str_contains($constraints, 'CA:TRUE')) {
                    return false;
                }
            }

            $certificates[] = $certificate;
        }

        for ($i = 0; $i < count($certificates) - 1; $i++) {
            if (openssl_x509_verify($certificates[$i], $certificates[$i + 1]) !== 1) {
                return false;
            }
        }

        $last = $certificates[count($certificates) - 1];

        foreach ($anchorsDer as $anchorDer) {
            if (hash_equals($anchorDer, $chainDer[count($chainDer) - 1])) {
                return true;
            }

            $anchor = self::readCertificate(self::derToPem($anchorDer));

            if ($anchor !== false && openssl_x509_verify($last, $anchor) === 1) {
                return true;
            }
        }

        return false;
    }

    /**
     * Parse a PEM certificate, turning the warning OpenSSL raises on malformed input
     * into a plain `false` return (an expected outcome here, not an error).
     *
     * @param string $pem
     *
     * @return \OpenSSLCertificate|false
     */
    private static function readCertificate(string $pem): \OpenSSLCertificate|false
    {
        set_error_handler(static fn (): bool => true, E_WARNING);

        try {
            return openssl_x509_read($pem);
        } finally {
            restore_error_handler();
        }
    }

    public static function derToPem(string $der): string
    {
        return "-----BEGIN CERTIFICATE-----\n" . chunk_split(base64_encode($der), 64, "\n") . "-----END CERTIFICATE-----\n";
    }

    /**
     * @throws \InvalidArgumentException if the PEM holds no certificate
     */
    public static function pemToDer(string $pem): string
    {
        if (!str_contains($pem, '-----BEGIN CERTIFICATE-----')) {
            throw new \InvalidArgumentException('Not a valid PEM certificate.');
        }

        $body = preg_replace('/-----(BEGIN|END) CERTIFICATE-----|\s+/', '', $pem);
        $der = is_string($body) ? base64_decode($body, true) : false;

        if ($der === false || $der === '') {
            throw new \InvalidArgumentException('Not a valid PEM certificate.');
        }

        return $der;
    }
}

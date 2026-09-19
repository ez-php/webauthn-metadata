<?php

declare(strict_types=1);

namespace EzPhp\WebauthnMetadata;

use EzPhp\WebauthnMetadata\Exception\BlobVerificationException;

/**
 * Verifies a FIDO MDS3 blob (a compact JWT) and parses its payload.
 *
 * Trust rests on one caller-supplied root certificate (the FIDO MDS root):
 * the JWT's x5c header chain must lead to it, every non-leaf certificate must
 * be a CA, and the JWT signature must verify under the leaf's public key.
 * Only RS256 and ES256 are accepted — `alg` is never taken on faith from a
 * list the attacker controls.
 *
 * @package EzPhp\WebauthnMetadata
 */
final class MetadataBlobVerifier
{
    private readonly string $rootDer;

    /**
     * @param string $rootPem the trusted FIDO MDS root certificate, PEM-encoded
     *
     * @throws \InvalidArgumentException if $rootPem is not a certificate
     */
    public function __construct(string $rootPem)
    {
        $this->rootDer = CertificateChain::pemToDer($rootPem);
    }

    /**
     * @throws BlobVerificationException
     */
    public function verify(string $jwt, \DateTimeImmutable $now): MetadataBlob
    {
        $parts = explode('.', $jwt);

        if (count($parts) !== 3) {
            throw new BlobVerificationException('Metadata blob is not a compact JWT.');
        }

        [$encodedHeader, $encodedPayload, $encodedSignature] = $parts;

        $header = $this->decodeJson($encodedHeader, 'header');
        $algorithm = $header['alg'] ?? null;
        $x5c = $header['x5c'] ?? null;

        if ($algorithm !== 'RS256' && $algorithm !== 'ES256') {
            throw new BlobVerificationException('Metadata blob uses an unsupported JWT algorithm.');
        }

        if (!is_array($x5c) || $x5c === []) {
            throw new BlobVerificationException('Metadata blob JWT has no x5c certificate chain.');
        }

        $chain = [];

        foreach ($x5c as $encodedCertificate) {
            $der = is_string($encodedCertificate) ? base64_decode($encodedCertificate, true) : false;

            if ($der === false || $der === '') {
                throw new BlobVerificationException('Metadata blob x5c contains an invalid certificate.');
            }

            $chain[] = $der;
        }

        if (!CertificateChain::verifiesTo($chain, [$this->rootDer], $now, true)) {
            throw new BlobVerificationException('Metadata blob certificate chain does not lead to the trusted root.');
        }

        $signature = $this->base64UrlDecode($encodedSignature);

        if ($algorithm === 'ES256') {
            $signature = $this->rawToDerSignature($signature);
        }

        $publicKey = openssl_pkey_get_public(CertificateChain::derToPem($chain[0]));

        if ($publicKey === false
            || openssl_verify($encodedHeader . '.' . $encodedPayload, $signature, $publicKey, OPENSSL_ALGO_SHA256) !== 1
        ) {
            throw new BlobVerificationException('Metadata blob JWT signature is invalid.');
        }

        $blob = $this->parsePayload($this->decodeJson($encodedPayload, 'payload'));

        if ($now >= $blob->nextUpdate) {
            throw new BlobVerificationException('Metadata blob is past its nextUpdate date.');
        }

        return $blob;
    }

    /**
     * @param array<mixed> $payload
     */
    private function parsePayload(array $payload): MetadataBlob
    {
        $number = $payload['no'] ?? null;
        $nextUpdateRaw = $payload['nextUpdate'] ?? null;
        $entries = $payload['entries'] ?? null;

        $nextUpdate = is_string($nextUpdateRaw)
            ? \DateTimeImmutable::createFromFormat('!Y-m-d', $nextUpdateRaw, new \DateTimeZone('UTC'))
            : false;

        if (!is_int($number) || $nextUpdate === false || !is_array($entries)) {
            throw new BlobVerificationException('Metadata blob payload is missing no/nextUpdate/entries.');
        }

        $byAaguid = [];

        foreach ($entries as $entry) {
            $parsed = is_array($entry) ? $this->parseEntry($entry) : null;

            if ($parsed !== null) {
                $byAaguid[$parsed->aaguid] = $parsed;
            }
        }

        return new MetadataBlob($number, $nextUpdate, $byAaguid);
    }

    /**
     * Entries without an AAGUID (U2F models, keyed by certificate key
     * identifier) are skipped — see the module CLAUDE.md.
     *
     * @param array<mixed> $entry
     */
    private function parseEntry(array $entry): ?MetadataEntry
    {
        $aaguid = $entry['aaguid'] ?? null;

        if (!is_string($aaguid) || $aaguid === '') {
            return null;
        }

        $statement = is_array($entry['metadataStatement'] ?? null) ? $entry['metadataStatement'] : [];
        $description = is_string($statement['description'] ?? null) ? $statement['description'] : '';

        $roots = [];

        foreach (is_array($statement['attestationRootCertificates'] ?? null) ? $statement['attestationRootCertificates'] : [] as $encoded) {
            $der = is_string($encoded) ? base64_decode($encoded, true) : false;

            if ($der !== false && $der !== '') {
                $roots[] = $der;
            }
        }

        $statuses = [];

        foreach (is_array($entry['statusReports'] ?? null) ? $entry['statusReports'] : [] as $report) {
            if (is_array($report) && is_string($report['status'] ?? null)) {
                $statuses[] = $report['status'];
            }
        }

        return new MetadataEntry(strtolower($aaguid), $description, $roots, $statuses);
    }

    /**
     * @return array<mixed>
     */
    private function decodeJson(string $encoded, string $what): array
    {
        try {
            $decoded = json_decode($this->base64UrlDecode($encoded), true, 512, JSON_THROW_ON_ERROR);
        } catch (\JsonException $e) {
            throw new BlobVerificationException("Metadata blob {$what} is not valid JSON.", previous: $e);
        }

        if (!is_array($decoded)) {
            throw new BlobVerificationException("Metadata blob {$what} is not a JSON object.");
        }

        return $decoded;
    }

    private function base64UrlDecode(string $value): string
    {
        $decoded = base64_decode(strtr($value, '-_', '+/'), true);

        if ($decoded === false) {
            throw new BlobVerificationException('Metadata blob contains invalid base64url data.');
        }

        return $decoded;
    }

    /**
     * ES256 JWT signatures are raw R||S; OpenSSL wants an ASN.1 DER sequence.
     */
    private function rawToDerSignature(string $raw): string
    {
        if (strlen($raw) !== 64) {
            throw new BlobVerificationException('ES256 signature must be 64 bytes.');
        }

        $encodeInteger = static function (string $bytes): string {
            $bytes = ltrim($bytes, "\0");

            if ($bytes === '' || (ord($bytes[0]) & 0x80) !== 0) {
                $bytes = "\0" . $bytes;
            }

            return "\x02" . pack('C', strlen($bytes)) . $bytes;
        };

        $body = $encodeInteger(substr($raw, 0, 32)) . $encodeInteger(substr($raw, 32));

        return "\x30" . pack('C', strlen($body)) . $body;
    }
}

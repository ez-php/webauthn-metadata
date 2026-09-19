<?php

declare(strict_types=1);

namespace Tests\Support;

use OpenSSLAsymmetricKey;

/**
 * Builds signed FIDO-MDS-style JWTs for tests.
 *
 * @package Tests\Support
 */
final class TestJwt
{
    /**
     * @param array<mixed>|string $payload raw string is used verbatim as the payload segment source
     * @param list<string>  $chainDer leaf first
     */
    public static function build(array|string $payload, array $chainDer, OpenSSLAsymmetricKey $leafKey, string $alg = 'ES256'): string
    {
        $header = self::b64(json_encode(['alg' => $alg, 'typ' => 'JWT', 'x5c' => array_map('base64_encode', $chainDer)], JSON_THROW_ON_ERROR));
        $body = self::b64(is_string($payload) ? $payload : json_encode($payload, JSON_THROW_ON_ERROR));

        openssl_sign($header . '.' . $body, $signature, $leafKey, OPENSSL_ALGO_SHA256);

        if ($alg === 'ES256') {
            $signature = self::derToRaw($signature);
        }

        return $header . '.' . $body . '.' . self::b64($signature);
    }

    public static function b64(string $value): string
    {
        return rtrim(strtr(base64_encode($value), '+/', '-_'), '=');
    }

    /**
     * @return array<mixed>
     */
    public static function payload(string $aaguid, string $rootDer, string $nextUpdate = '2999-01-01', string $status = 'FIDO_CERTIFIED_L1'): array
    {
        return [
            'no' => 7,
            'nextUpdate' => $nextUpdate,
            'entries' => [
                [
                    'aaguid' => $aaguid,
                    'metadataStatement' => [
                        'description' => 'Test Key',
                        'attestationRootCertificates' => [base64_encode($rootDer)],
                    ],
                    'statusReports' => [['status' => $status]],
                ],
                ['attestationCertificateKeyIdentifiers' => ['abcd'], 'statusReports' => [['status' => 'NOT_FIDO_CERTIFIED']]],
            ],
        ];
    }

    private static function derToRaw(string $der): string
    {
        $offset = 2;
        $raw = '';

        for ($i = 0; $i < 2; $i++) {
            $length = ord($der[$offset + 1]);
            $raw .= str_pad(ltrim(substr($der, $offset + 2, $length), "\0"), 32, "\0", STR_PAD_LEFT);
            $offset += 2 + $length;
        }

        return $raw;
    }
}

<?php

declare(strict_types=1);

namespace Tests\Support;

use OpenSSLAsymmetricKey;
use OpenSSLCertificate;

/**
 * Generates throw-away certificates for chain-validation tests.
 *
 * @package Tests\Support
 */
final class TestPki
{
    private static ?string $config = null;

    public static function key(bool $rsa = false): OpenSSLAsymmetricKey
    {
        $key = openssl_pkey_new($rsa
            ? ['private_key_type' => OPENSSL_KEYTYPE_RSA, 'private_key_bits' => 2048, 'config' => self::config()]
            : ['private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => 'prime256v1', 'config' => self::config()]);

        if ($key === false) {
            throw new \RuntimeException('Could not generate a test key.');
        }

        return $key;
    }

    /**
     * @param array{cert: OpenSSLCertificate, key: OpenSSLAsymmetricKey}|null $issuer null = self-signed
     *
     * @return array{cert: OpenSSLCertificate, key: OpenSSLAsymmetricKey}
     */
    public static function issue(string $commonName, ?array $issuer, bool $ca, bool $rsa = false): array
    {
        $key = self::key($rsa);
        $options = ['config' => self::config(), 'digest_alg' => 'sha256', 'x509_extensions' => $ca ? 'v3_ca' : 'v3_leaf'];
        $csr = openssl_csr_new(['commonName' => $commonName], $key, $options);

        if (!$csr instanceof \OpenSSLCertificateSigningRequest) {
            throw new \RuntimeException('Could not create a test CSR.');
        }

        $certificate = openssl_csr_sign($csr, $issuer['cert'] ?? null, $issuer['key'] ?? $key, 365, $options, random_int(1, PHP_INT_MAX));

        if ($certificate === false) {
            throw new \RuntimeException('Could not sign a test certificate.');
        }

        return ['cert' => $certificate, 'key' => $key];
    }

    public static function der(OpenSSLCertificate $certificate): string
    {
        openssl_x509_export($certificate, $pem);

        return self::pemToDer($pem);
    }

    public static function pem(OpenSSLCertificate $certificate): string
    {
        openssl_x509_export($certificate, $pem);

        return $pem;
    }

    private static function pemToDer(string $pem): string
    {
        return (string) base64_decode((string) preg_replace('/-----(BEGIN|END) CERTIFICATE-----|\s+/', '', $pem), true);
    }

    private static function config(): string
    {
        if (self::$config === null) {
            $path = sys_get_temp_dir() . '/ez-php-webauthn-metadata-openssl-' . bin2hex(random_bytes(4)) . '.cnf';
            file_put_contents($path, "[req]\ndistinguished_name=dn\n[dn]\n[v3_ca]\nbasicConstraints=critical,CA:TRUE\n[v3_leaf]\nbasicConstraints=CA:FALSE\n");
            register_shutdown_function(static fn () => @unlink($path));
            self::$config = $path;
        }

        return self::$config;
    }
}

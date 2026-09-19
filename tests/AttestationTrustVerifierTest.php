<?php

declare(strict_types=1);

namespace Tests;

use EzPhp\WebauthnMetadata\AttestationTrustVerifier;
use EzPhp\WebauthnMetadata\MdsClient;
use EzPhp\WebauthnMetadata\MetadataBlobVerifier;
use Tests\Support\ArrayBlobCache;
use Tests\Support\FakeBlobFetcher;
use Tests\Support\TestJwt;
use Tests\Support\TestPki;

/**
 * @package Tests
 */
final class AttestationTrustVerifierTest extends TestCase
{
    private const string AAGUID = '00112233-4455-6677-8899-aabbccddeeff';

    /** @var array{cert: \OpenSSLCertificate, key: \OpenSSLAsymmetricKey} */
    private array $vendorRoot;

    /** @var array{cert: \OpenSSLCertificate, key: \OpenSSLAsymmetricKey} */
    private array $attestation;

    private string $mdsRootPem;

    /** @var array{cert: \OpenSSLCertificate, key: \OpenSSLAsymmetricKey} */
    private array $mdsSigner;

    protected function setUp(): void
    {
        $mdsRoot = TestPki::issue('FIDO Root', null, true);
        $this->mdsSigner = TestPki::issue('MDS Signer', $mdsRoot, false);
        $this->mdsRootPem = TestPki::pem($mdsRoot['cert']);
        $this->vendorRoot = TestPki::issue('Vendor Root', null, true);
        $this->attestation = TestPki::issue('Attestation', $this->vendorRoot, false);
    }

    private function verifier(string $status = 'FIDO_CERTIFIED_L1', ?string $anchorDer = null): AttestationTrustVerifier
    {
        $jwt = TestJwt::build(
            TestJwt::payload(self::AAGUID, $anchorDer ?? TestPki::der($this->vendorRoot['cert']), '2999-01-01', $status),
            [TestPki::der($this->mdsSigner['cert'])],
            $this->mdsSigner['key'],
        );

        return new AttestationTrustVerifier(new MdsClient(new FakeBlobFetcher($jwt), new ArrayBlobCache(), new MetadataBlobVerifier($this->mdsRootPem)));
    }

    public function testChainToListedAnchorIsTrusted(): void
    {
        $decision = $this->verifier()->verify(self::AAGUID, [TestPki::der($this->attestation['cert'])]);

        self::assertTrue($decision->trusted);
        self::assertSame('Test Key', $decision->entry?->description);
    }

    public function testUnlistedAaguidIsUntrusted(): void
    {
        $decision = $this->verifier()->verify('ffffffff-0000-0000-0000-000000000000', [TestPki::der($this->attestation['cert'])]);

        self::assertFalse($decision->trusted);
        self::assertNull($decision->entry);
        self::assertStringContainsString('not listed', $decision->reason);
    }

    public function testRevokedModelIsUntrustedEvenWithValidChain(): void
    {
        $decision = $this->verifier('REVOKED')->verify(self::AAGUID, [TestPki::der($this->attestation['cert'])]);

        self::assertFalse($decision->trusted);
        self::assertStringContainsString('REVOKED', $decision->reason);
    }

    public function testChainNotLeadingToListedAnchorIsUntrusted(): void
    {
        $otherRoot = TestPki::issue('Other Vendor', null, true);
        $decision = $this->verifier(anchorDer: TestPki::der($otherRoot['cert']))->verify(self::AAGUID, [TestPki::der($this->attestation['cert'])]);

        self::assertFalse($decision->trusted);
        self::assertStringContainsString('trust anchor', $decision->reason);
    }
}

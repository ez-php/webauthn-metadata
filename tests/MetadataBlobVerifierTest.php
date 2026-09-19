<?php

declare(strict_types=1);

namespace Tests;

use EzPhp\WebauthnMetadata\Exception\BlobVerificationException;
use EzPhp\WebauthnMetadata\MetadataBlobVerifier;
use Tests\Support\TestJwt;
use Tests\Support\TestPki;

/**
 * @package Tests
 */
final class MetadataBlobVerifierTest extends TestCase
{
    private const string AAGUID = '00112233-4455-6677-8899-aabbccddeeff';

    /** @var array{cert: \OpenSSLCertificate, key: \OpenSSLAsymmetricKey} */
    private array $root;

    /** @var array{cert: \OpenSSLCertificate, key: \OpenSSLAsymmetricKey} */
    private array $leaf;

    private string $rootDer;

    protected function setUp(): void
    {
        $this->root = TestPki::issue('FIDO Root', null, true);
        $this->leaf = TestPki::issue('MDS Signer', $this->root, false);
        $this->rootDer = TestPki::der($this->root['cert']);
    }

    private function verifier(): MetadataBlobVerifier
    {
        return new MetadataBlobVerifier(TestPki::pem($this->root['cert']));
    }

    /**
     * @param array<mixed>|null $payload
     */
    private function jwt(?array $payload = null, string $alg = 'ES256'): string
    {
        return TestJwt::build($payload ?? TestJwt::payload(self::AAGUID, $this->rootDer), [TestPki::der($this->leaf['cert'])], $this->leaf['key'], $alg);
    }

    public function testVerifiesEs256BlobAndParsesEntries(): void
    {
        $blob = $this->verifier()->verify($this->jwt(), new \DateTimeImmutable());

        self::assertSame(7, $blob->number);
        self::assertSame(1, $blob->count(), 'entry without an AAGUID is skipped');
        self::assertSame('2999-01-01', $blob->nextUpdate->format('Y-m-d'));

        $entry = $blob->findByAaguid(strtoupper(self::AAGUID));
        self::assertNotNull($entry);
        self::assertSame('Test Key', $entry->description);
        self::assertSame([$this->rootDer], $entry->rootCertificatesDer);
        self::assertSame(['FIDO_CERTIFIED_L1'], $entry->statuses);
        self::assertNull($blob->findByAaguid('ffffffff-0000-0000-0000-000000000000'));
    }

    public function testVerifiesRs256BlobThroughIntermediate(): void
    {
        $intermediate = TestPki::issue('Int', $this->root, true, rsa: true);
        $leaf = TestPki::issue('Signer', $intermediate, false, rsa: true);
        $jwt = TestJwt::build(
            TestJwt::payload(self::AAGUID, $this->rootDer),
            [TestPki::der($leaf['cert']), TestPki::der($intermediate['cert'])],
            $leaf['key'],
            'RS256',
        );

        self::assertSame(1, $this->verifier()->verify($jwt, new \DateTimeImmutable())->count());
    }

    public function testEs256SignaturesWithVaryingIntegerLengthsVerify(): void
    {
        $verifier = $this->verifier();

        for ($i = 0; $i < 25; $i++) {
            $payload = TestJwt::payload(self::AAGUID, $this->rootDer);
            $payload['no'] = $i + 1;

            self::assertSame($i + 1, $verifier->verify($this->jwt($payload), new \DateTimeImmutable())->number);
        }
    }

    public function testRejectsChainToAnotherRoot(): void
    {
        $other = TestPki::issue('Other Root', null, true);

        $this->expectException(BlobVerificationException::class);
        $this->expectExceptionMessage('trusted root');

        (new MetadataBlobVerifier(TestPki::pem($other['cert'])))->verify($this->jwt(), new \DateTimeImmutable());
    }

    public function testRejectsNonCaIntermediate(): void
    {
        $notCa = TestPki::issue('NotCA', $this->root, false);
        $leaf = TestPki::issue('Signer', $notCa, false);
        $jwt = TestJwt::build(TestJwt::payload(self::AAGUID, $this->rootDer), [TestPki::der($leaf['cert']), TestPki::der($notCa['cert'])], $leaf['key']);

        $this->expectException(BlobVerificationException::class);

        $this->verifier()->verify($jwt, new \DateTimeImmutable());
    }

    public function testRejectsTamperedPayload(): void
    {
        $genuine = explode('.', $this->jwt());
        $forged = explode('.', $this->jwt(TestJwt::payload('ffffffff-0000-0000-0000-000000000000', $this->rootDer)));

        $this->expectException(BlobVerificationException::class);
        $this->expectExceptionMessage('signature');

        $this->verifier()->verify($genuine[0] . '.' . $forged[1] . '.' . $genuine[2], new \DateTimeImmutable());
    }

    public function testRejectsSignatureFromDifferentKeyThanCertificate(): void
    {
        $imposter = TestPki::key();
        $jwt = TestJwt::build(TestJwt::payload(self::AAGUID, $this->rootDer), [TestPki::der($this->leaf['cert'])], $imposter);

        $this->expectException(BlobVerificationException::class);
        $this->expectExceptionMessage('signature');

        $this->verifier()->verify($jwt, new \DateTimeImmutable());
    }

    public function testRejectsBlobPastNextUpdate(): void
    {
        $this->expectException(BlobVerificationException::class);
        $this->expectExceptionMessage('nextUpdate');

        $this->verifier()->verify($this->jwt(TestJwt::payload(self::AAGUID, $this->rootDer, '2020-01-01')), new \DateTimeImmutable());
    }

    public function testRejectsExpiredSignerCertificate(): void
    {
        $this->expectException(BlobVerificationException::class);

        $this->verifier()->verify($this->jwt(), new \DateTimeImmutable('+3 years'));
    }

    public function testRejectsUnsupportedAlgorithm(): void
    {
        $header = TestJwt::b64('{"alg":"none","x5c":["AA=="]}');

        $this->expectException(BlobVerificationException::class);
        $this->expectExceptionMessage('algorithm');

        $this->verifier()->verify($header . '.' . TestJwt::b64('{}') . '.', new \DateTimeImmutable());
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function malformedJwts(): iterable
    {
        yield 'two parts' => ['a.b'];
        yield 'header not json' => [TestJwt::b64('nope') . '.e30.AA'];
        yield 'header not object' => [TestJwt::b64('"str"') . '.e30.AA'];
        yield 'bad base64' => ['!!!.e30.AA'];
        yield 'missing x5c' => [TestJwt::b64('{"alg":"ES256"}') . '.e30.AA'];
        yield 'x5c not certificates' => [TestJwt::b64('{"alg":"ES256","x5c":[1]}') . '.e30.AA'];
    }

    #[\PHPUnit\Framework\Attributes\DataProvider('malformedJwts')]
    public function testRejectsMalformedJwt(string $jwt): void
    {
        $this->expectException(BlobVerificationException::class);

        $this->verifier()->verify($jwt, new \DateTimeImmutable());
    }

    public function testRejectsShortEs256Signature(): void
    {
        [$header, $payload] = explode('.', $this->jwt());

        $this->expectException(BlobVerificationException::class);
        $this->expectExceptionMessage('64 bytes');

        $this->verifier()->verify($header . '.' . $payload . '.' . TestJwt::b64('short'), new \DateTimeImmutable());
    }

    public function testRejectsPayloadMissingRequiredFields(): void
    {
        $this->expectException(BlobVerificationException::class);
        $this->expectExceptionMessage('no/nextUpdate/entries');

        $this->verifier()->verify($this->jwt(['no' => 1]), new \DateTimeImmutable());
    }

    public function testRejectsSignedPayloadThatIsNotJson(): void
    {
        $jwt = TestJwt::build('not json', [TestPki::der($this->leaf['cert'])], $this->leaf['key']);

        $this->expectException(BlobVerificationException::class);
        $this->expectExceptionMessage('not valid JSON');

        $this->verifier()->verify($jwt, new \DateTimeImmutable());
    }

    public function testInvalidRootPemThrows(): void
    {
        $this->expectException(\InvalidArgumentException::class);

        new MetadataBlobVerifier('garbage');
    }
}

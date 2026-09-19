<?php

declare(strict_types=1);

namespace Tests;

use EzPhp\WebauthnMetadata\CertificateChain;
use Tests\Support\TestPki;

/**
 * @package Tests
 */
final class CertificateChainTest extends TestCase
{
    public function testLeafSignedByAnchorVerifies(): void
    {
        $root = TestPki::issue('Root', null, true);
        $leaf = TestPki::issue('Leaf', $root, false);

        self::assertTrue(CertificateChain::verifiesTo([TestPki::der($leaf['cert'])], [TestPki::der($root['cert'])], new \DateTimeImmutable(), true));
    }

    public function testChainThroughIntermediateVerifies(): void
    {
        $root = TestPki::issue('Root', null, true);
        $intermediate = TestPki::issue('Int', $root, true);
        $leaf = TestPki::issue('Leaf', $intermediate, false);
        $chain = [TestPki::der($leaf['cert']), TestPki::der($intermediate['cert'])];

        self::assertTrue(CertificateChain::verifiesTo($chain, [TestPki::der($root['cert'])], new \DateTimeImmutable(), true));
    }

    public function testChainEndingInTheAnchorItselfVerifies(): void
    {
        $root = TestPki::issue('Root', null, true);
        $leaf = TestPki::issue('Leaf', $root, false);
        $chain = [TestPki::der($leaf['cert']), TestPki::der($root['cert'])];

        self::assertTrue(CertificateChain::verifiesTo($chain, [TestPki::der($root['cert'])], new \DateTimeImmutable(), true));
    }

    public function testUnrelatedAnchorFails(): void
    {
        $root = TestPki::issue('Root', null, true);
        $other = TestPki::issue('Other', null, true);
        $leaf = TestPki::issue('Leaf', $root, false);

        self::assertFalse(CertificateChain::verifiesTo([TestPki::der($leaf['cert'])], [TestPki::der($other['cert'])], new \DateTimeImmutable(), true));
    }

    public function testBrokenLinkFails(): void
    {
        $root = TestPki::issue('Root', null, true);
        $stranger = TestPki::issue('Stranger', null, true);
        $leaf = TestPki::issue('Leaf', $root, false);
        $chain = [TestPki::der($leaf['cert']), TestPki::der($stranger['cert'])];

        self::assertFalse(CertificateChain::verifiesTo($chain, [TestPki::der($stranger['cert'])], new \DateTimeImmutable(), true));
    }

    public function testNonCaIntermediateIsRejectedOnlyWhenCaIsRequired(): void
    {
        $root = TestPki::issue('Root', null, true);
        $notCa = TestPki::issue('NotCA', $root, false);
        $leaf = TestPki::issue('Leaf', $notCa, false);
        $chain = [TestPki::der($leaf['cert']), TestPki::der($notCa['cert'])];
        $anchors = [TestPki::der($root['cert'])];

        self::assertFalse(CertificateChain::verifiesTo($chain, $anchors, new \DateTimeImmutable(), true));
        self::assertTrue(CertificateChain::verifiesTo($chain, $anchors, new \DateTimeImmutable(), false));
    }

    public function testExpiredAndNotYetValidCertificatesFail(): void
    {
        $root = TestPki::issue('Root', null, true);
        $leaf = TestPki::issue('Leaf', $root, false);
        $chain = [TestPki::der($leaf['cert'])];
        $anchors = [TestPki::der($root['cert'])];

        self::assertFalse(CertificateChain::verifiesTo($chain, $anchors, new \DateTimeImmutable('+3 years'), true));
        self::assertFalse(CertificateChain::verifiesTo($chain, $anchors, new \DateTimeImmutable('-1 day'), true));
    }

    public function testEmptyInputsAndGarbageFail(): void
    {
        $now = new \DateTimeImmutable();

        self::assertFalse(CertificateChain::verifiesTo([], ['x'], $now, true));
        self::assertFalse(CertificateChain::verifiesTo(['x'], [], $now, true));
        self::assertFalse(CertificateChain::verifiesTo(['not a certificate'], ['x'], $now, true));
    }

    public function testPemDerRoundTrip(): void
    {
        $root = TestPki::issue('Root', null, true);
        $der = TestPki::der($root['cert']);

        self::assertSame($der, CertificateChain::pemToDer(CertificateChain::derToPem($der)));
        self::assertSame($der, CertificateChain::pemToDer(TestPki::pem($root['cert'])));
    }

    public function testInvalidPemThrows(): void
    {
        $this->expectException(\InvalidArgumentException::class);

        CertificateChain::pemToDer('-----BEGIN CERTIFICATE-----!!!-----END CERTIFICATE-----');
    }
}

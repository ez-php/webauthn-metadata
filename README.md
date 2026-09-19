# ez-php/webauthn-metadata

FIDO Metadata Service (MDS3) trust-anchor lookups for [`ez-php/webauthn`](https://github.com/ez-php/webauthn):
download and cryptographically verify the MDS blob, cache it, and decide whether an authenticator's
attestation chain leads to a trust anchor FIDO lists for its AAGUID.

`ez-php/webauthn` deliberately makes no network calls, so its `AttestationResult::$trusted` only reflects
signature validity. This module is the optional, separate check that adds "is this a known, non-revoked
authenticator model?".

---

## Installation

```bash
composer require ez-php/webauthn-metadata
```

Requires `ext-openssl`, `ext-curl`, `ext-json`.

---

## Usage

```php
use EzPhp\WebauthnMetadata\{Aaguid, AttestationTrustVerifier, CurlBlobFetcher, FileBlobCache, MdsClient, MetadataBlobVerifier};

// The FIDO MDS root certificate (PEM) is supplied by you — it is never bundled.
$verifier = new MetadataBlobVerifier(file_get_contents('/etc/app/fido-mds-root.pem'));

$client = new MdsClient(new CurlBlobFetcher(), new FileBlobCache('/var/cache/app/mds.jwt'), $verifier);

$trust = new AttestationTrustVerifier($client);

// aaguid: raw 16 bytes from authenticatorData; x5c: attStmt['x5c'] (DER strings, leaf first)
$decision = $trust->verify(Aaguid::fromBinary($aaguidBytes), $x5c);

if (!$decision->trusted) {
    // $decision->reason explains why; $decision->entry is the matched MDS entry, if any
}
```

The blob is re-verified on every load (the cache is not trusted) and refreshed once it passes `nextUpdate`.
A download or verification failure throws a `MetadataException` — it never falls back to a stale blob.

---

## What is checked

- The MDS JWT: `x5c` chain to your root (CA constraints, validity), RS256/ES256 signature, `nextUpdate`.
- The attestation chain: validity, signature links, and a match against the entry's attestation roots.
- MDS status: `REVOKED`, `ATTESTATION_KEY_COMPROMISE`, `USER_VERIFICATION_BYPASS`, `USER_KEY_REMOTE_COMPROMISE`,
  `USER_KEY_PHYSICAL_COMPROMISE` make a model untrusted.

Not covered: CRL/OCSP revocation, U2F-only entries (no AAGUID).

Bring your own transport by implementing `BlobFetcherInterface`, and your own storage via `BlobCacheInterface`.

---

## Quality

```bash
composer full   # PHPStan level 9, php-cs-fixer, PHPUnit
```

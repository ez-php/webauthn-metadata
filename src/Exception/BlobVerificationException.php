<?php

declare(strict_types=1);

namespace EzPhp\WebauthnMetadata\Exception;

/**
 * The metadata blob is malformed, expired, or failed signature / chain
 * verification. A blob that raises this must never be used or cached.
 *
 * @package EzPhp\WebauthnMetadata\Exception
 */
final class BlobVerificationException extends MetadataException
{
}

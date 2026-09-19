<?php

declare(strict_types=1);

namespace EzPhp\WebauthnMetadata\Exception;

/**
 * Base type for every exception this module throws. Concrete subclasses are
 * final; this base exists specifically to be extended (documented
 * exception-hierarchy carve-out per root CLAUDE.md).
 *
 * @package EzPhp\WebauthnMetadata\Exception
 */
abstract class MetadataException extends \RuntimeException
{
}

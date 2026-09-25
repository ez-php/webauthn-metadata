<?php

declare(strict_types=1);

namespace EzPhp\WebauthnMetadata;

/**
 * Single-file blob cache. Writes are atomic (temp file + rename).
 *
 * @package EzPhp\WebauthnMetadata
 */
final class FileBlobCache implements BlobCacheInterface
{
    /**
     * FileBlobCache Constructor
     *
     * @param string $path
     */
    public function __construct(
        private readonly string $path,
    ) {
    }

    /**
     * {@inheritDoc}
     */
    public function get(): ?string
    {
        if (!is_file($this->path)) {
            return null;
        }

        $contents = file_get_contents($this->path);

        return is_string($contents) && $contents !== '' ? $contents : null;
    }

    /**
     * {@inheritDoc}
     */
    public function put(string $jwt): void
    {
        $directory = dirname($this->path);

        if (!is_dir($directory) && !self::quietly(static fn (): bool => mkdir($directory, 0o775, true)) && !is_dir($directory)) {
            throw new \RuntimeException("Cannot create cache directory {$directory}.");
        }

        $temporary = $this->path . '.' . bin2hex(random_bytes(4)) . '.tmp';

        if (
            self::quietly(static fn (): int|false => file_put_contents($temporary, $jwt)) === false
            || !self::quietly(fn (): bool => rename($temporary, $this->path))
        ) {
            self::quietly(static fn (): bool => unlink($temporary));

            throw new \RuntimeException("Cannot write metadata cache {$this->path}.");
        }
    }

    /**
     * Run a call whose PHP warning is expected and handled through its return value,
     * without the `@` operator.
     *
     * @template T
     *
     * @param callable(): T $fn
     *
     * @return T
     */
    private static function quietly(callable $fn)
    {
        set_error_handler(static fn (): bool => true, E_WARNING);

        try {
            return $fn();
        } finally {
            restore_error_handler();
        }
    }
}

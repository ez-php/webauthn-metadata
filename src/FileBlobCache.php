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
    public function __construct(
        private readonly string $path,
    ) {
    }

    public function get(): ?string
    {
        if (!is_file($this->path)) {
            return null;
        }

        $contents = file_get_contents($this->path);

        return is_string($contents) && $contents !== '' ? $contents : null;
    }

    public function put(string $jwt): void
    {
        $directory = dirname($this->path);

        if (!is_dir($directory) && !@mkdir($directory, 0o775, true) && !is_dir($directory)) {
            throw new \RuntimeException("Cannot create cache directory {$directory}.");
        }

        $temporary = $this->path . '.' . bin2hex(random_bytes(4)) . '.tmp';

        if (@file_put_contents($temporary, $jwt) === false || !@rename($temporary, $this->path)) {
            @unlink($temporary);

            throw new \RuntimeException("Cannot write metadata cache {$this->path}.");
        }
    }
}

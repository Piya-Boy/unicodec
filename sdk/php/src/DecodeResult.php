<?php

declare(strict_types=1);

namespace Ubc;

/** Decoded plaintext and its metadata entries. */
final class DecodeResult
{
    /**
     * @param MetadataEntry[] $metadata
     */
    public function __construct(
        public readonly string $data,
        public readonly array $metadata,
    ) {
    }
}

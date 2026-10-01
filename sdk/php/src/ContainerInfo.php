<?php

declare(strict_types=1);

namespace Ubc;

/** Header and metadata summary returned by Streaming::inspect(). */
final class ContainerInfo
{
    /**
     * @param MetadataEntry[] $metadata
     */
    public function __construct(
        public readonly int $version,
        public readonly bool $encrypted,
        public readonly bool $hasMetadata,
        public readonly int $hashAlgo,
        public readonly int $aeadAlgo,
        public readonly int $chunkSize,
        public readonly int $chunkCount,
        public readonly int $totalSize,
        public readonly array $metadata,
    ) {
    }
}

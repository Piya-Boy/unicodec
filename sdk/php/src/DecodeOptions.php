<?php

declare(strict_types=1);

namespace Ubc;

/** Resource limits applied while decoding untrusted containers. */
final class DecodeOptions
{
    public const int DEFAULT_MAX_META_BYTES = 16 << 20;
    public const int DEFAULT_MAX_CHUNK_LEN = 64 << 20;
    public const int DEFAULT_MAX_CHUNK_COUNT = 1 << 20;
    public const int DEFAULT_MAX_TOTAL_SIZE = 1 << 30;

    public function __construct(
        public readonly int $maxMetaBytes = self::DEFAULT_MAX_META_BYTES,
        public readonly int $maxChunkLen = self::DEFAULT_MAX_CHUNK_LEN,
        public readonly int $maxChunkCount = self::DEFAULT_MAX_CHUNK_COUNT,
        public readonly int $maxTotalSize = self::DEFAULT_MAX_TOTAL_SIZE,
        public readonly ?string $key = null,
    ) {
        if ($maxMetaBytes < 0 || $maxChunkLen < 0 || $maxChunkCount < 0 || $maxTotalSize < 0) {
            throw new \InvalidArgumentException('decode limits must be non-negative');
        }
    }

    public function withKey(?string $key): self
    {
        return new self($this->maxMetaBytes, $this->maxChunkLen, $this->maxChunkCount, $this->maxTotalSize, $key);
    }
}

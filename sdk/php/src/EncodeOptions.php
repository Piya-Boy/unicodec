<?php

declare(strict_types=1);

namespace Ubc;

/**
 * Options for a streaming Encoder. baseNonce exists only for deterministic conformance
 * tests; production callers must leave it null so a CSPRNG nonce is generated.
 */
final class EncodeOptions
{
    public function __construct(
        public readonly int $chunkSize = Payload::DEFAULT_CHUNK_SIZE,
        public readonly ?string $key = null,
        public readonly ?string $baseNonce = null,
    ) {
        if ($chunkSize <= 0 || $chunkSize > 0xFFFF_FFFF) {
            throw new UbcException(ErrorCode::ReservedBits);
        }
        if ($key !== null && strlen($key) !== 32) {
            throw new UbcException(ErrorCode::ReservedBits);
        }
        if ($baseNonce !== null && strlen($baseNonce) !== 12) {
            throw new UbcException(ErrorCode::ReservedBits);
        }
        if ($key === null && $baseNonce !== null) {
            throw new UbcException(ErrorCode::ReservedBits);
        }
    }

    public function withKey(?string $key): self
    {
        return new self($this->chunkSize, $key, $this->baseNonce);
    }

    public function withChunkSize(int $chunkSize): self
    {
        return new self($chunkSize, $this->key, $this->baseNonce);
    }
}

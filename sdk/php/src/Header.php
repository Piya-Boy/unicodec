<?php

declare(strict_types=1);

namespace Ubc;

/**
 * UBC v1 fixed 40-byte header (SPEC.md section 2.1).
 *
 * PHP has no native uint64 type; chunk_count/total_size are stored as PHP's signed 64-bit
 * int. Real-world payloads never approach 2^63 bytes, so — matching the Java port's
 * documented tradeoff — every bit pattern is treated as structurally valid (no range
 * rejection), but magnitude comparisons use plain signed operators rather than a hand-rolled
 * unsigned-compare helper; values above PHP_INT_MAX cannot be represented at all.
 */
final class Header
{
    public const int SIZE = 40;
    public const int VERSION = 1;

    public const int HASH_SHA256 = 0;
    public const int HASH_HMAC_SHA256 = 1;
    public const int AEAD_NONE = 0;
    public const int AEAD_AES_256_GCM = 1;

    public const int FLAG_ENCRYPTED = 1;
    public const int FLAG_HAS_METADATA = 1 << 1;

    private const string MAGIC = 'UBC1';
    private const int ALLOWED_FLAGS = self::FLAG_ENCRYPTED | self::FLAG_HAS_METADATA;
    private const int MAX_ENCRYPTED_CHUNK_SIZE = 0xFFFF_FFEF;

    public readonly string $baseNonce;

    public function __construct(
        public readonly int $flags,
        public readonly int $hashAlgo,
        public readonly int $aeadAlgo,
        public readonly int $chunkSize,
        public readonly int $chunkCount,
        public readonly int $totalSize,
        string $baseNonce,
    ) {
        $this->baseNonce = $baseNonce;
        $this->validate();
    }

    public function encrypted(): bool
    {
        return ($this->flags & self::FLAG_ENCRYPTED) !== 0;
    }

    public function hasMetadata(): bool
    {
        return ($this->flags & self::FLAG_HAS_METADATA) !== 0;
    }

    public function toBytes(): string
    {
        return self::MAGIC
            . pack('CCCC', self::VERSION, $this->flags, $this->hashAlgo, $this->aeadAlgo)
            . pack('V', $this->chunkSize)
            . pack('P', $this->chunkCount)
            . pack('P', $this->totalSize)
            . $this->baseNonce;
    }

    public static function parse(string $data, int $offset = 0): self
    {
        if (strlen($data) - $offset < self::SIZE) {
            throw new UbcException(ErrorCode::Truncated);
        }
        if (substr($data, $offset, 4) !== self::MAGIC) {
            throw new UbcException(ErrorCode::BadMagic);
        }

        $version = ord($data[$offset + 4]);
        $flags = ord($data[$offset + 5]);
        $hashAlgo = ord($data[$offset + 6]);
        $aeadAlgo = ord($data[$offset + 7]);
        $chunkSize = unpack('V', $data, $offset + 8)[1];
        $chunkCount = unpack('P', $data, $offset + 12)[1];
        $totalSize = unpack('P', $data, $offset + 20)[1];
        $baseNonce = substr($data, $offset + 28, 12);

        if ($version !== self::VERSION) {
            throw new UbcException(ErrorCode::UnsupportedVersion);
        }
        return new self($flags, $hashAlgo, $aeadAlgo, $chunkSize, $chunkCount, $totalSize, $baseNonce);
    }

    private function validate(): void
    {
        if ($this->hashAlgo !== self::HASH_SHA256 && $this->hashAlgo !== self::HASH_HMAC_SHA256) {
            throw new UbcException(ErrorCode::UnsupportedAlgorithm);
        }
        if ($this->aeadAlgo !== self::AEAD_NONE && $this->aeadAlgo !== self::AEAD_AES_256_GCM) {
            throw new UbcException(ErrorCode::UnsupportedAlgorithm);
        }
        if (($this->flags & ~self::ALLOWED_FLAGS) !== 0) {
            throw new UbcException(ErrorCode::ReservedBits);
        }
        if ($this->chunkSize < 0 || $this->chunkSize > 0xFFFF_FFFF) {
            throw new UbcException(ErrorCode::ReservedBits);
        }
        if (strlen($this->baseNonce) !== 12) {
            throw new UbcException(ErrorCode::ReservedBits);
        }

        if ($this->encrypted()) {
            if ($this->aeadAlgo !== self::AEAD_AES_256_GCM
                || $this->hashAlgo !== self::HASH_HMAC_SHA256
                || $this->chunkSize === 0
                || $this->chunkSize > self::MAX_ENCRYPTED_CHUNK_SIZE
            ) {
                throw new UbcException(ErrorCode::ReservedBits);
            }
            return;
        }
        if ($this->aeadAlgo !== self::AEAD_NONE
            || $this->hashAlgo !== self::HASH_SHA256
            || $this->chunkSize === 0
            || $this->baseNonce !== "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        ) {
            throw new UbcException(ErrorCode::ReservedBits);
        }
    }
}

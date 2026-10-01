<?php

declare(strict_types=1);

namespace Ubc;

/** One-shot AES-256-GCM encrypted UBC v1 encoding and decoding (SPEC.md sections 3-4). */
final class Crypto
{
    private const int KEY_SIZE = 32;
    private const int NONCE_SIZE = 12;
    private const int FOOTER_SIZE = 36;
    private const string FOOTER_MAGIC = 'UBCE';

    private function __construct()
    {
    }

    /** Encodes with a CSPRNG-generated base_nonce. Production callers MUST use this. */
    public static function encodeEncrypted(string $data, string $key, array $entries, int $chunkSize): string
    {
        $baseNonce = random_bytes(self::NONCE_SIZE);
        return self::encodeEncryptedWithFixedNonce($data, $key, $baseNonce, $entries, $chunkSize);
    }

    /** Deterministic encoding for conformance vectors/tests only — never reuse a base_nonce in production. */
    public static function encodeEncryptedWithFixedNonce(
        string $data,
        string $key,
        string $baseNonce,
        array $entries,
        int $chunkSize,
    ): string {
        self::validateEncodeKey($key);
        if (strlen($baseNonce) !== self::NONCE_SIZE) {
            throw new UbcException(ErrorCode::ReservedBits);
        }
        if ($chunkSize <= 0 || $chunkSize > 0xFFFF_FFEF) {
            throw new \InvalidArgumentException('chunkSize must be a positive uint32 <= 0xffff_ffef when encrypted');
        }

        $metadata = Metadata::encode($entries);
        $dataLength = strlen($data);
        $chunkCount = $dataLength === 0 ? 0 : intdiv($dataLength + $chunkSize - 1, $chunkSize);

        $header = new Header(
            Header::FLAG_ENCRYPTED | ($metadata !== '' ? Header::FLAG_HAS_METADATA : 0),
            Header::HASH_HMAC_SHA256,
            Header::AEAD_AES_256_GCM,
            $chunkSize,
            $chunkCount,
            $dataLength,
            $baseNonce,
        );
        $headerBytes = $header->toBytes();
        $metadataDigest = CryptoInternal::sha256($metadata);

        $root = RootAccumulator::keyed(CryptoInternal::rootKey($key, $baseNonce));
        $root->update($headerBytes);
        $root->update($metadata);

        $output = $headerBytes . $metadata;
        $index = 0;
        for ($offset = 0; $offset < $dataLength; $offset += $chunkSize, $index++) {
            $length = min($chunkSize, $dataLength - $offset);
            $chunk = substr($data, $offset, $length);
            $aad = CryptoInternal::chunkAad($headerBytes, $metadataDigest, $index);
            $ciphertext = CryptoInternal::gcmEncrypt($key, CryptoInternal::chunkNonce($baseNonce, $index), $chunk, $aad);
            $output .= pack('V', strlen($ciphertext)) . $ciphertext;
            $root->update(CryptoInternal::sha256($ciphertext));
        }

        $output .= $root->finish();
        $output .= self::FOOTER_MAGIC;
        return $output;
    }

    public static function decodeEncrypted(string $container, ?DecodeOptions $options = null): DecodeResult
    {
        $opts = $options ?? new DecodeOptions();
        $key = $opts->key;

        $header = Header::parse($container);
        $headerBytes = substr($container, 0, Header::SIZE);
        $offset = Header::SIZE;

        $entries = [];
        $metadataRegion = '';
        if ($header->hasMetadata()) {
            [$entries, $consumed] = Metadata::parse($container, $offset, self::boundedCap($opts->maxMetaBytes));
            $metadataRegion = substr($container, $offset, $consumed);
            $offset += $consumed;
        }

        if (!$header->encrypted() || $key === null || strlen($key) !== self::KEY_SIZE) {
            throw new UbcException(ErrorCode::MissingKey);
        }
        if ($header->chunkCount > $opts->maxChunkCount || $header->totalSize > $opts->maxTotalSize) {
            throw new UbcException(ErrorCode::Truncated);
        }

        $metadataDigest = CryptoInternal::sha256($metadataRegion);
        $baseNonce = $header->baseNonce;
        $root = RootAccumulator::keyed(CryptoInternal::rootKey($key, $baseNonce));
        $root->update($headerBytes);
        $root->update($metadataRegion);

        $plaintext = '';
        $remaining = $header->totalSize;
        $containerLength = strlen($container);
        $index = 0;
        for ($i = 0; $i < $header->chunkCount; $i++, $index++) {
            if ($containerLength - $offset < 4) {
                throw new UbcException(ErrorCode::Truncated);
            }
            $chunkLength = unpack('V', $container, $offset)[1];
            $offset += 4;
            if ($chunkLength > $opts->maxChunkLen || $chunkLength > $containerLength - $offset) {
                throw new UbcException(ErrorCode::Truncated);
            }
            $body = substr($container, $offset, $chunkLength);
            $root->update(CryptoInternal::sha256($body));
            if ($chunkLength < CryptoInternal::GCM_TAG_SIZE) {
                throw new UbcException(ErrorCode::ChunkAuth);
            }
            $aad = CryptoInternal::chunkAad($headerBytes, $metadataDigest, $index);
            $plaintextChunk = CryptoInternal::gcmDecrypt($key, CryptoInternal::chunkNonce($baseNonce, $index), $body, $aad);
            if ($plaintextChunk === null) {
                throw new UbcException(ErrorCode::ChunkAuth);
            }
            $offset += $chunkLength;
            if (strlen($plaintextChunk) > $remaining) {
                throw new UbcException(ErrorCode::RootMismatch);
            }
            $plaintext .= $plaintextChunk;
            $remaining -= strlen($plaintextChunk);
        }

        if ($containerLength - $offset < self::FOOTER_SIZE) {
            throw new UbcException(ErrorCode::Truncated);
        }
        $footerRoot = substr($container, $offset, 32);
        $footerMagic = substr($container, $offset + 32, 4);
        if ($footerMagic !== self::FOOTER_MAGIC) {
            throw new UbcException(ErrorCode::Truncated);
        }
        $computedRoot = $root->finish();
        if (strlen($plaintext) !== $header->totalSize || !hash_equals($computedRoot, $footerRoot)) {
            throw new UbcException(ErrorCode::RootMismatch);
        }
        if ($containerLength !== $offset + self::FOOTER_SIZE) {
            throw new UbcException(ErrorCode::TrailingData);
        }
        return new DecodeResult($plaintext, $entries);
    }

    /** Internal: exposed only so conformance tests can check this against the shared known-answer fixture. */
    public static function rootKeyForTesting(string $key, string $baseNonce): string
    {
        return CryptoInternal::rootKey($key, $baseNonce);
    }

    private static function validateEncodeKey(string $key): void
    {
        if (strlen($key) !== self::KEY_SIZE) {
            throw new UbcException(ErrorCode::ReservedBits);
        }
    }

    private static function boundedCap(int $cap): int
    {
        return $cap > 0xFFFF_FFFF ? 0xFFFF_FFFF : $cap;
    }
}

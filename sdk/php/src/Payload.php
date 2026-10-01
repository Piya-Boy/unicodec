<?php

declare(strict_types=1);

namespace Ubc;

/** One-shot plain (non-encrypted) UBC v1 encoding and decoding (SPEC.md sections 2-4). */
final class Payload
{
    public const int DEFAULT_CHUNK_SIZE = 1 << 20;
    private const int FOOTER_SIZE = 36;
    private const string FOOTER_MAGIC = 'UBCE';

    private function __construct()
    {
    }

    /**
     * @param MetadataEntry[] $entries
     */
    public static function encodePlain(string $data, array $entries, int $chunkSize): string
    {
        if ($chunkSize <= 0 || $chunkSize > 0xFFFF_FFFF) {
            throw new \InvalidArgumentException('chunkSize must be a positive uint32');
        }
        $metadata = Metadata::encode($entries);
        $dataLength = strlen($data);
        $chunkCount = $dataLength === 0 ? 0 : intdiv($dataLength + $chunkSize - 1, $chunkSize);

        $header = new Header(
            $metadata !== '' ? Header::FLAG_HAS_METADATA : 0,
            Header::HASH_SHA256,
            Header::AEAD_NONE,
            $chunkSize,
            $chunkCount,
            $dataLength,
            "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
        );
        $headerBytes = $header->toBytes();

        $output = $headerBytes . $metadata;
        $rootContext = hash_init('sha256');
        hash_update($rootContext, $headerBytes);
        hash_update($rootContext, $metadata);

        for ($offset = 0; $offset < $dataLength; $offset += $chunkSize) {
            $length = min($chunkSize, $dataLength - $offset);
            $chunk = substr($data, $offset, $length);
            $output .= pack('V', $length) . $chunk;
            hash_update($rootContext, hash('sha256', $chunk, true));
        }

        $output .= hash_final($rootContext, true);
        $output .= self::FOOTER_MAGIC;
        return $output;
    }

    public static function decodePlain(string $container, ?DecodeOptions $options = null): DecodeResult
    {
        $opts = $options ?? new DecodeOptions();

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

        if ($header->encrypted()) {
            throw new UbcException(ErrorCode::MissingKey);
        }
        if ($header->chunkCount > $opts->maxChunkCount || $header->totalSize > $opts->maxTotalSize) {
            throw new UbcException(ErrorCode::Truncated);
        }

        $rootContext = hash_init('sha256');
        hash_update($rootContext, $headerBytes);
        hash_update($rootContext, $metadataRegion);

        $plaintext = '';
        $remaining = $header->totalSize;
        $containerLength = strlen($container);
        for ($i = 0; $i < $header->chunkCount; $i++) {
            if ($containerLength - $offset < 4) {
                throw new UbcException(ErrorCode::Truncated);
            }
            $chunkLength = unpack('V', $container, $offset)[1];
            $offset += 4;
            if ($chunkLength > $opts->maxChunkLen || $chunkLength > $containerLength - $offset) {
                throw new UbcException(ErrorCode::Truncated);
            }
            if ($chunkLength > $remaining) {
                throw new UbcException(ErrorCode::RootMismatch);
            }
            $chunk = substr($container, $offset, $chunkLength);
            hash_update($rootContext, hash('sha256', $chunk, true));
            $plaintext .= $chunk;
            $offset += $chunkLength;
            $remaining -= $chunkLength;
        }

        if ($containerLength - $offset < self::FOOTER_SIZE) {
            throw new UbcException(ErrorCode::Truncated);
        }
        $footerRoot = substr($container, $offset, 32);
        $footerMagic = substr($container, $offset + 32, 4);
        if ($footerMagic !== self::FOOTER_MAGIC) {
            throw new UbcException(ErrorCode::Truncated);
        }
        $computedRoot = hash_final($rootContext, true);
        if (strlen($plaintext) !== $header->totalSize || !hash_equals($computedRoot, $footerRoot)) {
            throw new UbcException(ErrorCode::RootMismatch);
        }
        if ($containerLength !== $offset + self::FOOTER_SIZE) {
            throw new UbcException(ErrorCode::TrailingData);
        }
        return new DecodeResult($plaintext, $entries);
    }

    private static function boundedCap(int $cap): int
    {
        return $cap > 0xFFFF_FFFF ? 0xFFFF_FFFF : $cap;
    }
}

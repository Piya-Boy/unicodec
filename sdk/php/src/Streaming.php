<?php

declare(strict_types=1);

namespace Ubc;

/** Factory, verify, and inspect entry points over Encoder/Decoder. */
final class Streaming
{
    private function __construct()
    {
    }

    /**
     * @param resource $sink
     * @param MetadataEntry[] $entries
     */
    public static function newEncoder($sink, array $entries, ?EncodeOptions $options = null): Encoder
    {
        return new Encoder($sink, $entries, $options);
    }

    /** @param resource $source */
    public static function newDecoder($source, ?DecodeOptions $options = null): Decoder
    {
        return new Decoder($source, $options);
    }

    /** Fully decodes and discards the plaintext, reporting whether the container is valid. */
    public static function verify($source, ?DecodeOptions $options = null): VerifyReport
    {
        try {
            $decoder = new Decoder($source, $options);
            $decoder->readAll();
        } catch (UbcException $e) {
            return new VerifyReport(false, $e->errorCode);
        }
        return new VerifyReport(true, null);
    }

    /** Reads only the header and metadata — never touches payload or footer. */
    public static function inspect($source, ?DecodeOptions $options = null): ContainerInfo
    {
        $opts = $options ?? new DecodeOptions();
        $headerBytes = self::readExact($source, Header::SIZE);
        $header = Header::parse($headerBytes);
        $entries = [];
        if ($header->hasMetadata()) {
            $prefix = self::readExact($source, 4);
            $metadataLength = unpack('V', $prefix)[1];
            if ($metadataLength === 0 || $metadataLength > $opts->maxMetaBytes) {
                throw new UbcException(ErrorCode::MetaMalformed);
            }
            try {
                $body = self::readExact($source, $metadataLength);
            } catch (UbcException $e) {
                if ($e->errorCode === ErrorCode::Truncated) {
                    throw new UbcException(ErrorCode::MetaMalformed);
                }
                throw $e;
            }
            [$entries] = Metadata::parse($prefix . $body, 0, self::boundedCap($opts->maxMetaBytes));
        }
        return new ContainerInfo(
            Header::VERSION,
            $header->encrypted(),
            $header->hasMetadata(),
            $header->hashAlgo,
            $header->aeadAlgo,
            $header->chunkSize,
            $header->chunkCount,
            $header->totalSize,
            $entries,
        );
    }

    /** @param resource $source */
    private static function readExact($source, int $length): string
    {
        $data = '';
        while (strlen($data) < $length) {
            $chunk = fread($source, $length - strlen($data));
            if ($chunk === false || $chunk === '') {
                throw new UbcException(ErrorCode::Truncated);
            }
            $data .= $chunk;
        }
        return $data;
    }

    private static function boundedCap(int $cap): int
    {
        return $cap > 0xFFFF_FFFF ? 0xFFFF_FFFF : $cap;
    }
}

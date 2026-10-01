<?php

declare(strict_types=1);

namespace Ubc;

/** UBC metadata TLV block encoding and parsing (SPEC.md section 2.2). */
final class Metadata
{
    public const int TAG_FILENAME = 0x0001;
    public const int TAG_MIME_TYPE = 0x0002;
    public const int TAG_CREATED_AT = 0x0003;

    private function __construct()
    {
    }

    /**
     * @param MetadataEntry[] $entries
     */
    public static function encode(array $entries): string
    {
        $ordered = $entries;
        usort($ordered, static fn (MetadataEntry $a, MetadataEntry $b): int => $a->tag <=> $b->tag);
        if ($ordered === []) {
            return '';
        }

        $body = '';
        $previousTag = null;
        foreach ($ordered as $entry) {
            self::validateEntry($entry);
            if ($previousTag === $entry->tag) {
                throw new UbcException(ErrorCode::MetaMalformed);
            }
            $previousTag = $entry->tag;
            $valueLength = strlen($entry->value);
            if ($valueLength > 0xFFFF_FFFF || strlen($body) + 6 + $valueLength > 0xFFFF_FFFF) {
                throw new UbcException(ErrorCode::MetaMalformed);
            }
            $body .= pack('vV', $entry->tag, $valueLength) . $entry->value;
        }
        return pack('V', strlen($body)) . $body;
    }

    /**
     * @return array{0: MetadataEntry[], 1: int} entries and bytes consumed
     */
    public static function parse(string $data, int $offset = 0, ?int $maxBytes = null): array
    {
        if (strlen($data) - $offset < 4) {
            throw new UbcException(ErrorCode::MetaMalformed);
        }
        $metadataLength = unpack('V', $data, $offset)[1];
        $available = strlen($data) - $offset - 4;
        if ($metadataLength === 0 || ($maxBytes !== null && $metadataLength > $maxBytes) || $metadataLength > $available) {
            throw new UbcException(ErrorCode::MetaMalformed);
        }

        $end = $offset + 4 + $metadataLength;
        $entries = [];
        $cursor = $offset + 4;
        $previousTag = null;
        while ($cursor < $end) {
            if ($end - $cursor < 6) {
                throw new UbcException(ErrorCode::MetaMalformed);
            }
            $header = unpack('vtag/Vlength', $data, $cursor);
            $tag = $header['tag'];
            $valueLength = $header['length'];
            $cursor += 6;
            if ($valueLength > $end - $cursor || ($previousTag !== null && $tag <= $previousTag)) {
                throw new UbcException(ErrorCode::MetaMalformed);
            }
            $value = substr($data, $cursor, $valueLength);
            $entry = new MetadataEntry($tag, $value);
            self::validateEntry($entry);
            $entries[] = $entry;
            $previousTag = $tag;
            $cursor += $valueLength;
        }
        return [$entries, $end - $offset];
    }

    private static function validateEntry(MetadataEntry $entry): void
    {
        if ($entry->tag < 0 || $entry->tag > 0xFFFF) {
            throw new UbcException(ErrorCode::MetaMalformed);
        }
        if ($entry->tag === self::TAG_FILENAME) {
            if (str_starts_with($entry->value, "\xEF\xBB\xBF") || str_contains($entry->value, "\x00")) {
                throw new UbcException(ErrorCode::MetaMalformed);
            }
            if (!self::isValidUtf8($entry->value)) {
                throw new UbcException(ErrorCode::MetaMalformed);
            }
        } elseif ($entry->tag === self::TAG_MIME_TYPE) {
            foreach (str_split($entry->value) as $byte) {
                $code = ord($byte);
                if ($code === 0 || $code > 0x7F) {
                    throw new UbcException(ErrorCode::MetaMalformed);
                }
            }
        } elseif ($entry->tag === self::TAG_CREATED_AT) {
            if (strlen($entry->value) !== 8) {
                throw new UbcException(ErrorCode::MetaMalformed);
            }
        }
    }

    private static function isValidUtf8(string $value): bool
    {
        return mb_check_encoding($value, 'UTF-8');
    }
}

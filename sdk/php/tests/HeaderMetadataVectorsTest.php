<?php

declare(strict_types=1);

namespace Ubc\Tests;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Ubc\ErrorCode;
use Ubc\Header;
use Ubc\Metadata;
use Ubc\MetadataEntry;
use Ubc\UbcException;

final class HeaderMetadataVectorsTest extends TestCase
{
    private static function vectorRoot(): string
    {
        return realpath(__DIR__ . '/../../../spec/vectors');
    }

    private static function vector(string $name): string
    {
        return file_get_contents(self::vectorRoot() . '/expected/' . $name);
    }

    public function testAllPositiveVectorHeadersRoundTripByteExactly(): void
    {
        $expectedDir = self::vectorRoot() . '/expected';
        $files = glob($expectedDir . '/*.ubc');
        self::assertNotEmpty($files);
        foreach ($files as $path) {
            $name = basename($path);
            if (str_starts_with($name, 'negative-')) {
                continue;
            }
            $container = file_get_contents($path);
            $header = Header::parse($container);
            self::assertSame(substr($container, 0, Header::SIZE), $header->toBytes(), $name);
        }
    }

    public function testVectorMetadataRoundTripsByteExactly(): void
    {
        $container = self::vector('plain-metadata.ubc');
        $header = Header::parse($container);
        self::assertTrue($header->hasMetadata());

        [$entries, $consumed] = Metadata::parse($container, Header::SIZE);
        $reencoded = Metadata::encode($entries);
        $expected = substr($container, Header::SIZE, $consumed);
        self::assertSame($expected, $reencoded);
    }

    public static function headerNegativeVectors(): array
    {
        return [
            ['negative-bad-magic.ubc', ErrorCode::BadMagic],
            ['negative-version-two.ubc', ErrorCode::UnsupportedVersion],
            ['negative-hash-algo.ubc', ErrorCode::UnsupportedAlgorithm],
            ['negative-aead-algo.ubc', ErrorCode::UnsupportedAlgorithm],
            ['negative-reserved-flag.ubc', ErrorCode::ReservedBits],
            ['negative-inconsistent-encryption.ubc', ErrorCode::ReservedBits],
            ['negative-zero-chunk-size.ubc', ErrorCode::ReservedBits],
            ['negative-encrypted-zero-chunk-size.ubc', ErrorCode::ReservedBits],
            ['negative-encrypted-oversized-chunk-size.ubc', ErrorCode::ReservedBits],
        ];
    }

    #[DataProvider('headerNegativeVectors')]
    public function testHeaderNegativeVectorsUseStableErrorCodes(string $name, ErrorCode $expected): void
    {
        $container = self::vector($name);
        try {
            Header::parse($container);
            self::fail("$name: expected UbcException");
        } catch (UbcException $e) {
            self::assertSame($expected, $e->errorCode, $name);
        }
    }

    public static function metadataNegativeVectors(): array
    {
        return [
            ['negative-meta-out-of-order.ubc'],
            ['negative-meta-duplicate.ubc'],
            ['negative-meta-overrun.ubc'],
            ['negative-empty-metadata.ubc'],
            ['negative-encrypted-reserved-metadata.ubc'],
            ['negative-reserved-metadata.ubc'],
        ];
    }

    #[DataProvider('metadataNegativeVectors')]
    public function testMetadataNegativeVectorsUseStableErrorCodes(string $name): void
    {
        $container = self::vector($name);
        try {
            Metadata::parse($container, Header::SIZE);
            self::fail("$name: expected UbcException");
        } catch (UbcException $e) {
            self::assertSame(ErrorCode::MetaMalformed, $e->errorCode, $name);
        }
    }

    public function testMetadataEncoderSortsTagsAndRejectsDuplicates(): void
    {
        $entries = [
            new MetadataEntry(0x1000, "\x01"),
            new MetadataEntry(0x0001, 'example.txt'),
        ];
        $encoded = Metadata::encode($entries);
        [$parsed] = Metadata::parse($encoded);
        self::assertSame(0x0001, $parsed[0]->tag);
        self::assertSame(0x1000, $parsed[1]->tag);

        $duplicates = [
            new MetadataEntry(1, ''),
            new MetadataEntry(1, ''),
        ];
        try {
            Metadata::encode($duplicates);
            self::fail('expected UbcException');
        } catch (UbcException $e) {
            self::assertSame(ErrorCode::MetaMalformed, $e->errorCode);
        }
    }

    public function testMetadataLengthCapIsCheckedBeforeCopyingEntries(): void
    {
        $oversized = "\x01\x00\x00\x01"; // declares a length larger than 16 MiB
        try {
            Metadata::parse($oversized, 0, 16 << 20);
            self::fail('expected UbcException');
        } catch (UbcException $e) {
            self::assertSame(ErrorCode::MetaMalformed, $e->errorCode);
        }

        $metadata = Metadata::encode([new MetadataEntry(0x1000, "\x01")]);
        try {
            Metadata::parse($metadata, 0, 6);
            self::fail('expected UbcException');
        } catch (UbcException $e) {
            self::assertSame(ErrorCode::MetaMalformed, $e->errorCode);
        }
    }
}

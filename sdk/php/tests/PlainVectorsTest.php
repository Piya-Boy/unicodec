<?php

declare(strict_types=1);

namespace Ubc\Tests;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Ubc\ErrorCode;
use Ubc\Header;
use Ubc\MetadataEntry;
use Ubc\Payload;
use Ubc\UbcException;

final class PlainVectorsTest extends TestCase
{
    private static function vectorRoot(): string
    {
        return realpath(__DIR__ . '/../../../spec/vectors');
    }

    private static function readVector(string $relative): string
    {
        return file_get_contents(self::vectorRoot() . '/' . $relative);
    }

    public function testEncodesEveryPlainVectorByteExactly(): void
    {
        self::assertSame(
            self::readVector('expected/plain-empty.ubc'),
            Payload::encodePlain(self::readVector('inputs/empty.bin'), [], 1 << 20),
        );
        self::assertSame(
            self::readVector('expected/plain-one-byte.ubc'),
            Payload::encodePlain(self::readVector('inputs/one-byte.bin'), [], 1 << 20),
        );
        self::assertSame(
            self::readVector('expected/plain-chunk-1m.ubc'),
            Payload::encodePlain(self::readVector('inputs/chunk-1m.bin'), [], 1 << 20),
        );
        self::assertSame(
            self::readVector('expected/plain-chunk-1m-plus-one.ubc'),
            Payload::encodePlain(self::readVector('inputs/chunk-1m-plus-one.bin'), [], 1 << 20),
        );
        self::assertSame(
            self::readVector('expected/plain-multi-3m.ubc'),
            Payload::encodePlain(self::readVector('inputs/multi-3m.bin'), [], 1 << 20),
        );

        $entries = [
            new MetadataEntry(0x0001, hex2bin('e0b8a3e0b8b2e0b8a2e0b887e0b8b2e0b8992d323032362e747874')),
            new MetadataEntry(0x0002, hex2bin('746578742f706c61696e')),
            new MetadataEntry(0x0003, hex2bin('00a8da769b010000')),
            new MetadataEntry(0x1000, hex2bin('00ff7f')),
        ];
        self::assertSame(
            self::readVector('expected/plain-metadata.ubc'),
            Payload::encodePlain(self::readVector('inputs/one-byte.bin'), $entries, 1 << 20),
        );
    }

    public function testDecodesEveryPlainVector(): void
    {
        $this->decodeMatchesInput('expected/plain-empty.ubc', 'inputs/empty.bin');
        $this->decodeMatchesInput('expected/plain-one-byte.ubc', 'inputs/one-byte.bin');
        $this->decodeMatchesInput('expected/plain-chunk-1m.ubc', 'inputs/chunk-1m.bin');
        $this->decodeMatchesInput('expected/plain-chunk-1m-plus-one.ubc', 'inputs/chunk-1m-plus-one.bin');
        $this->decodeMatchesInput('expected/plain-multi-3m.ubc', 'inputs/multi-3m.bin');
        $this->decodeMatchesInput('expected/plain-metadata.ubc', 'inputs/one-byte.bin');
    }

    private function decodeMatchesInput(string $container, string $input): void
    {
        $result = Payload::decodePlain(self::readVector($container));
        self::assertSame(self::readVector($input), $result->data, $container);
    }

    public function testFlippedPlainPayloadReturnsRootMismatch(): void
    {
        $container = self::readVector('expected/plain-chunk-1m.ubc');
        $index = Header::SIZE + 4;
        $container[$index] = chr(ord($container[$index]) ^ 0x01);
        try {
            Payload::decodePlain($container);
            self::fail('expected UbcException');
        } catch (UbcException $e) {
            self::assertSame(ErrorCode::RootMismatch, $e->errorCode);
        }
    }

    public static function negativeVectors(): array
    {
        return [
            ['negative-truncated.ubc', ErrorCode::Truncated],
            ['negative-root-mismatch.ubc', ErrorCode::RootMismatch],
            ['negative-trailing-data.ubc', ErrorCode::TrailingData],
            ['negative-oversized-clen.ubc', ErrorCode::Truncated],
        ];
    }

    #[DataProvider('negativeVectors')]
    public function testNegativeVectorsUseStableErrorCodes(string $name, ErrorCode $expected): void
    {
        $container = self::readVector('expected/' . $name);
        try {
            Payload::decodePlain($container);
            self::fail("$name: expected UbcException");
        } catch (UbcException $e) {
            self::assertSame($expected, $e->errorCode, $name);
        }
    }
}

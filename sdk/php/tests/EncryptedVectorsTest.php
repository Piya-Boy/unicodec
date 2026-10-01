<?php

declare(strict_types=1);

namespace Ubc\Tests;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Ubc\Crypto;
use Ubc\DecodeOptions;
use Ubc\ErrorCode;
use Ubc\MetadataEntry;
use Ubc\UbcException;

final class EncryptedVectorsTest extends TestCase
{
    private static function key(): string
    {
        return hex2bin('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f');
    }

    private static function baseNonce(): string
    {
        return hex2bin('f0e0d0c0b0a0908070605040');
    }

    private static function vectorRoot(): string
    {
        return realpath(__DIR__ . '/../../../spec/vectors');
    }

    private static function readVector(string $relative): string
    {
        return file_get_contents(self::vectorRoot() . '/' . $relative);
    }

    public function testEncodesEveryEncryptedVectorByteExactly(): void
    {
        self::assertSame(
            self::readVector('expected/encrypted-empty.ubc'),
            Crypto::encodeEncryptedWithFixedNonce(self::readVector('inputs/empty.bin'), self::key(), self::baseNonce(), [], 1 << 20),
        );
        self::assertSame(
            self::readVector('expected/encrypted-one-byte.ubc'),
            Crypto::encodeEncryptedWithFixedNonce(self::readVector('inputs/one-byte.bin'), self::key(), self::baseNonce(), [], 1 << 20),
        );
        self::assertSame(
            self::readVector('expected/encrypted-chunk-1m.ubc'),
            Crypto::encodeEncryptedWithFixedNonce(self::readVector('inputs/chunk-1m.bin'), self::key(), self::baseNonce(), [], 1 << 20),
        );
        self::assertSame(
            self::readVector('expected/encrypted-chunk-1m-plus-one.ubc'),
            Crypto::encodeEncryptedWithFixedNonce(self::readVector('inputs/chunk-1m-plus-one.bin'), self::key(), self::baseNonce(), [], 1 << 20),
        );
        self::assertSame(
            self::readVector('expected/encrypted-multi-3m.ubc'),
            Crypto::encodeEncryptedWithFixedNonce(self::readVector('inputs/multi-3m.bin'), self::key(), self::baseNonce(), [], 1 << 20),
        );

        $entries = [
            new MetadataEntry(0x0001, hex2bin('e0b8a3e0b8b2e0b8a2e0b887e0b8b2e0b8992d323032362e747874')),
            new MetadataEntry(0x0002, hex2bin('746578742f706c61696e')),
            new MetadataEntry(0x0003, hex2bin('00a8da769b010000')),
            new MetadataEntry(0x1000, hex2bin('00ff7f')),
        ];
        self::assertSame(
            self::readVector('expected/encrypted-metadata.ubc'),
            Crypto::encodeEncryptedWithFixedNonce(self::readVector('inputs/one-byte.bin'), self::key(), self::baseNonce(), $entries, 1 << 20),
        );
    }

    public function testDecodesEveryEncryptedVector(): void
    {
        $this->decodeMatchesInput('expected/encrypted-empty.ubc', 'inputs/empty.bin');
        $this->decodeMatchesInput('expected/encrypted-one-byte.ubc', 'inputs/one-byte.bin');
        $this->decodeMatchesInput('expected/encrypted-chunk-1m.ubc', 'inputs/chunk-1m.bin');
        $this->decodeMatchesInput('expected/encrypted-chunk-1m-plus-one.ubc', 'inputs/chunk-1m-plus-one.bin');
        $this->decodeMatchesInput('expected/encrypted-multi-3m.ubc', 'inputs/multi-3m.bin');
        $this->decodeMatchesInput('expected/encrypted-metadata.ubc', 'inputs/one-byte.bin');
    }

    private function decodeMatchesInput(string $container, string $input): void
    {
        $options = (new DecodeOptions())->withKey(self::key());
        $result = Crypto::decodeEncrypted(self::readVector($container), $options);
        self::assertSame(self::readVector($input), $result->data, $container);
    }

    public function testWrongKeyReturnsChunkAuthOnNonEmptyCiphertext(): void
    {
        $container = self::readVector('expected/encrypted-one-byte.ubc');
        $wrongKey = self::key();
        $wrongKey[0] = chr(ord($wrongKey[0]) ^ 0x01);
        $options = (new DecodeOptions())->withKey($wrongKey);
        try {
            Crypto::decodeEncrypted($container, $options);
            self::fail('expected UbcException');
        } catch (UbcException $e) {
            self::assertSame(ErrorCode::ChunkAuth, $e->errorCode);
        }
    }

    public function testMissingKeyReturnsMissingKey(): void
    {
        $container = self::readVector('expected/encrypted-one-byte.ubc');
        try {
            Crypto::decodeEncrypted($container, new DecodeOptions());
            self::fail('expected UbcException');
        } catch (UbcException $e) {
            self::assertSame(ErrorCode::MissingKey, $e->errorCode);
        }
    }

    public static function negativeVectors(): array
    {
        return [
            ['negative-chunk-auth.ubc', ErrorCode::ChunkAuth, true],
            ['negative-encrypted-short-clen.ubc', ErrorCode::ChunkAuth, true],
            ['negative-encrypted-metadata-tamper.ubc', ErrorCode::ChunkAuth, true],
            ['negative-missing-key.ubc', ErrorCode::MissingKey, false],
            ['negative-encrypted-cap-missing-key.ubc', ErrorCode::MissingKey, false],
        ];
    }

    #[DataProvider('negativeVectors')]
    public function testNegativeVectorsUseStableErrorCodes(string $name, ErrorCode $expected, bool $suppliesKey): void
    {
        $container = self::readVector('expected/' . $name);
        $options = $suppliesKey ? (new DecodeOptions())->withKey(self::key()) : new DecodeOptions();
        try {
            Crypto::decodeEncrypted($container, $options);
            self::fail("$name: expected UbcException");
        } catch (UbcException $e) {
            self::assertSame($expected, $e->errorCode, $name);
        }
    }

    public function testEncryptedEmptyWrongKeyReturnsRootMismatch(): void
    {
        $container = self::readVector('expected/negative-encrypted-empty-wrong-key.ubc');
        $wrongKey = hex2bin('ff0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f');
        $options = (new DecodeOptions())->withKey($wrongKey);
        try {
            Crypto::decodeEncrypted($container, $options);
            self::fail('expected UbcException');
        } catch (UbcException $e) {
            self::assertSame(ErrorCode::RootMismatch, $e->errorCode);
        }
    }

    public function testRootKeyMatchesSharedKnownAnswer(): void
    {
        $key = hex2bin('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f');
        $baseNonce = hex2bin('f0e0d0c0b0a0908070605040');
        $expectedRootKey = hex2bin('52c04b400d73df15d8a0db6ba58919f46fe822fff200fb50d8dee097af3c688c');
        self::assertSame($expectedRootKey, Crypto::rootKeyForTesting($key, $baseNonce));
    }
}

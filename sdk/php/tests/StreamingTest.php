<?php

declare(strict_types=1);

namespace Ubc\Tests;

use PHPUnit\Framework\TestCase;
use Ubc\DecodeOptions;
use Ubc\Decoder;
use Ubc\EncodeOptions;
use Ubc\Encoder;
use Ubc\ErrorCode;
use Ubc\Header;
use Ubc\Payload;
use Ubc\Streaming;
use Ubc\UbcException;

final class StreamingTest extends TestCase
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

    /** @return resource */
    private static function memoryStream(string $initial = ''): mixed
    {
        $stream = fopen('php://temp', 'r+b');
        if ($initial !== '') {
            fwrite($stream, $initial);
            fseek($stream, 0);
        }
        return $stream;
    }

    public function testStreamedPlainOutputIsByteExactAndFragmentedDecodeRoundTrips(): void
    {
        $input = self::readVector('inputs/multi-3m.bin');
        $sink = self::memoryStream();
        $encoder = new Encoder($sink, [], new EncodeOptions(1 << 20));
        $third = intdiv(strlen($input), 3);
        $encoder->write(substr($input, 0, $third));
        $encoder->write(substr($input, $third));
        $encoder->close();
        fseek($sink, 0);
        $streamed = stream_get_contents($sink);
        self::assertSame(self::readVector('expected/plain-multi-3m.ubc'), $streamed);

        // Decode through a source that only ever hands back 1 byte per fread() call.
        $source = self::memoryStream($streamed);
        $decoder = new Decoder($source, null);
        $decoded = '';
        while (($chunk = $decoder->read(1)) !== '') {
            $decoded .= $chunk;
        }
        self::assertSame($input, $decoded);
    }

    public function testStreamedEncryptedOutputIsByteExactAndAuthenticatesBeforeRelease(): void
    {
        $input = self::readVector('inputs/chunk-1m-plus-one.bin');
        $sink = self::memoryStream();
        $options = new EncodeOptions(1 << 20, self::key(), self::baseNonce());
        $encoder = new Encoder($sink, [], $options);
        $encoder->write($input);
        $encoder->close();
        fseek($sink, 0);
        $streamed = stream_get_contents($sink);
        self::assertSame(self::readVector('expected/encrypted-chunk-1m-plus-one.ubc'), $streamed);

        $source = self::memoryStream($streamed);
        $decoder = new Decoder($source, (new DecodeOptions())->withKey(self::key()));
        self::assertSame($input, $decoder->readAll());
    }

    public function testStreamedPlainDecoderWithholdsOutputUntilRootVerifies(): void
    {
        $container = self::readVector('expected/plain-chunk-1m.ubc');
        $lastIndex = strlen($container) - 1;
        $container[$lastIndex] = chr(ord($container[$lastIndex]) ^ 0x01); // corrupt footer magic's last byte
        $source = self::memoryStream($container);
        $decoder = new Decoder($source, null);
        try {
            $decoder->readAll();
            self::fail('expected UbcException');
        } catch (UbcException $e) {
            self::assertSame(ErrorCode::Truncated, $e->errorCode);
        }
    }

    public function testStreamedPlainDecoderWithholdsOutputUntilTrailingDataIsChecked(): void
    {
        $container = self::readVector('expected/plain-chunk-1m.ubc') . "\x00";
        $source = self::memoryStream($container);
        $decoder = new Decoder($source, null);
        try {
            $decoder->readAll();
            self::fail('expected UbcException');
        } catch (UbcException $e) {
            self::assertSame(ErrorCode::TrailingData, $e->errorCode);
        }
    }

    public function testTruncatedEncryptedFooterPrecedesFinalChunkAuthentication(): void
    {
        // Corrupt both the final chunk's GCM tag AND truncate the footer. SPEC.md section 5
        // requires truncation (stage 4) to win over chunk-auth failure (stage 5).
        $container = self::readVector('expected/encrypted-one-byte.ubc');
        $footerStart = strlen($container) - 36;
        $index = $footerStart - 1;
        $container[$index] = chr(ord($container[$index]) ^ 0x01); // flip the last byte of the only chunk's GCM tag
        $truncated = substr($container, 0, strlen($container) - 10);

        $source = self::memoryStream($truncated);
        $decoder = new Decoder($source, (new DecodeOptions())->withKey(self::key()));
        try {
            $decoder->readAll();
            self::fail('expected UbcException');
        } catch (UbcException $e) {
            self::assertSame(ErrorCode::Truncated, $e->errorCode);
        }
    }

    public function testStreamedEncoderWithLargeChunkSizeOnlyBuffersWrittenInput(): void
    {
        // A chunk_size far larger than the actual input must not cause the encoder to
        // allocate a chunk_size-sized buffer (the historical Rust OOM bug this guards against).
        $input = "\x01\x02\x03";
        $sink = self::memoryStream();
        $encoder = new Encoder($sink, [], new EncodeOptions(1 << 28)); // 256 MiB
        $encoder->write($input);
        $encoder->close();
        fseek($sink, 0);
        $result = Payload::decodePlain(stream_get_contents($sink));
        self::assertSame($input, $result->data);
    }

    public function testStreamedDecoderEnforcesCapsBeforeAllocatingChunkData(): void
    {
        $container = self::readVector('expected/plain-chunk-1m.ubc');
        $tight = new DecodeOptions(16 << 20, 4, 1 << 20, 1 << 30, null);
        $source = self::memoryStream($container);
        $decoder = new Decoder($source, $tight);
        try {
            $decoder->read(4096);
            self::fail('expected UbcException');
        } catch (UbcException $e) {
            self::assertSame(ErrorCode::Truncated, $e->errorCode);
        }
    }

    public function testVerifyAndInspectHaveTheirDocumentedReadScopes(): void
    {
        $container = self::readVector('expected/plain-metadata.ubc');
        $ok = Streaming::verify(self::memoryStream($container));
        self::assertTrue($ok->ok);

        $corrupted = $container;
        $index = Header::SIZE + 4;
        $corrupted[$index] = chr(ord($corrupted[$index]) ^ 0x01);
        $bad = Streaming::verify(self::memoryStream($corrupted));
        self::assertFalse($bad->ok);
        self::assertSame(ErrorCode::RootMismatch, $bad->error);

        // inspect only reads header + metadata; it must not touch (or require) the payload
        // or footer at all, so a stream with the footer deliberately mangled still works.
        $mangledFooter = $container;
        $lastIndex = strlen($mangledFooter) - 1;
        $mangledFooter[$lastIndex] = chr(ord($mangledFooter[$lastIndex]) ^ 0x01);
        $info = Streaming::inspect(self::memoryStream($mangledFooter));
        self::assertTrue($info->hasMetadata);
        self::assertFalse($info->encrypted);
        self::assertCount(4, $info->metadata);
    }
}

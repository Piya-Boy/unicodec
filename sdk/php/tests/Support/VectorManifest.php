<?php

declare(strict_types=1);

namespace Ubc\Tests\Support;

use Ubc\Crypto;
use Ubc\DecodeOptions;
use Ubc\ErrorCode;
use Ubc\Header;
use Ubc\MetadataEntry;
use Ubc\Payload;
use Ubc\UbcException;

/** Reads spec/vectors/vectors.json and encodes/decodes vectors through the PHP SDK. */
final class VectorManifest
{
    /** @param Vector[] $vectors */
    private function __construct(public readonly array $vectors)
    {
    }

    public static function vectorsRoot(): string
    {
        return realpath(__DIR__ . '/../../../../spec/vectors');
    }

    public static function read(string $vectorsRoot): self
    {
        $json = file_get_contents($vectorsRoot . '/vectors.json');
        $decoded = json_decode($json, associative: true, flags: JSON_THROW_ON_ERROR);
        $vectors = array_map(static fn (array $raw): Vector => Vector::from($raw), $decoded['vectors']);
        return new self($vectors);
    }

    /** The key shared by every encrypted positive vector, used to decode negative vectors that omit options. */
    public function canonicalKey(): string
    {
        foreach ($this->vectors as $vector) {
            if ($vector->expectError === null && $vector->options?->key !== null) {
                return $vector->options->key;
            }
        }
        throw new \RuntimeException('manifest has no encrypted positive vector');
    }

    public function find(string $id): Vector
    {
        foreach ($this->vectors as $vector) {
            if ($vector->id === $id) {
                return $vector;
            }
        }
        throw new \RuntimeException("manifest vector is missing: $id");
    }
}

final class Vector
{
    public function __construct(
        public readonly string $id,
        public readonly ?string $input,
        public readonly ?VectorOptions $options,
        public readonly string $expected,
        public readonly string $expectedSha256,
        public readonly ?string $expectError,
    ) {
    }

    public static function from(array $raw): self
    {
        return new self(
            $raw['id'],
            $raw['input'] ?? null,
            isset($raw['options']) ? VectorOptions::from($raw['options']) : null,
            $raw['expected'],
            hex2bin($raw['expectedSha256']),
            $raw['expectError'] ?? null,
        );
    }

    /** Encodes this vector's input through the PHP SDK using its declared options. */
    public function encode(string $inputBytes): string
    {
        if ($this->options === null) {
            throw new \RuntimeException("$this->id: positive vector has no options");
        }
        if ($this->options->key !== null && $this->options->baseNonce !== null) {
            return Crypto::encodeEncryptedWithFixedNonce($inputBytes, $this->options->key, $this->options->baseNonce, $this->options->metadata, $this->options->chunkSize);
        }
        if ($this->options->key === null && $this->options->baseNonce === null) {
            return Payload::encodePlain($inputBytes, $this->options->metadata, $this->options->chunkSize);
        }
        throw new \RuntimeException("$this->id: key and baseNonce must be paired");
    }

    /**
     * Decodes a container, auto-detecting plain vs encrypted from the header itself
     * (mirrors Go's single DecodeBytes entry point). key is used only if the container
     * turns out to be encrypted.
     */
    public function decode(string $container, ?string $key): DecodedVector
    {
        try {
            $encrypted = Header::parse($container)->encrypted();
            if ($encrypted) {
                $result = Crypto::decodeEncrypted($container, (new DecodeOptions())->withKey($key));
                return new DecodedVector($result->data, $result->metadata, null);
            }
            $result = Payload::decodePlain($container);
            return new DecodedVector($result->data, $result->metadata, null);
        } catch (UbcException $e) {
            return new DecodedVector(null, null, $e->errorCode);
        }
    }
}

final class VectorOptions
{
    /** @param MetadataEntry[] $metadata */
    public function __construct(
        public readonly int $chunkSize,
        public readonly ?string $key,
        public readonly ?string $baseNonce,
        public readonly array $metadata,
    ) {
    }

    public static function from(array $raw): self
    {
        $metadata = [];
        foreach ($raw['metadata'] ?? [] as $rawEntry) {
            $tag = (int) hexdec(substr($rawEntry['tag'], 2));
            $metadata[] = new MetadataEntry($tag, hex2bin($rawEntry['valueHex']));
        }
        return new self(
            $raw['chunkSize'],
            isset($raw['key']) ? hex2bin($raw['key']) : null,
            isset($raw['baseNonce']) ? hex2bin($raw['baseNonce']) : null,
            $metadata,
        );
    }
}

final class DecodedVector
{
    /** @param MetadataEntry[]|null $metadata */
    public function __construct(
        public readonly ?string $data,
        public readonly ?array $metadata,
        public readonly ?ErrorCode $error,
    ) {
    }
}

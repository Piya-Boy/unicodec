<?php

declare(strict_types=1);

namespace Ubc\Tests;

use PHPUnit\Framework\TestCase;
use Ubc\Tests\Support\VectorManifest;

/** Drives every vector in spec/vectors/vectors.json through the PHP SDK — the manifest is the contract. */
final class ConformanceTest extends TestCase
{
    public function testEveryShareManifestVectorConforms(): void
    {
        $root = VectorManifest::vectorsRoot();
        $manifest = VectorManifest::read($root);
        $canonicalKey = $manifest->canonicalKey();
        $positiveCount = 0;
        $negativeCount = 0;

        foreach ($manifest->vectors as $vector) {
            $expected = file_get_contents($root . '/' . $vector->expected);
            self::assertSame($vector->expectedSha256, hash('sha256', $expected, true), "$vector->id: expected artifact SHA-256 differs from vectors.json");

            if ($vector->expectError !== null) {
                $negativeCount++;
                $vectorKey = $vector->options?->key;
                $decodeKey = self::requiresKey($vector->id) ? ($vectorKey ?? $canonicalKey) : null;
                $decoded = $vector->decode($expected, $decodeKey);
                self::assertNotNull($decoded->error, "$vector->id: negative vector must not decode successfully");
                self::assertSame($vector->expectError, $decoded->error->value, "$vector->id: stable error id differs");
                continue;
            }

            $positiveCount++;
            $input = file_get_contents($root . '/' . $vector->input);
            $encoded = $vector->encode($input);
            self::assertSame($expected, $encoded, "$vector->id: encoded container differs from vectors.json artifact");

            $result = $vector->decode($expected, $vector->options->key);
            self::assertNull($result->error, "$vector->id: decode failed with " . ($result->error?->value ?? ''));
            self::assertSame($input, $result->data, "$vector->id: decoded plaintext differs");
            $expectedMetadata = $vector->options->metadata;
            self::assertCount(count($expectedMetadata), $result->metadata, "$vector->id: decoded metadata count differs");
            foreach ($expectedMetadata as $i => $entry) {
                self::assertSame($entry->tag, $result->metadata[$i]->tag, "$vector->id: metadata tag $i");
                self::assertSame($entry->value, $result->metadata[$i]->value, "$vector->id: metadata value $i");
            }
        }

        self::assertGreaterThan(0, $positiveCount, 'manifest must contain positive vectors');
        self::assertGreaterThan(0, $negativeCount, 'manifest must contain negative vectors');
    }

    // Negative vectors whose own point is "decoded without a key" must actually be decoded
    // without one; every other negative vector decodes with the canonical/vector-supplied key
    // so a missing-key short-circuit doesn't mask the error the vector is meant to exercise.
    private static function requiresKey(string $id): bool
    {
        return $id !== 'negative-missing-key' && $id !== 'negative-encrypted-cap-missing-key';
    }
}

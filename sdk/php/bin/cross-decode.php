#!/usr/bin/env php
<?php

declare(strict_types=1);

/**
 * Cross-decode CLI matching the Rust/Java/.NET CLIs' contract: --vectors DIR --work DIR
 * --cases a,b,c [--write | --verify]. Invoked by scripts/cross-decode.mjs so PHP
 * participates in the Go/Node/Python/Rust/Java/.NET/PHP cross-decode matrix.
 */

require __DIR__ . '/../vendor/autoload.php';
require __DIR__ . '/../tests/Support/VectorManifest.php';

use Ubc\Tests\Support\VectorManifest;

function safeChild(string $root, string $child): string
{
    if ($child === '') {
        throw new \InvalidArgumentException('manifest path must be a non-empty relative path');
    }
    $target = realpath($root) === false ? null : $root . '/' . $child;
    $resolved = realpath(dirname($target)) . '/' . basename($target);
    $normalizedRoot = rtrim(realpath($root), '/\\') . DIRECTORY_SEPARATOR;
    if (!str_starts_with(str_replace('\\', '/', $resolved), str_replace('\\', '/', $normalizedRoot))) {
        throw new \InvalidArgumentException("manifest path escapes vectors root: $child");
    }
    return $resolved;
}

function safeId(string $id): bool
{
    return preg_match('/^[a-z0-9]+(-[a-z0-9]+)*$/', $id) === 1;
}

function existingDirectory(?string $path, string $label): string
{
    if ($path === null || $path === '') {
        throw new \InvalidArgumentException("--$label is required");
    }
    $resolved = realpath($path);
    if ($resolved === false || !is_dir($resolved)) {
        throw new \InvalidArgumentException("$label path is not a directory");
    }
    return $resolved;
}

function parseArguments(array $args): array
{
    $vectorsRoot = null;
    $workDir = null;
    $cases = null;
    $write = null;
    $i = 0;
    $count = count($args);
    while ($i < $count) {
        $argument = $args[$i];
        switch ($argument) {
            case '--vectors':
                $vectorsRoot = $args[++$i];
                break;
            case '--work':
                $workDir = $args[++$i];
                break;
            case '--cases':
                $cases = $args[++$i];
                break;
            case '--write':
                if ($write !== null) {
                    throw new \InvalidArgumentException('--write/--verify specified more than once');
                }
                $write = true;
                break;
            case '--verify':
                if ($write !== null) {
                    throw new \InvalidArgumentException('--write/--verify specified more than once');
                }
                $write = false;
                break;
            default:
                throw new \InvalidArgumentException("unexpected argument: $argument");
        }
        $i++;
    }
    $resolvedVectorsRoot = existingDirectory($vectorsRoot, 'vectors');
    $resolvedWorkDir = existingDirectory($workDir, 'work');
    if ($cases === null) {
        throw new \InvalidArgumentException('--cases is required');
    }
    if ($write === null) {
        throw new \InvalidArgumentException('exactly one of --write or --verify is required');
    }
    $seen = [];
    $caseIds = [];
    foreach (explode(',', $cases) as $id) {
        if (!safeId($id) || isset($seen[$id])) {
            throw new \InvalidArgumentException("unsafe or duplicate case id: $id");
        }
        $seen[$id] = true;
        $caseIds[] = $id;
    }
    if ($caseIds === []) {
        throw new \InvalidArgumentException('--cases must not be empty');
    }
    return [$resolvedVectorsRoot, $resolvedWorkDir, $caseIds, $write];
}

function metadataEquals(array $actual, array $expected): bool
{
    if (count($actual) !== count($expected)) {
        return false;
    }
    foreach ($actual as $i => $entry) {
        if ($entry->tag !== $expected[$i]->tag || $entry->value !== $expected[$i]->value) {
            return false;
        }
    }
    return true;
}

function run(array $args): void
{
    [$vectorsRoot, $workDir, $caseIds, $write] = parseArguments($args);
    $manifest = VectorManifest::read($vectorsRoot);
    $canonicalKey = $manifest->canonicalKey();

    foreach ($caseIds as $id) {
        $vector = $manifest->find($id);
        if ($vector->expectError !== null) {
            throw new \RuntimeException("negative cross-decode case is not allowed: $id");
        }
        if ($vector->input === null) {
            throw new \RuntimeException("$id: positive vector has no input");
        }
        $input = file_get_contents(safeChild($vectorsRoot, $vector->input));
        $expected = file_get_contents(safeChild($vectorsRoot, $vector->expected));
        if (!hash_equals($vector->expectedSha256, hash('sha256', $expected, true))) {
            throw new \RuntimeException("$id: expected artifact SHA-256 differs from vectors.json");
        }

        if ($write) {
            $container = $vector->encode($input);
            if ($container !== $expected) {
                throw new \RuntimeException("$id: PHP encode differs from shared artifact");
            }
            file_put_contents(safeChild($workDir, "$id.php.ubc"), $container);
        } else {
            $key = $vector->options?->key ?? $canonicalKey;
            foreach (['go', 'node', 'python', 'rust', 'java', 'dotnet', 'php'] as $producer) {
                $container = file_get_contents(safeChild($workDir, "$id.$producer.ubc"));
                $decoded = $vector->decode($container, $key);
                if ($decoded->error !== null) {
                    throw new \RuntimeException("$id: PHP rejected $producer container with {$decoded->error->value}");
                }
                if ($decoded->data !== $input) {
                    throw new \RuntimeException("$id: PHP-decoded $producer plaintext differs from manifest input");
                }
                $expectedMetadata = $vector->options?->metadata ?? [];
                if (!metadataEquals($decoded->metadata, $expectedMetadata)) {
                    throw new \RuntimeException("$id: PHP-decoded $producer metadata differs from manifest");
                }
                $reencoded = $vector->encode($decoded->data);
                if ($reencoded !== $expected) {
                    throw new \RuntimeException("$id: $producer-to-PHP re-encode is not byte-identical");
                }
                if ($container !== $expected) {
                    throw new \RuntimeException("$id: fresh $producer container differs from shared artifact");
                }
            }
        }
    }
}

try {
    run(array_slice($argv, 1));
    exit(0);
} catch (\Throwable $e) {
    fwrite(STDERR, $e->getMessage() . "\n");
    exit(1);
}

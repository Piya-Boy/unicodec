<?php

declare(strict_types=1);

namespace Ubc;

/**
 * SPEC.md section 4's root_hash accumulator: plain SHA-256 over root_input for plain
 * containers, or a keyed HMAC-SHA-256 (HKDF-derived root_key) for encrypted containers.
 * Wraps the two so encoder/decoder code can call update() without branching on mode.
 */
final class RootAccumulator
{
    private \HashContext $context;
    private ?string $finished = null;

    private function __construct(\HashContext $context)
    {
        $this->context = $context;
    }

    public static function plain(): self
    {
        return new self(hash_init('sha256'));
    }

    public static function keyed(string $rootKey): self
    {
        return new self(hash_init('sha256', HASH_HMAC, $rootKey));
    }

    public function update(string $data): void
    {
        if ($this->finished !== null) {
            throw new \LogicException('RootAccumulator already finished');
        }
        hash_update($this->context, $data);
    }

    public function finish(): string
    {
        if ($this->finished === null) {
            $this->finished = hash_final($this->context, true);
        }
        return $this->finished;
    }
}

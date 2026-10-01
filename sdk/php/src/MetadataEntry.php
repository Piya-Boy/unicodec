<?php

declare(strict_types=1);

namespace Ubc;

/** One UBC metadata TLV entry (SPEC.md section 2.2.1). */
final class MetadataEntry
{
    public function __construct(
        public readonly int $tag,
        public readonly string $value,
    ) {
    }
}

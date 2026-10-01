<?php

declare(strict_types=1);

namespace Ubc;

/** Result of Streaming::verify(). */
final class VerifyReport
{
    public function __construct(
        public readonly bool $ok,
        public readonly ?ErrorCode $error,
    ) {
    }
}

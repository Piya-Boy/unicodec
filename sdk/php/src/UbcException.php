<?php

declare(strict_types=1);

namespace Ubc;

/**
 * A UBC failure carrying a portable, stable error identifier.
 *
 * Named errorCode (not code) because \Exception already declares a non-readonly $code
 * property for getCode(); a promoted readonly $code property would collide with it.
 */
final class UbcException extends \RuntimeException
{
    public function __construct(public readonly ErrorCode $errorCode)
    {
        parent::__construct($errorCode->value);
    }
}

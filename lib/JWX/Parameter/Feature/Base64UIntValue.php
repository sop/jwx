<?php

declare(strict_types = 1);

namespace Sop\JWX\Parameter\Feature;

use Sop\JWX\Parameter\Parameter;
use Sop\JWX\Util\Base64;
use Sop\JWX\Util\BigInt;

/**
 * Trait for parameters having Base64urlUInt value.
 *
 * @see https://tools.ietf.org/html/rfc7518#section-2
 */
trait Base64UIntValue
{
    use Base64URLValue;

    /**
     * Initialize parameter from base10 number.
     *
     * @param int|string $number
     *
     * @return self
     */
    public static function fromNumber($number): Parameter
    {
        $data = BigInt::fromBase10($number)->base256();
        return static::fromString($data);
    }

    /**
     * Get value as a number.
     */
    public function number(): BigInt
    {
        return BigInt::fromBase256(Base64::urlDecode($this->value()));
    }
}

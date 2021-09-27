<?php

declare(strict_types = 1);

namespace Sop\JWX\Parameter\Feature;

use Sop\JWX\Parameter\Parameter;

/**
 * Trait for parameters having an array value.
 */
trait ArrayParameterValue
{
    /**
     * Initialize from a JSON value.
     *
     * @param array $value
     *
     * @return static
     */
    public static function fromJSONValue($value): Parameter
    {
        if (!is_array($value)) {
            throw new \UnexpectedValueException(
                get_called_class() . ' expects an array parameter.');
        }
        return new static(...$value);
    }
}

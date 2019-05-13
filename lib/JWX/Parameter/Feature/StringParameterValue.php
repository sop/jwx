<?php

declare(strict_types = 1);

namespace Sop\JWX\Parameter\Feature;

use Sop\JWX\Parameter\Parameter;

/**
 * Trait for parameters having a string value.
 */
trait StringParameterValue
{
    /**
     * Constructor.
     *
     * @param string $value Parameter value
     */
    abstract public function __construct(string $value);

    /**
     * Initialize from a JSON value.
     *
     * @param string $value
     *
     * @return static
     */
    public static function fromJSONValue($value): Parameter
    {
        return new static(strval($value));
    }
}

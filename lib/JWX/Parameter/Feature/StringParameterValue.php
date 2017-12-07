<?php

declare(strict_types = 1);

namespace JWX\Parameter\Feature;

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
     * @return static
     */
    public static function fromJSONValue($value)
    {
        return new static(strval($value));
    }
}

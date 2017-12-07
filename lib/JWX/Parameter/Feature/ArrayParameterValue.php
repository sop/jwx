<?php

declare(strict_types = 1);

namespace JWX\Parameter\Feature;

/**
 * Trait for parameters having an array value.
 */
trait ArrayParameterValue
{
    /**
     * Constructor.
     *
     * @param mixed ...$values
     */
    abstract public function __construct(...$values);
    
    /**
     * Initialize from a JSON value.
     *
     * @param array $value
     * @return static
     */
    public static function fromJSONValue($value)
    {
        if (!is_array($value)) {
            throw new \UnexpectedValueException(
                get_called_class() . " expects an array parameter.");
        }
        return new static(...$value);
    }
}

<?php

declare(strict_types = 1);

namespace Sop\JWX\JWT\Claim\Validator;

/**
 * Base class for the claim validators.
 */
abstract class Validator
{
    /**
     * Functor method.
     *
     * @param mixed $value
     * @param mixed $constraint
     *
     * @return bool
     */
    public function __invoke($value, $constraint): bool
    {
        return $this->validate($value, $constraint);
    }

    /**
     * Check whether value is valid by given constraint.
     *
     * @param mixed $value      Value to assert
     * @param mixed $constraint Constraint
     *
     * @return bool True if value is valid
     */
    abstract public function validate($value, $constraint): bool;
}

<?php

declare(strict_types = 1);

namespace JWX\JWT\Claim\Validator;

/**
 * Validator to check whether the claim value is greater than the constraint.
 */
class GreaterValidator extends Validator
{
    /**
     *
     * {@inheritdoc}
     */
    public function validate($value, $constraint): bool
    {
        return $value > $constraint;
    }
}

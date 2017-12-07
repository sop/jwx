<?php

declare(strict_types = 1);

namespace JWX\JWT\Claim\Validator;

/**
 * Validator to check whether the claim value is less than the constraint.
 */
class LessValidator extends Validator
{
    /**
     *
     * {@inheritdoc}
     */
    public function validate($value, $constraint): bool
    {
        return $value < $constraint;
    }
}

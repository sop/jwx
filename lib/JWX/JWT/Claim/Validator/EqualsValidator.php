<?php

namespace JWX\JWT\Claim\Validator;

/**
 * Validator to check whether the claim value is equal to the constraint.
 */
class EqualsValidator extends Validator
{
    /**
     *
     * {@inheritdoc}
     */
    public function validate($value, $constraint)
    {
        return $value == $constraint;
    }
}

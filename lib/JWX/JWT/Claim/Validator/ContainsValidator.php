<?php

declare(strict_types = 1);

namespace Sop\JWX\JWT\Claim\Validator;

/**
 * Validator to check whether the claim value contains a given constraint.
 *
 * If the claim value is an array, validator checks whether the array contains
 * a constraint. Otherwise variable equality is tested.
 */
class ContainsValidator extends Validator
{
    /**
     * {@inheritdoc}
     */
    public function validate($value, $constraint): bool
    {
        if (is_array($value)) {
            return in_array($constraint, $value);
        }
        return $value == $constraint;
    }
}

<?php

declare(strict_types = 1);

namespace Sop\JWX\JWT\Claim\Validator;

/**
 * Validator to check whether the claim value is less or equal to the
 * constraint.
 */
class LessOrEqualValidator extends Validator
{
    /**
     * {@inheritdoc}
     */
    public function validate($value, $constraint): bool
    {
        return $value <= $constraint;
    }
}

<?php

declare(strict_types = 1);

namespace Sop\JWX\JWT\Claim\Feature;

use Sop\JWX\JWT\ValidationContext;

/**
 * Trait for claims using reference time as a validation constraint.
 */
trait ReferenceTimeValidation
{
    /**
     * Validate the claim against given constraint.
     *
     * @param mixed $constraint
     */
    abstract public function validate($constraint): bool;

    /**
     * Override default Claim validation.
     *
     * Uses reference time of the validation context as a constraint.
     *
     * @see \Sop\JWX\JWT\Claim\Claim::validateWithContext()
     */
    public function validateWithContext(ValidationContext $ctx): bool
    {
        if ($ctx->hasReferenceTime()) {
            // try to validate with leeway added
            if ($this->validate($ctx->referenceTime() + $ctx->leeway())) {
                return true;
            }
            // try to validate with leeway substracted
            if ($this->validate($ctx->referenceTime() - $ctx->leeway())) {
                return true;
            }
            return false;
        }
        return true;
    }
}

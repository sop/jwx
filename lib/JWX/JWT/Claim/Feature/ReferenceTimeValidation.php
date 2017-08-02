<?php

namespace JWX\JWT\Claim\Feature;

use JWX\JWT\ValidationContext;

/**
 * Trait for claims using reference time as a validation constraint.
 */
trait ReferenceTimeValidation
{
    /**
     * Validate the claim against given constraint.
     *
     * @param mixed $constraint
     * @return bool
     */
    abstract public function validate($constraint);
    
    /**
     * Override default Claim validation.
     *
     * Uses reference time of the validation context as a constraint.
     *
     * @see \JWX\JWT\Claim\Claim::validateWithContext()
     * @param ValidationContext $ctx
     * @return bool
     */
    public function validateWithContext(ValidationContext $ctx)
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

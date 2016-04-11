<?php

namespace JWX\JWT\Claim\Feature;

use JWX\JWT\ValidationContext;


trait ReferenceTimeValidation
{
	/**
	 * Override default Claim validation.
	 *
	 * Uses reference time of the validation context as a constraint.
	 *
	 * @see JWX\JWT\Claim\Claim::validate
	 * @param ValidationContext $ctx
	 * @return bool
	 */
	public function validate(ValidationContext $ctx) {
		if (isset($this->_validator)) {
			if ($ctx->hasReferenceTime()) {
				return $this->_validator->__invoke($this->_value, 
					$ctx->referenceTime());
			}
		}
		return true;
	}
}

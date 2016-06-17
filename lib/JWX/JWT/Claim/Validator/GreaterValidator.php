<?php

namespace JWX\JWT\Claim\Validator;


/**
 * Validator to check whether the claim value is greater than the constraint.
 */
class GreaterValidator extends Validator
{
	public function validate($value, $constraint) {
		return $value > $constraint;
	}
}

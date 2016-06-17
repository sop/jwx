<?php

namespace JWX\JWT\Claim\Validator;


/**
 * Validator to check whether the claim value is greater or equal to the
 * constraint.
 */
class GreaterOrEqualValidator extends Validator
{
	public function validate($value, $constraint) {
		return $value >= $constraint;
	}
}

<?php

namespace JWX\JWT\Claim\Validator;


/**
 * Validator to check whether the claim value is less or equal to the
 * constraint.
 */
class LessOrEqualValidator extends Validator
{
	public function validate($value, $constraint) {
		return $value <= $constraint;
	}
}

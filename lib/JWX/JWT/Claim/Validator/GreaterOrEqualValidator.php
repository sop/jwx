<?php

namespace JWX\JWT\Claim\Validator;


/**
 * Validator to check whether value is greater or equal to constraint.
 */
class GreaterOrEqualValidator extends Validator
{
	public function validate($value, $constraint) {
		return $value >= $constraint;
	}
}

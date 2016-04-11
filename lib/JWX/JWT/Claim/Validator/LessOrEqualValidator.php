<?php

namespace JWX\JWT\Claim\Validator;


/**
 * Validator to check whether value is less or equal to constraint.
 */
class LessOrEqualValidator extends Validator
{
	public function validate($value, $constraint) {
		return $value <= $constraint;
	}
}

<?php

namespace JWX\JWT\Claim\Validator;


/**
 * Validator to check whether value is less than constraint.
 */
class LessValidator extends Validator
{
	public function validate($value, $constraint) {
		return $value < $constraint;
	}
}

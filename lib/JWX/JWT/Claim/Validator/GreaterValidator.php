<?php

namespace JWX\JWT\Claim\Validator;


/**
 * Validator to check whether value is greater than constraint.
 */
class GreaterValidator extends Validator
{
	public function validate($value, $constraint) {
		return $value > $constraint;
	}
}

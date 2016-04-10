<?php

namespace JWX\JWT\Claim\Validator;


/**
 * Validator to check whether value is equal to constraint.
 */
class EqualsValidator extends Validator
{
	public function __invoke($value, $constraint) {
		return $value == $constraint;
	}
}

<?php

namespace JWX\JWT\Claim\Validator;


/**
 * Validator to check whether value is greater than constraint.
 */
class GreaterValidator extends Validator
{
	public function __invoke($value, $constraint) {
		return $value > $constraint;
	}
}

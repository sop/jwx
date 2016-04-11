<?php

namespace JWX\JWT\Claim\Validator;


/**
 * Validator to check whether value contains given constraint.
 * If value is an array, validator checks whether the array has constraint as a
 * value. Otherwise variable equality is tested.
 */
class ContainsValidator extends Validator
{
	public function validate($value, $constraint) {
		if (is_array($value)) {
			return in_array($constraint, $value);
		}
		return $value == $constraint;
	}
}

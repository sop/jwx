<?php

namespace JWX\JWT\Claim\Validator;


abstract class Validator
{
	/**
	 * Check whether value is valid by given constraint.
	 *
	 * @param mixed $value Value to assert
	 * @param mixed $constraint Constraint
	 * @return bool True if value is valid
	 */
	abstract public function __invoke($value, $constraint);
}

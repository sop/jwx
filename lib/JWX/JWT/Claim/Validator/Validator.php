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
	abstract public function validate($value, $constraint);
	
	/**
	 * Functor method
	 *
	 * @param mixed $value
	 * @param mixed $constraint
	 * @return bool
	 */
	public function __invoke($value, $constraint) {
		return $this->validate($value, $constraint);
	}
}

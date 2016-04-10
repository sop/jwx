<?php

namespace JWX\JWT\Claim;

use JWX\JWT\ValidationContext;
use JWX\JWT\Claim\Validator\Validator;


class Claim
{
	/**
	 * Claim name
	 *
	 * @var string $_name
	 */
	protected $_name;
	
	/**
	 * Claim value
	 *
	 * @var mixed $_value
	 */
	protected $_value;
	
	/**
	 * Claim validator
	 *
	 * @var Validator|null $_validator
	 */
	protected $_validator;
	
	/**
	 * Constructor
	 *
	 * @param string $name Claim name
	 * @param mixed $value Claim value
	 * @param Validator|null $validator Claim validator or null if claim doesn't
	 *        provide validation
	 */
	public function __construct($name, $value, Validator $validator = null) {
		$this->_name = $name;
		$this->_value = $value;
		$this->_validator = $validator;
	}
	
	/**
	 * Initialize from name and value
	 *
	 * @param string $name
	 * @param mixed $value
	 * @return Claim
	 */
	public static function fromNameAndValue($name, $value) {
		if (isset(RegisteredClaim::$nameToCls[$name])) {
			$cls = RegisteredClaim::$nameToCls[$name];
			return $cls::fromJSONValue($value);
		}
		return new self($name, $value);
	}
	
	/**
	 * Get claim name
	 *
	 * @return string
	 */
	public function name() {
		return $this->_name;
	}
	
	/**
	 * Get claim value
	 *
	 * @return mixed
	 */
	public function value() {
		return $this->_value;
	}
	
	/**
	 * Validate claim in given context.
	 *
	 * @param ValidationContext $ctx
	 * @return bool True if claim is valid
	 */
	public function validate(ValidationContext $ctx) {
		if (isset($this->_validator)) {
			if ($ctx->hasConstraint($this->_name)) {
				return $this->_validator->__invoke($this->_value, 
					$ctx->constraint($this->_name));
			}
		}
		return true;
	}
}

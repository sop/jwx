<?php

namespace JWX\JWT\Claim;

use JWX\JWT\Claim\Validator\Validator;
use JWX\JWT\ValidationContext;


/**
 * Represents a JWT claim.
 *
 * @link https://tools.ietf.org/html/rfc7519#section-4
 */
class Claim
{
	/**
	 * Claim name.
	 *
	 * @var string $_name
	 */
	protected $_name;
	
	/**
	 * Claim value.
	 *
	 * @var mixed $_value
	 */
	protected $_value;
	
	/**
	 * Claim validator.
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
	 * Initialize from name and value.
	 *
	 * @param string $name
	 * @param mixed $value
	 * @return Claim
	 */
	public static function fromNameAndValue($name, $value) {
		if (array_key_exists($name, RegisteredClaim::MAP_NAME_TO_CLASS)) {
			$cls = RegisteredClaim::MAP_NAME_TO_CLASS[$name];
			return $cls::fromJSONValue($value);
		}
		return new self($name, $value);
	}
	
	/**
	 * Get the claim name.
	 *
	 * @return string
	 */
	public function name() {
		return $this->_name;
	}
	
	/**
	 * Get the claim value.
	 *
	 * @return mixed
	 */
	public function value() {
		return $this->_value;
	}
	
	/**
	 * Validate the claim against given constraint.
	 *
	 * @param mixed $constraint True if claim is valid
	 * @return bool
	 */
	public function validate($constraint) {
		if (isset($this->_validator)) {
			return $this->_validator->validate($this->_value, $constraint);
		}
		return true;
	}
	
	/**
	 * Validate the claim in a given context.
	 *
	 * @param ValidationContext $ctx
	 * @return bool True if claim is valid
	 */
	public function validateWithContext(ValidationContext $ctx) {
		if ($ctx->hasConstraint($this->_name)) {
			return $this->validate($ctx->constraint($this->_name));
		}
		return true;
	}
}

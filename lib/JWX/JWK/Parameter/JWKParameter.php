<?php

namespace JWX\JWK\Parameter;


/**
 * Represents a single JWK parameter.
 *
 * @link https://tools.ietf.org/html/rfc7517#section-4
 */
class JWKParameter
{
	/**
	 * Parameter name.
	 *
	 * @var string $_name
	 */
	protected $_name;
	
	/**
	 * Parameter value.
	 *
	 * @var mixed $_value
	 */
	protected $_value;
	
	/**
	 * Constructor
	 *
	 * @param string $name Parameter name
	 * @param mixed $value Parameter value
	 */
	public function __construct($name, $value) {
		$this->_name = $name;
		$this->_value = $value;
	}
	
	/**
	 * Initialize from name and value.
	 *
	 * Returns a parameter specific object if one is implemented.
	 *
	 * @param string $name Parameter name
	 * @param mixed $value Parameter value
	 * @return self
	 */
	public static function fromNameAndValue($name, $value) {
		if (array_key_exists($name, RegisteredJWKParameter::NAME_TO_CLS)) {
			$cls = RegisteredJWKParameter::NAME_TO_CLS[$name];
			return $cls::fromJSONValue($value);
		}
		return new self($name, $value);
	}
	
	/**
	 * Parameter name.
	 *
	 * @return string
	 */
	public function name() {
		return $this->_name;
	}
	
	/**
	 * Parameter value.
	 *
	 * @return mixed
	 */
	public function value() {
		return $this->_value;
	}
}

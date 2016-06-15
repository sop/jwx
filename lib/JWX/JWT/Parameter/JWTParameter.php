<?php

namespace JWX\JWT\Parameter;


/**
 * Represents a header parameter.
 */
class JWTParameter
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
	 * Initialize from a name and a value.
	 *
	 * Returns parameter specific object if one is implemented.
	 *
	 * @param string $name Parameter name
	 * @param mixed $value Parameter value
	 * @return self
	 */
	public static function fromNameAndValue($name, $value) {
		if (array_key_exists($name, RegisteredJWTParameter::MAP_NAME_TO_CLASS)) {
			$cls = RegisteredJWTParameter::MAP_NAME_TO_CLASS[$name];
			return $cls::fromJSONValue($value);
		}
		return new self($name, $value);
	}
	
	/**
	 * Get the parameter name.
	 *
	 * @return string
	 */
	public function name() {
		return $this->_name;
	}
	
	/**
	 * Get the parameter value.
	 *
	 * @return mixed
	 */
	public function value() {
		return $this->_value;
	}
}

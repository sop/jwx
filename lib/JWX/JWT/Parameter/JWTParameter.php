<?php

namespace JWX\JWT\Parameter;


class JWTParameter
{
	/**
	 * Parameter name
	 *
	 * @var string $_name
	 */
	protected $_name;
	
	/**
	 * Parameter value
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
	 * Returns parameter specific object if one is implemented.
	 *
	 * @param string $name Parameter name
	 * @param mixed $value Parameter value
	 * @return self
	 */
	public static function fromNameAndValue($name, $value) {
		switch ($name) {
		case RegisteredParameter::NAME_TYPE:
			return new TypeParameter($value);
		case RegisteredParameter::NAME_CONTENT_TYPE:
			return new ContentTypeParameter($value);
		case RegisteredParameter::NAME_ALGORITHM:
			return new AlgorithmParameter($value);
		}
		return new JWTParameter($name, $value);
	}
	
	/**
	 * Get parameter name
	 *
	 * @return string
	 */
	public function name() {
		return $this->_name;
	}
	
	/**
	 * Get parameter value
	 *
	 * @return mixed
	 */
	public function value() {
		return $this->_value;
	}
}

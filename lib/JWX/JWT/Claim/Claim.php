<?php

namespace JWX\JWT\Claim;


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
	 * Constructor
	 *
	 * @param string $name Claim name
	 * @param mixed $value Claim value
	 */
	public function __construct($name, $value) {
		$this->_name = $name;
		$this->_value = $value;
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
}

<?php

namespace JWX\JWT\Parameter;


/**
 * Implements 'Critical' parameter.
 *
 * @link https://tools.ietf.org/html/rfc7515#section-4.1.11
 */
class CriticalParameter extends JWTParameter
{
	/**
	 * Constructor
	 *
	 * @param string[] $names
	 */
	public function __construct(...$names) {
		parent::__construct(self::PARAM_CRITICAL, $names);
	}
	
	public static function fromJSONValue($value) {
		if (!is_array($value)) {
			throw new \UnexpectedValueException("crit must be an array.");
		}
		return new static(...$value);
	}
	
	/**
	 * Get self with parameter name added.
	 *
	 * @param string $name
	 * @return self
	 */
	public function withParamName($name) {
		$obj = clone $this;
		$obj->_value[] = $name;
		$obj->_value = array_values(array_unique($obj->_value));
		return $obj;
	}
	
	/**
	 * Check whether given parameter name is critical.
	 *
	 * @param string $name
	 * @return bool
	 */
	public function has($name) {
		return false !== array_search($name, $this->_value);
	}
	
	/**
	 * Get critical header parameter names.
	 *
	 * @return string[]
	 */
	public function names() {
		return $this->_value;
	}
}

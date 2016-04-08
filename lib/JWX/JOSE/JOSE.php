<?php

namespace JWX\JOSE;

use JWX\JOSE\Parameter\Parameter;


class JOSE
{
	/**
	 * Parameters
	 *
	 * @var Parameter[] $_parameters
	 */
	protected $_parameters;
	
	/**
	 * Constructor
	 *
	 * @param Parameter ...$params Parameters
	 */
	public function __construct(Parameter ...$params) {
		$this->_parameters = array();
		foreach ($params as $param) {
			$this->_parameters[$param->name()] = $param;
		}
	}
	
	/**
	 * Initialize from JSON
	 *
	 * @param string $json
	 * @throws \UnexpectedValueException
	 * @return self
	 */
	public static function fromJSON($json) {
		$params = array();
		$fields = json_decode($json, true, 32, JSON_BIGINT_AS_STRING);
		if (!is_array($fields)) {
			throw new \UnexpectedValueException("Invalid JSON");
		}
		foreach ($fields as $name => $value) {
			$params[] = Parameter::fromNameAndValue($name, $value);
		}
		return new self(...$params);
	}
	
	/**
	 * Whether parameter is present
	 *
	 * @param string $name Parameter name
	 * @return boolean
	 */
	public function has($name) {
		return isset($this->_parameters[$name]);
	}
	
	/**
	 * Get parameter
	 *
	 * @param string $name Parameter name
	 * @throws \LogicException
	 * @return Parameter
	 */
	public function get($name) {
		if (!$this->has($name)) {
			throw new \LogicException("Parameter $name doesn't exists");
		}
		return $this->_parameters[$name];
	}
	
	/**
	 * Convert to JSON
	 *
	 * @return string
	 */
	public function toJSON() {
		$data = array();
		foreach ($this->_parameters as $param) {
			$data[$param->name()] = $param->value();
		}
		return json_encode($data, JSON_FORCE_OBJECT);
	}
}

<?php

namespace JWX\Header;

use JWX\Header\Parameter\Parameter;


class Header implements \Countable
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
	 * Get self with parameters added
	 *
	 * @param Parameters ...$param
	 * @return self
	 */
	public function withParameters(Parameter ...$params) {
		$obj = clone $this;
		foreach ($params as $param) {
			$obj->_parameters[$param->name()] = $param;
		}
		return $obj;
	}
	
	/**
	 * Get all parameters
	 *
	 * @return Parameter[]
	 */
	public function parameters() {
		return $this->_parameters;
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
		if (empty($this->_parameters)) {
			return "";
		}
		$data = array();
		foreach ($this->_parameters as $param) {
			$data[$param->name()] = $param->value();
		}
		return json_encode($data, JSON_FORCE_OBJECT);
	}
	
	/**
	 *
	 * {@inheritDoc}
	 *
	 * @see Countable::count()
	 */
	public function count() {
		return count($this->_parameters);
	}
}

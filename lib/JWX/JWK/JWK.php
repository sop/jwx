<?php

namespace JWX\JWK;

use JWX\JWK\Parameter\JWKParameter;


class JWK implements \Countable
{
	/**
	 * Parameters
	 *
	 * @var JWKParameter[] $_parameters
	 */
	protected $_parameters;
	
	/**
	 * Constructor
	 *
	 * @param JWKParameter ...$params
	 */
	public function __construct(JWKParameter ...$params) {
		$this->_parameters = array();
		foreach ($params as $param) {
			$this->_parameters[$param->name()] = $param;
		}
	}
	
	/**
	 * Initialize from array representing JSON object
	 *
	 * @param array $members
	 * @return self
	 */
	public static function fromArray(array $members) {
		$params = array();
		foreach ($members as $name => $value) {
			$params[] = JWKParameter::fromNameAndValue($name, $value);
		}
		return new self(...$params);
	}
	
	/**
	 * Initialize from JSON
	 *
	 * @param string $json
	 * @throws \UnexpectedValueException
	 * @return self
	 */
	public static function fromJSON($json) {
		$members = json_decode($json, true, 32, JSON_BIGINT_AS_STRING);
		if (!is_array($members)) {
			throw new \UnexpectedValueException("Invalid JSON");
		}
		return static::fromArray($members);
	}
	
	/**
	 * Get self with parameters added
	 *
	 * @param JWKParameter ...$params
	 * @return self
	 */
	public function withParameters(JWKParameter ...$params) {
		$obj = clone $this;
		foreach ($params as $param) {
			$obj->_parameters[$param->name()] = $param;
		}
		return $obj;
	}
	
	/**
	 * Get all parameters
	 *
	 * @return JWKParameter[]
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
	 * @return JWKParameter
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
		return json_encode($data, JSON_FORCE_OBJECT | JSON_UNESCAPED_SLASHES);
	}
	
	/**
	 * Get number of parameters
	 *
	 * @see Countable::count()
	 */
	public function count() {
		return count($this->_parameters);
	}
}

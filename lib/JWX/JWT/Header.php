<?php

namespace JWX\JWT;

use JWX\JWT\Parameter\JWTParameter;
use JWX\JWT\Parameter\RegisteredJWTParameter;


/**
 * Represents a header used in JWS and JWE.
 */
class Header implements 
	\Countable, \IteratorAggregate
{
	/**
	 * Parameters.
	 *
	 * @var JWTParameter[] $_parameters
	 */
	protected $_parameters;
	
	/**
	 * Constructor
	 *
	 * @param JWTParameter ...$params Parameters
	 */
	public function __construct(JWTParameter ...$params) {
		$this->_parameters = array();
		foreach ($params as $param) {
			$this->_parameters[$param->name()] = $param;
		}
	}
	
	/**
	 * Initialize from an array representing a JSON object.
	 *
	 * @param array $members
	 * @return self
	 */
	public static function fromArray(array $members) {
		$params = array();
		foreach ($members as $name => $value) {
			$params[] = JWTParameter::fromNameAndValue($name, $value);
		}
		return new self(...$params);
	}
	
	/**
	 * Initialize from a JSON.
	 *
	 * @param string $json
	 * @throws \UnexpectedValueException
	 * @return self
	 */
	public static function fromJSON($json) {
		$members = json_decode($json, true, 32, JSON_BIGINT_AS_STRING);
		if (!is_array($members)) {
			throw new \UnexpectedValueException("Invalid JSON.");
		}
		return self::fromArray($members);
	}
	
	/**
	 * Get self with parameters added.
	 *
	 * @param JWTParameter ...$param
	 * @return self
	 */
	public function withParameters(JWTParameter ...$params) {
		$obj = clone $this;
		foreach ($params as $param) {
			$obj->_parameters[$param->name()] = $param;
		}
		return $obj;
	}
	
	/**
	 * Get all parameters.
	 *
	 * @return JWTParameter[]
	 */
	public function parameters() {
		return $this->_parameters;
	}
	
	/**
	 * Whether parameters are present.
	 *
	 * Returns false if any of the given parameters is not set.
	 *
	 * @param string ...$names Parameter names
	 * @return boolean
	 */
	public function has(...$names) {
		foreach ($names as $name) {
			if (!isset($this->_parameters[$name])) {
				return false;
			}
		}
		return true;
	}
	
	/**
	 * Get a parameter.
	 *
	 * @param string $name Parameter name
	 * @throws \LogicException
	 * @return JWTParameter
	 */
	public function get($name) {
		if (!$this->has($name)) {
			throw new \LogicException("Parameter $name doesn't exists.");
		}
		return $this->_parameters[$name];
	}
	
	/**
	 * Get a parameter and check that it's an instance of the expected type.
	 *
	 * @param string $name Parameter name
	 * @throws \RuntimeException
	 * @return JWTParameter
	 */
	public function getTyped($name) {
		$param = $this->get($name);
		if (array_key_exists($name, RegisteredJWTParameter::MAP_NAME_TO_CLASS)) {
			$cls = RegisteredJWTParameter::MAP_NAME_TO_CLASS[$name];
			if (!$param instanceof $cls) {
				throw new \RuntimeException(
					"$cls expected, got " . get_class($param));
			}
		}
		return $param;
	}
	
	/**
	 * Convert to a JSON.
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
		return json_encode((object) $data, JSON_UNESCAPED_SLASHES);
	}
	
	/**
	 * Get the number of parameters.
	 *
	 * @see Countable::count()
	 * @return int
	 */
	public function count() {
		return count($this->_parameters);
	}
	
	/**
	 * Get iterator for the parameters.
	 *
	 * @see IteratorAggregate::getIterator()
	 * @return \ArrayIterator
	 */
	public function getIterator() {
		return new \ArrayIterator($this->_parameters);
	}
}

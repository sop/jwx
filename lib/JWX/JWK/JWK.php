<?php

namespace JWX\JWK;

use JWX\JWK\Parameter\JWKParameter;


/**
 * Class to represent JWK structure.
 *
 * @link https://tools.ietf.org/html/rfc7517#section-4
 */
class JWK implements \Countable, \IteratorAggregate
{
	use TypedJWK;
	
	/**
	 * Parameters.
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
	 * Initialize from an array representing a JSON object.
	 *
	 * @param array $members
	 * @return self
	 */
	public static function fromArray(array $members) {
		$params = array();
		foreach ($members as $name => $value) {
			$params[] = JWKParameter::fromNameAndValue($name, $value);
		}
		return new static(...$params);
	}
	
	/**
	 * Initialize from a JSON string.
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
		return static::fromArray($members);
	}
	
	/**
	 * Initialize from another JWK.
	 *
	 * Allows casting to subclass by late static binding.
	 *
	 * @param JWK $jwk
	 * @return self
	 */
	public static function fromJWK(JWK $jwk) {
		return new static(...array_values($jwk->_parameters));
	}
	
	/**
	 * Get self with parameters added.
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
	 * Get all parameters.
	 *
	 * @return JWKParameter[]
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
	 * @return bool
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
	 * @return JWKParameter
	 */
	public function get($name) {
		if (!$this->has($name)) {
			throw new \LogicException("Parameter $name doesn't exists.");
		}
		return $this->_parameters[$name];
	}
	
	/**
	 * Convert to array.
	 *
	 * @return array Parameter values keyed by parameter names
	 */
	public function toArray() {
		$a = array();
		foreach ($this->_parameters as $param) {
			$a[$param->name()] = $param->value();
		}
		return $a;
	}
	
	/**
	 * Convert to JSON.
	 *
	 * @return string
	 */
	public function toJSON() {
		$data = $this->toArray();
		if (empty($data)) {
			return "";
		}
		return json_encode((object) $data, JSON_UNESCAPED_SLASHES);
	}
	
	/**
	 * Get the number of parameters.
	 *
	 * @see Countable::count()
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

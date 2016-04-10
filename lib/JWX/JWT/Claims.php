<?php

namespace JWX\JWT;

use JWX\JWT\Claim\Claim;


/**
 * Set of Claim objects
 */
class Claims implements \IteratorAggregate
{
	/**
	 * Claims
	 *
	 * @var Claim[] $_claims
	 */
	protected $_claims;
	
	/**
	 * Constructor
	 *
	 * @param Claim ...$claims
	 */
	public function __construct(Claim ...$claims) {
		$this->_claims = array();
		foreach ($claims as $claim) {
			$this->_claims[$claim->name()] = $claim;
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
		$claims = array();
		$fields = json_decode($json, true, 32, JSON_BIGINT_AS_STRING);
		if (!is_array($fields)) {
			throw new \UnexpectedValueException("Invalid JSON");
		}
		foreach ($fields as $name => $value) {
			$claims[] = Claim::fromNameAndValue($name, $value);
		}
		return new self(...$claims);
	}
	
	/**
	 * Get self with Claim objects added
	 *
	 * @param Claim ...$claims One or more Claim objects
	 * @return self
	 */
	public function withClaims(Claim ...$claims) {
		$obj = clone $this;
		foreach ($claims as $claim) {
			$obj->_claims[$claim->name()] = $claim;
		}
		return $obj;
	}
	
	/**
	 * Whether claim is present
	 *
	 * @param string $name Claim name
	 */
	public function has($name) {
		return isset($this->_claims[$name]);
	}
	
	/**
	 * Get claim by name
	 *
	 * @param string $name Claim name
	 * @throws \LogicException If claim is not present
	 * @return Claim
	 */
	public function get($name) {
		if (!isset($this->_claims[$name])) {
			throw new \LogicException("Claim $name not set");
		}
		return $this->_claims[$name];
	}
	
	/**
	 * Convert to JSON
	 *
	 * @return string
	 */
	public function toJSON() {
		$data = array();
		foreach ($this->_claims as $claim) {
			$data[$claim->name()] = $claim->value();
		}
		return json_encode($data, JSON_FORCE_OBJECT | JSON_UNESCAPED_SLASHES);
	}
	
	/**
	 * Check whether claims set is valid in given context
	 *
	 * @param ValidationContext $ctx
	 * @return boolean
	 */
	public function isValid(ValidationContext $ctx) {
		try {
			$ctx->validate($this);
		} catch (\RuntimeException $e) {
			return false;
		}
		return true;
	}
	
	/**
	 * Get iterator for Claim objects keyed by claim name
	 *
	 * @see IteratorAggregate::getIterator()
	 * @return Claim[]
	 */
	public function getIterator() {
		return new \ArrayIterator($this->_claims);
	}
}

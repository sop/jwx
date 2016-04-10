<?php

namespace JWX\JWT;

use JWX\JWT\Claim\Claim;


class Claims
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
		$this->_claims = $claims;
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
}

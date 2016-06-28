<?php

namespace JWX\JWK\Parameter;


/**
 * Implements 'Other Primes Info' parameter.
 *
 * @todo Implement the underlying data structure
 * @link https://tools.ietf.org/html/rfc7518#section-6.3.2.7
 */
class OtherPrimesInfoParameter extends JWKParameter
{
	/**
	 * Constructor
	 *
	 * @param array[] ...$primes
	 */
	public function __construct(...$primes) {
		parent::__construct(self::PARAM_OTHER_PRIMES_INFO, $primes);
	}
	
	public static function fromJSONValue($value) {
		if (!is_array($value)) {
			throw new \UnexpectedValueException("oth must be an array.");
		}
		return new self(...$value);
	}
}

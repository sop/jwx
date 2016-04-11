<?php

namespace JWX\JWK\Parameter;


class OtherPrimesInfoParameter extends RegisteredJWKParameter
{
	/**
	 * Constructor
	 *
	 * @param array[] ...$primes
	 * @todo implement underlying data structure
	 */
	public function __construct(...$primes) {
		parent::__construct(self::PARAM_OTHER_PRIMES_INFO, $primes);
	}
	
	public static function fromJSONValue($value) {
		return new self(...$value);
	}
}

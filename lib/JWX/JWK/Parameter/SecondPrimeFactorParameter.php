<?php

namespace JWX\JWK\Parameter;


class SecondPrimeFactorParameter extends RegisteredJWKParameter
{
	/**
	 * Constructor
	 * 
	 * @param string $q Second prime factor in base64urlUInt encoding
	 */
	public function __construct($q) {
		parent::__construct(self::PARAM_SECOND_PRIME_FACTOR, $q);
	}
}

<?php

namespace JWX\JWK\Parameter;

use JWX\JWK\Parameter\Feature\Base64UIntValue;


class SecondPrimeFactorParameter extends RegisteredJWKParameter
{
	use Base64UIntValue;
	
	/**
	 * Constructor
	 *
	 * @param string $q Second prime factor in base64urlUInt encoding
	 */
	public function __construct($q) {
		parent::__construct(self::PARAM_SECOND_PRIME_FACTOR, $q);
	}
}

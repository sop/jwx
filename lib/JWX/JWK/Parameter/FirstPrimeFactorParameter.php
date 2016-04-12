<?php

namespace JWX\JWK\Parameter;

use JWX\JWK\Parameter\Feature\Base64UIntValue;


class FirstPrimeFactorParameter extends RegisteredJWKParameter
{
	use Base64UIntValue;
	
	/**
	 * Constructor
	 *
	 * @param string $p First prime factor in base64urlUInt encoding
	 */
	public function __construct($p) {
		parent::__construct(self::PARAM_FIRST_PRIME_FACTOR, $p);
	}
}

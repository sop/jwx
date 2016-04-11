<?php

namespace JWX\JWK\Parameter;


class FirstPrimeFactorParameter extends RegisteredJWKParameter
{
	/**
	 * Constructor
	 *
	 * @param string $p First prime factor in base64urlUInt encoding
	 */
	public function __construct($p) {
		parent::__construct(self::PARAM_FIRST_PRIME_FACTOR, $p);
	}
}

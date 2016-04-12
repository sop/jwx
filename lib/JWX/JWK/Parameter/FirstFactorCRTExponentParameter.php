<?php

namespace JWX\JWK\Parameter;

use JWX\JWK\Parameter\Feature\Base64UIntValue;


class FirstFactorCRTExponentParameter extends RegisteredJWKParameter
{
	use Base64UIntValue;
	
	/**
	 * Constructor
	 *
	 * @param string $dp First factor CRT exponent in base64urlUInt encoding
	 */
	public function __construct($dp) {
		parent::__construct(self::PARAM_FIRST_FACTOR_CRT_EXPONENT, $dp);
	}
}

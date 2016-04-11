<?php

namespace JWX\JWK\Parameter;


class FirstFactorCRTExponentParameter extends RegisteredJWKParameter
{
	/**
	 * Constructor
	 *
	 * @param string $dp First factor CRT exponent in base64urlUInt encoding
	 */
	public function __construct($dp) {
		parent::__construct(self::PARAM_FIRST_FACTOR_CRT_EXPONENT, $dp);
	}
}

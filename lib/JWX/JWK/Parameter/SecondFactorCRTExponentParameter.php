<?php

namespace JWX\JWK\Parameter;


class SecondFactorCRTExponentParameter extends RegisteredJWKParameter
{
	/**
	 * Constructor
	 *
	 * @param string $dq Second factor CRT exponent in base64urlUInt encoding
	 */
	public function __construct($dq) {
		parent::__construct(self::PARAM_SECOND_FACTOR_CRT_EXPONENT, $dq);
	}
}

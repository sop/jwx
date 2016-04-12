<?php

namespace JWX\JWK\Parameter;

use JWX\JWK\Parameter\Feature\Base64UIntValue;


class SecondFactorCRTExponentParameter extends RegisteredJWKParameter
{
	use Base64UIntValue;
	
	/**
	 * Constructor
	 *
	 * @param string $dq Second factor CRT exponent in base64urlUInt encoding
	 */
	public function __construct($dq) {
		parent::__construct(self::PARAM_SECOND_FACTOR_CRT_EXPONENT, $dq);
	}
}

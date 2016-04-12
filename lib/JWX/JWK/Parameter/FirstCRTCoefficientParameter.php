<?php

namespace JWX\JWK\Parameter;

use JWX\JWK\Parameter\Feature\Base64UIntValue;


class FirstCRTCoefficientParameter extends RegisteredJWKParameter
{
	use Base64UIntValue;
	
	/**
	 * Constructor
	 *
	 * @param string $qi First CRT coefficient in base64urlUInt encoding
	 */
	public function __construct($qi) {
		parent::__construct(self::PARAM_FIRST_CRT_COEFFICIENT, $qi);
	}
}

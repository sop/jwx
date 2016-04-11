<?php

namespace JWX\JWK\Parameter;


class FirstCRTCoefficientParameter extends RegisteredJWKParameter
{
	/**
	 * Constructor
	 *
	 * @param string $qi First CRT coefficient in base64urlUInt encoding
	 */
	public function __construct($qi) {
		parent::__construct(self::PARAM_FIRST_CRT_COEFFICIENT, $qi);
	}
}

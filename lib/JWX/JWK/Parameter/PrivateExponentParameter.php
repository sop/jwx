<?php

namespace JWX\JWK\Parameter;

use JWX\JWK\Parameter\Feature\Base64UIntValue;


class PrivateExponentParameter extends RegisteredJWKParameter
{
	use Base64UIntValue;
	
	/**
	 * Constructor
	 *
	 * @param string $d Private exponent in base64urlUInt encoding
	 */
	public function __construct($d) {
		parent::__construct(self::PARAM_PRIVATE_EXPONENT, $d);
	}
}

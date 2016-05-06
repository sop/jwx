<?php

namespace JWX\JWK\Parameter;

use JWX\JWK\Parameter\Feature\Base64UIntValue;


/**
 * Implements 'First Factor CRT Exponent' parameter.
 *
 * @link https://tools.ietf.org/html/rfc7518#section-6.3.2.4
 */
class FirstFactorCRTExponentParameter extends RegisteredJWKParameter
{
	use Base64UIntValue;
	
	/**
	 * Constructor
	 *
	 * @param string $dp First factor CRT exponent in base64urlUInt encoding
	 */
	public function __construct($dp) {
		$this->_validateEncoding($dp);
		parent::__construct(self::PARAM_FIRST_FACTOR_CRT_EXPONENT, $dp);
	}
}

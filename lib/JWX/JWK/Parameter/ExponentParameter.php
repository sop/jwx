<?php

namespace JWX\JWK\Parameter;

use JWX\JWK\Parameter\Feature\Base64UIntValue;


/**
 * Implements 'Exponent' parameter.
 *
 * @link https://tools.ietf.org/html/rfc7518#section-6.3.1.2
 */
class ExponentParameter extends RegisteredJWKParameter
{
	use Base64UIntValue;
	
	/**
	 * Constructor
	 *
	 * @param string $e Exponent in base64urlUInt encoding
	 */
	public function __construct($e) {
		parent::__construct(self::PARAM_EXPONENT, $e);
	}
}

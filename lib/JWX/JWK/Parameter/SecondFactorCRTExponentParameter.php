<?php

namespace JWX\JWK\Parameter;

use JWX\JWK\Parameter\Feature\Base64UIntValue;


/**
 * Implements 'Second Factor CRT Exponent' parameter.
 *
 * @link https://tools.ietf.org/html/rfc7518#section-6.3.2.5
 */
class SecondFactorCRTExponentParameter extends JWKParameter
{
	use Base64UIntValue;
	
	/**
	 * Constructor
	 *
	 * @param string $dq Second factor CRT exponent in base64urlUInt encoding
	 */
	public function __construct($dq) {
		$this->_validateEncoding($dq);
		parent::__construct(self::PARAM_SECOND_FACTOR_CRT_EXPONENT, $dq);
	}
}

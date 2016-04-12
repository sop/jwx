<?php

namespace JWX\JWK\Parameter;

use JWX\JWK\Parameter\Feature\Base64UIntValue;


class ModulusParameter extends RegisteredJWKParameter
{
	use Base64UIntValue;
	
	/**
	 * Constructor
	 *
	 * @param string $n Modulus in base64urlUInt encoding
	 */
	public function __construct($n) {
		parent::__construct(self::PARAM_MODULUS, $n);
	}
}

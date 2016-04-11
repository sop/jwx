<?php

namespace JWX\JWK\Parameter;


class PrivateExponentParameter extends RegisteredJWKParameter
{
	/**
	 * Constructor
	 *
	 * @param string $d Private exponent in base64urlUInt encoding
	 */
	public function __construct($d) {
		parent::__construct(self::PARAM_PRIVATE_EXPONENT, $d);
	}
}

<?php

namespace JWX\JWK\Parameter;


class ExponentParameter extends RegisteredJWKParameter
{
	/**
	 * Constructor
	 *
	 * @param string $e Exponent in base64urlUInt encoding
	 */
	public function __construct($e) {
		parent::__construct(self::PARAM_EXPONENT, $e);
	}
}

<?php

namespace JWX\JWK\Parameter;


class ModulusParameter extends RegisteredJWKParameter
{
	/**
	 * Constructor
	 *
	 * @param string $n Modulus in base64urlUInt encoding
	 */
	public function __construct($n) {
		parent::__construct(self::PARAM_MODULUS, $n);
	}
}

<?php

namespace JWX\JWK\Parameter;


class ECCPrivateKeyParameter extends RegisteredJWKParameter
{
	/**
	 * Constructor
	 *
	 * @param string $key Private key in base64url encoding
	 */
	public function __construct($key) {
		parent::__construct(self::PARAM_ECC_PRIVATE_KEY, $key);
	}
}

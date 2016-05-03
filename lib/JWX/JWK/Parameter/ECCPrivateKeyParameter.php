<?php

namespace JWX\JWK\Parameter;


/**
 * Implements 'ECC Private Key' parameter.
 *
 * @link https://tools.ietf.org/html/rfc7518#section-6.2.2.1
 */
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

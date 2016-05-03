<?php

namespace JWX\JWK\Parameter;


/**
 * Implements 'Public Key Use' parameter.
 *
 * @link https://tools.ietf.org/html/rfc7517#section-4.2
 */
class PublicKeyUseParameter extends RegisteredJWKParameter
{
	const USE_SIGNATURE = "sig";
	const USE_ENCRYPTION = "enc";
	
	/**
	 * Constructor
	 *
	 * @param string $use Intended use of the public key
	 */
	public function __construct($use) {
		parent::__construct(self::PARAM_PUBLIC_KEY_USE, $use);
	}
}

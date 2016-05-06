<?php

namespace JWX\JWK\Parameter;

use JWX\JWT\Parameter\Feature\Base64URLValue;


/**
 * Implements 'ECC Private Key' parameter.
 *
 * @link https://tools.ietf.org/html/rfc7518#section-6.2.2.1
 */
class ECCPrivateKeyParameter extends RegisteredJWKParameter
{
	use Base64URLValue;
	
	/**
	 * Constructor
	 *
	 * @param string $key Private key in base64url encoding
	 */
	public function __construct($key) {
		$this->_validateEncoding($key);
		parent::__construct(self::PARAM_ECC_PRIVATE_KEY, $key);
	}
}

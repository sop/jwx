<?php

namespace JWX\JWT\Parameter;


/**
 * PBES2 Salt Input parameter
 *
 * @link https://tools.ietf.org/html/rfc7518#section-4.8.1.1
 */
class PBES2SaltInputParameter extends RegisteredJWTParameter
{
	/**
	 * Constructor
	 *
	 * @param string $salt Base64url encoded salt input value
	 */
	public function __construct($salt) {
		parent::__construct(self::PARAM_PBES2_SALT_INPUT, (string) $salt);
	}
}

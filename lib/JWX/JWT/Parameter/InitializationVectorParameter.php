<?php

namespace JWX\JWT\Parameter;


/**
 * Initialization Vector parameter
 *
 * @link https://tools.ietf.org/html/rfc7518#section-4.7.1.1
 */
class InitializationVectorParameter extends RegisteredJWTParameter
{
	/**
	 * Constructor
	 *
	 * @param string $iv Base64url encoded initialization vector
	 */
	public function __construct($iv) {
		parent::__construct(self::PARAM_INITIALIZATION_VECTOR, (string) $iv);
	}
}

<?php

namespace JWX\JWT\Parameter;


/**
 * Authentication Tag parameter
 *
 * @link https://tools.ietf.org/html/rfc7518#section-4.7.1.2
 */
class AuthenticationTagParameter extends RegisteredJWTParameter
{
	/**
	 * Constructor
	 *
	 * @param string $tag Base64url encoded authentication tag
	 */
	public function __construct($tag) {
		parent::__construct(self::PARAM_AUTHENTICATION_TAG, (string) $tag);
	}
}

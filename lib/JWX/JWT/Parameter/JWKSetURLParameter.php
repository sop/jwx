<?php

namespace JWX\JWT\Parameter;


/**
 * Implements 'JWK Set URL' parameter.
 *
 * @link https://tools.ietf.org/html/rfc7515#section-4.1.2
 */
class JWKSetURLParameter extends JWTParameter
{
	/**
	 * Constructor
	 *
	 * @param string $uri
	 */
	public function __construct($uri) {
		parent::__construct(self::PARAM_JWK_SET_URL, (string) $uri);
	}
}

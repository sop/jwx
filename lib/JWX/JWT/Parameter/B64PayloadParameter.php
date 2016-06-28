<?php

namespace JWX\JWT\Parameter;


/**
 * Implements 'base64url-encode payload' parameter.
 *
 * @link https://tools.ietf.org/html/rfc7797#section-3
 */
class B64PayloadParameter extends JWTParameter
{
	/**
	 * Constructor
	 *
	 * @param bool $flag
	 */
	public function __construct($flag) {
		parent::__construct(self::PARAM_BASE64URL_ENCODE_PAYLOAD, (bool) $flag);
	}
}

<?php

namespace JWX\JWT\Parameter;

use JWX\Parameter\Feature\Base64URLValue;
use JWX\Util\Base64;


/**
 * Implements 'Authentication Tag' parameter.
 *
 * @link https://tools.ietf.org/html/rfc7518#section-4.7.1.2
 */
class AuthenticationTagParameter extends JWTParameter
{
	use Base64URLValue;
	
	/**
	 * Constructor
	 *
	 * @param string $tag Base64url encoded authentication tag
	 */
	public function __construct($tag) {
		$this->_validateEncoding($tag);
		parent::__construct(self::PARAM_AUTHENTICATION_TAG, (string) $tag);
	}
	
	/**
	 * Get authentication tag.
	 *
	 * @return string
	 */
	public function authenticationTag() {
		return Base64::urlDecode($this->_value);
	}
}

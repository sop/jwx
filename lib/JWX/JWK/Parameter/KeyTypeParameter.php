<?php

namespace JWX\JWK\Parameter;


/**
 * Implements 'Key Type' parameter.
 *
 * @link https://tools.ietf.org/html/rfc7517#section-4.1
 */
class KeyTypeParameter extends RegisteredJWKParameter
{
	const TYPE_OCT = "oct";
	const TYPE_RSA = "RSA";
	const TYPE_EC = "EC";
	
	/**
	 * Constructor
	 *
	 * @param string $type Key type
	 */
	public function __construct($type) {
		parent::__construct(self::PARAM_KEY_TYPE, $type);
	}
}

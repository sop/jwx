<?php

namespace JWX\JWT\Parameter;


/**
 * Key ID parameter
 *
 * @link https://tools.ietf.org/html/rfc7515#section-4.1.4
 */
class KeyIDParameter extends RegisteredJWTParameter
{
	/**
	 * Constructor
	 *
	 * @param string $id
	 */
	public function __construct($id) {
		parent::__construct(self::PARAM_KEY_ID, $id);
	}
}

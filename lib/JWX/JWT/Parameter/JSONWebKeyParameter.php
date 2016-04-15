<?php

namespace JWX\JWT\Parameter;

use JWX\JWK\JWK;


/**
 * JSON Web Key parameter
 *
 * @link https://tools.ietf.org/html/rfc7515#section-4.1.3
 */
class JSONWebKeyParameter extends RegisteredJWTParameter
{
	/**
	 * Constructor
	 *
	 * @param JWK $jwk
	 */
	public function __construct(JWK $jwk) {
		parent::__construct(self::PARAM_JSON_WEB_KEY, $jwk->toArray());
	}
	
	public static function fromJSONValue($value) {
		if (!is_array($value)) {
			throw new \UnexpectedValueException("Array expected");
		}
		return new static(JWK::fromArray($value));
	}
}

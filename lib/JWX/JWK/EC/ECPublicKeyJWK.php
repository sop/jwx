<?php

namespace JWX\JWK\EC;

use JWX\JWK\JWK;
use JWX\JWK\Parameter\JWKParameter;
use JWX\JWK\Parameter\KeyTypeParameter;
use JWX\JWK\Parameter\RegisteredJWKParameter;


/**
 * Class representing elliptic curve public key as a JWK.
 *
 * @link https://tools.ietf.org/html/rfc7517#section-4
 * @link https://tools.ietf.org/html/rfc7518#section-6.2
 * @link https://tools.ietf.org/html/rfc7518#section-6.2.1
 */
class ECPublicKeyJWK extends JWK
{
	/**
	 * Parameter names managed by this class.
	 *
	 * @var string[]
	 */
	const MANAGED_PARAMS = array(
		/* @formatter:off */
		RegisteredJWKParameter::PARAM_KEY_TYPE, 
		RegisteredJWKParameter::PARAM_CURVE, 
		RegisteredJWKParameter::PARAM_X_COORDINATE
		/* @formatter:on */
	);
	
	/**
	 * Constructor
	 *
	 * @param JWKParameter ...$params
	 * @throws \UnexpectedValueException If missing required parameter
	 */
	public function __construct(JWKParameter ...$params) {
		parent::__construct(...$params);
		foreach (self::MANAGED_PARAMS as $name) {
			if (!$this->has($name)) {
				throw new \UnexpectedValueException("Missing '$name' parameter.");
			}
		}
		if ($this->get(RegisteredJWKParameter::PARAM_KEY_TYPE)->value() !=
			 KeyTypeParameter::TYPE_EC) {
			throw new \UnexpectedValueException("Invalid key type.");
		}
	}
}

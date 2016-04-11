<?php

namespace JWX\JWK\Parameter;


abstract class RegisteredJWKParameter extends JWKParameter
{
	const PARAM_KEY_TYPE = "kty";
	const PARAM_PUBLIC_KEY_USE = "use";
	const PARAM_KEY_OPERATIONS = "key_ops";
	const PARAM_ALGORITHM = "alg";
	const PARAM_KEY_ID = "kid";
	
	/**
	 * Mapping from registered JWK parameter name to class name
	 *
	 * @var array
	 */
	public static $nameToCls = array(
		// @formatter:off
		self::PARAM_KEY_TYPE => KeyTypeParameter::class,
		self::PARAM_PUBLIC_KEY_USE => PublicKeyUseParameter::class,
		self::PARAM_KEY_OPERATIONS => KeyOperationsParameter::class,
		self::PARAM_ALGORITHM => AlgorithmParameter::class,
		self::PARAM_KEY_ID => KeyIDParameter::class
	);	// @formatter:on
	

	/**
	 * Initialize concrete JWK parameter instance from JSON value
	 *
	 * @param mixed $value
	 * @return RegisteredJWKParameter
	 */
	public static function fromJSONValue($value) {
		return new static($value);
	}
}

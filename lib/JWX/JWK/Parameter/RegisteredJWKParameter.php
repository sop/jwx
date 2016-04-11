<?php

namespace JWX\JWK\Parameter;


/**
 * IANA registered JSON Web Key Parameters
 *
 * @link http://www.iana.org/assignments/jose/jose.xhtml#web-key-parameters
 */
abstract class RegisteredJWKParameter extends JWKParameter
{
	const PARAM_KEY_TYPE = "kty";
	const PARAM_PUBLIC_KEY_USE = "use";
	const PARAM_KEY_OPERATIONS = "key_ops";
	const PARAM_ALGORITHM = "alg";
	const PARAM_KEY_ID = "kid";
	const PARAM_X509_URL = "x5u";
	const PARAM_X509_CERTIFICATE_CHAIN = "x5c";
	const PARAM_X509_CERTIFICATE_SHA1_THUMBPRINT = "x5t";
	const PARAM_X509_CERTIFICATE_SHA256_THUMBPRINT = "x5t#S256";
	const PARAM_CURVE = "crv";
	const PARAM_X_COORDINATE = "x";
	const PARAM_Y_COORDINATE = "y";
	const PARAM_ECC_PRIVATE_KEY = "d";
	const PARAM_MODULUS = "n";
	const PARAM_EXPONENT = "e";
	const PARAM_PRIVATE_EXPONENT = "d";
	const PARAM_FIRST_PRIME_FACTOR = "p";
	const PARAM_SECOND_PRIME_FACTOR = "q";
	const PARAM_FIRST_FACTOR_CRT_EXPONENT = "dp";
	const PARAM_SECOND_FACTOR_CRT_EXPONENT = "dq";
	const PARAM_FIRST_CRT_COEFFICIENT = "qi";
	const PARAM_OTHER_PRIMES_INFO = "oth";
	const PARAM_KEY_VALUE = "k";
	
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
		self::PARAM_KEY_ID => KeyIDParameter::class,
		self::PARAM_CURVE => CurveParameter::class,
		self::PARAM_X_COORDINATE => XCoordinateParameter::class,
		self::PARAM_Y_COORDINATE => YCoordinateParameter::class,
		self::PARAM_ECC_PRIVATE_KEY => ECCPrivateKeyParameter::class,
		self::PARAM_MODULUS => ModulusParameter::class,
		self::PARAM_EXPONENT => ExponentParameter::class,
		self::PARAM_PRIVATE_EXPONENT => PrivateExponentParameter::class,
		self::PARAM_FIRST_PRIME_FACTOR => FirstPrimeFactorParameter::class,
		self::PARAM_SECOND_PRIME_FACTOR => SecondPrimeFactorParameter::class,
		self::PARAM_FIRST_FACTOR_CRT_EXPONENT => 
			FirstFactorCRTExponentParameter::class,
		self::PARAM_SECOND_FACTOR_CRT_EXPONENT => 
			SecondFactorCRTExponentParameter::class,
		self::PARAM_FIRST_CRT_COEFFICIENT =>
			FirstCRTCoefficientParameter::class,
		self::PARAM_OTHER_PRIMES_INFO => OtherPrimesInfoParameter::class,
		self::PARAM_KEY_VALUE => KeyValueParameter::class
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

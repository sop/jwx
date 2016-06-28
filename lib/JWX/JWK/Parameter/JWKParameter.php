<?php

namespace JWX\JWK\Parameter;

use JWX\Parameter\Parameter;


/**
 * Represents a single JWK parameter.
 *
 * @link https://tools.ietf.org/html/rfc7517#section-4
 * @link http://www.iana.org/assignments/jose/jose.xhtml#web-key-parameters
 */
class JWKParameter extends Parameter
{
	// registered parameter names
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
	
	// shorthand aliases for parameter names
	const P_KTY = self::PARAM_KEY_TYPE;
	const P_USE = self::PARAM_PUBLIC_KEY_USE;
	const P_KEY_OPS = self::PARAM_KEY_OPERATIONS;
	const P_ALG = self::PARAM_ALGORITHM;
	const P_KID = self::PARAM_KEY_ID;
	const P_X5U = self::PARAM_X509_URL;
	const P_X5C = self::PARAM_X509_CERTIFICATE_CHAIN;
	const P_X5T = self::PARAM_X509_CERTIFICATE_SHA1_THUMBPRINT;
	const P_X5TS256 = self::PARAM_X509_CERTIFICATE_SHA256_THUMBPRINT;
	const P_CRV = self::PARAM_CURVE;
	const P_X = self::PARAM_X_COORDINATE;
	const P_Y = self::PARAM_Y_COORDINATE;
	const P_ECC_D = self::PARAM_ECC_PRIVATE_KEY;
	const P_N = self::PARAM_MODULUS;
	const P_E = self::PARAM_EXPONENT;
	const P_RSA_D = self::PARAM_PRIVATE_EXPONENT;
	const P_P = self::PARAM_FIRST_PRIME_FACTOR;
	const P_Q = self::PARAM_SECOND_PRIME_FACTOR;
	const P_DP = self::PARAM_FIRST_FACTOR_CRT_EXPONENT;
	const P_DQ = self::PARAM_SECOND_FACTOR_CRT_EXPONENT;
	const P_QI = self::PARAM_FIRST_CRT_COEFFICIENT;
	const P_OTH = self::PARAM_OTHER_PRIMES_INFO;
	const P_K = self::PARAM_KEY_VALUE;
	
	/**
	 * Mapping from registered JWK parameter name to class name.
	 *
	 * Note that ECC private key and RSA private key cannot be mapped since
	 * they share the same parameter name 'd'.
	 *
	 * @internal
	 *
	 * @var array
	 */
	const MAP_NAME_TO_CLASS = array(
		/* @formatter:off */
		self::P_KTY => KeyTypeParameter::class,
		self::P_USE => PublicKeyUseParameter::class,
		self::P_KEY_OPS => KeyOperationsParameter::class,
		self::P_ALG => AlgorithmParameter::class,
		self::P_KID => KeyIDParameter::class,
		self::P_CRV => CurveParameter::class,
		self::P_X => XCoordinateParameter::class,
		self::P_Y => YCoordinateParameter::class,
		self::P_N => ModulusParameter::class,
		self::P_E => ExponentParameter::class,
		self::P_P => FirstPrimeFactorParameter::class,
		self::P_Q => SecondPrimeFactorParameter::class,
		self::P_DP => FirstFactorCRTExponentParameter::class,
		self::P_DQ => SecondFactorCRTExponentParameter::class,
		self::P_QI => FirstCRTCoefficientParameter::class,
		self::P_OTH => OtherPrimesInfoParameter::class,
		self::P_K => KeyValueParameter::class
		/* @formatter:on */
	);
	
	/**
	 * Constructor.
	 *
	 * @param string $name Parameter name
	 * @param mixed $value Parameter value
	 */
	public function __construct($name, $value) {
		$this->_name = $name;
		$this->_value = $value;
	}
	
	/**
	 * Initialize from a name and a value.
	 *
	 * Returns a parameter specific object if one is implemented.
	 *
	 * @param string $name Parameter name
	 * @param mixed $value Parameter value
	 * @return self
	 */
	public static function fromNameAndValue($name, $value) {
		if (array_key_exists($name, self::MAP_NAME_TO_CLASS)) {
			$cls = self::MAP_NAME_TO_CLASS[$name];
			return $cls::fromJSONValue($value);
		}
		return new self($name, $value);
	}
	
	/**
	 * Initialize a concrete JWK parameter instance from a JSON value.
	 *
	 * @param mixed $value
	 * @return self
	 */
	public static function fromJSONValue($value) {
		return new static($value);
	}
}

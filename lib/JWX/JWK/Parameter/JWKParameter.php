<?php

declare(strict_types = 1);

namespace Sop\JWX\JWK\Parameter;

use Sop\JWX\Parameter\Parameter;

/**
 * Represents a single JWK parameter.
 *
 * @see https://tools.ietf.org/html/rfc7517#section-4
 * @see http://www.iana.org/assignments/jose/jose.xhtml#web-key-parameters
 */
class JWKParameter extends Parameter
{
    // registered parameter names
    public const PARAM_KEY_TYPE = 'kty';
    public const PARAM_PUBLIC_KEY_USE = 'use';
    public const PARAM_KEY_OPERATIONS = 'key_ops';
    public const PARAM_ALGORITHM = 'alg';
    public const PARAM_KEY_ID = 'kid';
    public const PARAM_X509_URL = 'x5u';
    public const PARAM_X509_CERTIFICATE_CHAIN = 'x5c';
    public const PARAM_X509_CERTIFICATE_SHA1_THUMBPRINT = 'x5t';
    public const PARAM_X509_CERTIFICATE_SHA256_THUMBPRINT = 'x5t#S256';
    public const PARAM_CURVE = 'crv';
    public const PARAM_X_COORDINATE = 'x';
    public const PARAM_Y_COORDINATE = 'y';
    public const PARAM_ECC_PRIVATE_KEY = 'd';
    public const PARAM_MODULUS = 'n';
    public const PARAM_EXPONENT = 'e';
    public const PARAM_PRIVATE_EXPONENT = 'd';
    public const PARAM_FIRST_PRIME_FACTOR = 'p';
    public const PARAM_SECOND_PRIME_FACTOR = 'q';
    public const PARAM_FIRST_FACTOR_CRT_EXPONENT = 'dp';
    public const PARAM_SECOND_FACTOR_CRT_EXPONENT = 'dq';
    public const PARAM_FIRST_CRT_COEFFICIENT = 'qi';
    public const PARAM_OTHER_PRIMES_INFO = 'oth';
    public const PARAM_KEY_VALUE = 'k';

    // shorthand aliases for parameter names
    public const P_KTY = self::PARAM_KEY_TYPE;
    public const P_USE = self::PARAM_PUBLIC_KEY_USE;
    public const P_KEY_OPS = self::PARAM_KEY_OPERATIONS;
    public const P_ALG = self::PARAM_ALGORITHM;
    public const P_KID = self::PARAM_KEY_ID;
    public const P_X5U = self::PARAM_X509_URL;
    public const P_X5C = self::PARAM_X509_CERTIFICATE_CHAIN;
    public const P_X5T = self::PARAM_X509_CERTIFICATE_SHA1_THUMBPRINT;
    public const P_X5TS256 = self::PARAM_X509_CERTIFICATE_SHA256_THUMBPRINT;
    public const P_CRV = self::PARAM_CURVE;
    public const P_X = self::PARAM_X_COORDINATE;
    public const P_Y = self::PARAM_Y_COORDINATE;
    public const P_ECC_D = self::PARAM_ECC_PRIVATE_KEY;
    public const P_N = self::PARAM_MODULUS;
    public const P_E = self::PARAM_EXPONENT;
    public const P_RSA_D = self::PARAM_PRIVATE_EXPONENT;
    public const P_P = self::PARAM_FIRST_PRIME_FACTOR;
    public const P_Q = self::PARAM_SECOND_PRIME_FACTOR;
    public const P_DP = self::PARAM_FIRST_FACTOR_CRT_EXPONENT;
    public const P_DQ = self::PARAM_SECOND_FACTOR_CRT_EXPONENT;
    public const P_QI = self::PARAM_FIRST_CRT_COEFFICIENT;
    public const P_OTH = self::PARAM_OTHER_PRIMES_INFO;
    public const P_K = self::PARAM_KEY_VALUE;

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
    public const MAP_NAME_TO_CLASS = [
        self::P_KTY => KeyTypeParameter::class,
        self::P_USE => PublicKeyUseParameter::class,
        self::P_KEY_OPS => KeyOperationsParameter::class,
        self::P_ALG => AlgorithmParameter::class,
        self::P_KID => KeyIDParameter::class,
        self::P_X5U => X509URLParameter::class,
        self::P_X5C => X509CertificateChainParameter::class,
        self::P_X5T => X509CertificateSHA1ThumbprintParameter::class,
        self::P_X5TS256 => X509CertificateSHA256ThumbprintParameter::class,
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
        self::P_K => KeyValueParameter::class,
    ];

    /**
     * Constructor.
     *
     * @param string $name  Parameter name
     * @param mixed  $value Parameter value
     */
    public function __construct(string $name, $value)
    {
        $this->_name = $name;
        $this->_value = $value;
    }

    /**
     * Initialize from a name and a value.
     *
     * Returns a parameter specific object if one is implemented.
     *
     * @param string $name  Parameter name
     * @param mixed  $value Parameter value
     */
    public static function fromNameAndValue(string $name, $value): self
    {
        if (array_key_exists($name, self::MAP_NAME_TO_CLASS)) {
            $cls = self::MAP_NAME_TO_CLASS[$name];
            return $cls::fromJSONValue($value);
        }
        return new self($name, $value);
    }

    /**
     * Initialize from a JSON value.
     *
     * @param mixed $value
     *
     * @return JWKParameter
     */
    public static function fromJSONValue($value): Parameter
    {
        throw new \BadMethodCallException(
            __FUNCTION__ . ' must be implemented in a derived class.');
    }
}

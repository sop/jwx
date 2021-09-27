<?php

declare(strict_types = 1);

namespace Sop\JWX\JWT\Parameter;

use Sop\JWX\Parameter\Parameter;

/**
 * Represents a header parameter.
 *
 * @see https://tools.ietf.org/html/rfc7519#section-5
 * @see http://www.iana.org/assignments/jose/jose.xhtml#web-signature-encryption-header-parameters
 */
class JWTParameter extends Parameter
{
    // registered parameter names
    public const PARAM_ALGORITHM = 'alg';
    public const PARAM_JWK_SET_URL = 'jku';
    public const PARAM_JSON_WEB_KEY = 'jwk';
    public const PARAM_KEY_ID = 'kid';
    public const PARAM_X509_URL = 'x5u';
    public const PARAM_X509_CERTIFICATE_CHAIN = 'x5c';
    public const PARAM_X509_CERTIFICATE_SHA1_THUMBPRINT = 'x5t';
    public const PARAM_X509_CERTIFICATE_SHA256_THUMBPRINT = 'x5t#S256';
    public const PARAM_TYPE = 'typ';
    public const PARAM_CONTENT_TYPE = 'cty';
    public const PARAM_CRITICAL = 'crit';
    public const PARAM_ENCRYPTION_ALGORITHM = 'enc';
    public const PARAM_COMPRESSION_ALGORITHM = 'zip';
    public const PARAM_EPHEMERAL_PUBLIC_KEY = 'epk';
    public const PARAM_AGREEMENT_PARTYUINFO = 'apu';
    public const PARAM_AGREEMENT_PARTYVINFO = 'apv';
    public const PARAM_INITIALIZATION_VECTOR = 'iv';
    public const PARAM_AUTHENTICATION_TAG = 'tag';
    public const PARAM_PBES2_SALT_INPUT = 'p2s';
    public const PARAM_PBES2_COUNT = 'p2c';
    public const PARAM_BASE64URL_ENCODE_PAYLOAD = 'b64';

    // shorthand aliases for parameter names
    public const P_ALG = self::PARAM_ALGORITHM;
    public const P_JKU = self::PARAM_JWK_SET_URL;
    public const P_JWK = self::PARAM_JSON_WEB_KEY;
    public const P_KID = self::PARAM_KEY_ID;
    public const P_X5U = self::PARAM_X509_URL;
    public const P_X5C = self::PARAM_X509_CERTIFICATE_CHAIN;
    public const P_X5T = self::PARAM_X509_CERTIFICATE_SHA1_THUMBPRINT;
    public const P_X5TS256 = self::PARAM_X509_CERTIFICATE_SHA256_THUMBPRINT;
    public const P_TYP = self::PARAM_TYPE;
    public const P_CTY = self::PARAM_CONTENT_TYPE;
    public const P_CRIT = self::PARAM_CRITICAL;
    public const P_ENC = self::PARAM_ENCRYPTION_ALGORITHM;
    public const P_ZIP = self::PARAM_COMPRESSION_ALGORITHM;
    public const P_EPK = self::PARAM_EPHEMERAL_PUBLIC_KEY;
    public const P_APU = self::PARAM_AGREEMENT_PARTYUINFO;
    public const P_APV = self::PARAM_AGREEMENT_PARTYVINFO;
    public const P_IV = self::PARAM_INITIALIZATION_VECTOR;
    public const P_TAG = self::PARAM_AUTHENTICATION_TAG;
    public const P_P2S = self::PARAM_PBES2_SALT_INPUT;
    public const P_P2C = self::PARAM_PBES2_COUNT;
    public const P_B64 = self::PARAM_BASE64URL_ENCODE_PAYLOAD;

    /**
     * Mapping from registered JWT parameter name to class name.
     *
     * @internal
     *
     * @var array
     */
    public const MAP_NAME_TO_CLASS = [
        self::P_ALG => AlgorithmParameter::class,
        self::P_JKU => JWKSetURLParameter::class,
        self::P_JWK => JSONWebKeyParameter::class,
        self::P_KID => KeyIDParameter::class,
        self::P_X5U => X509URLParameter::class,
        self::P_X5C => X509CertificateChainParameter::class,
        self::P_X5T => X509CertificateSHA1ThumbprintParameter::class,
        self::P_X5TS256 => X509CertificateSHA256ThumbprintParameter::class,
        self::P_TYP => TypeParameter::class,
        self::P_CTY => ContentTypeParameter::class,
        self::P_CRIT => CriticalParameter::class,
        self::P_ENC => EncryptionAlgorithmParameter::class,
        self::P_ZIP => CompressionAlgorithmParameter::class,
        self::P_IV => InitializationVectorParameter::class,
        self::P_TAG => AuthenticationTagParameter::class,
        self::P_P2S => PBES2SaltInputParameter::class,
        self::P_P2C => PBES2CountParameter::class,
        self::P_B64 => B64PayloadParameter::class,
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
     * @return JWTParameter
     */
    public static function fromJSONValue($value): Parameter
    {
        throw new \BadMethodCallException(
            __FUNCTION__ . ' must be implemented in a derived class.');
    }
}

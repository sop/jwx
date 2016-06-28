<?php

namespace JWX\JWT\Parameter;

use JWX\Parameter\Parameter;


/**
 * Represents a header parameter.
 *
 * @link https://tools.ietf.org/html/rfc7519#section-5
 * @link
 *       http://www.iana.org/assignments/jose/jose.xhtml#web-signature-encryption-header-parameters
 */
class JWTParameter extends Parameter
{
	// registered parameter names
	const PARAM_ALGORITHM = "alg";
	const PARAM_JWK_SET_URL = "jku";
	const PARAM_JSON_WEB_KEY = "jwk";
	const PARAM_KEY_ID = "kid";
	const PARAM_X509_URL = "x5u";
	const PARAM_X509_CERTIFICATE_CHAIN = "x5c";
	const PARAM_X509_CERTIFICATE_SHA1_THUMBPRINT = "x5t";
	const PARAM_X509_CERTIFICATE_SHA256_THUMBPRINT = "x5t#S256";
	const PARAM_TYPE = "typ";
	const PARAM_CONTENT_TYPE = "cty";
	const PARAM_CRITICAL = "crit";
	const PARAM_ENCRYPTION_ALGORITHM = "enc";
	const PARAM_COMPRESSION_ALGORITHM = "zip";
	const PARAM_EPHEMERAL_PUBLIC_KEY = "epk";
	const PARAM_AGREEMENT_PARTYUINFO = "apu";
	const PARAM_AGREEMENT_PARTYVINFO = "apv";
	const PARAM_INITIALIZATION_VECTOR = "iv";
	const PARAM_AUTHENTICATION_TAG = "tag";
	const PARAM_PBES2_SALT_INPUT = "p2s";
	const PARAM_PBES2_COUNT = "p2c";
	const PARAM_BASE64URL_ENCODE_PAYLOAD = "b64";
	
	// shorthand aliases for parameter names
	const P_ALG = self::PARAM_ALGORITHM;
	const P_JKU = self::PARAM_JWK_SET_URL;
	const P_JWK = self::PARAM_JSON_WEB_KEY;
	const P_KID = self::PARAM_KEY_ID;
	const P_X5U = self::PARAM_X509_URL;
	const P_X5C = self::PARAM_X509_CERTIFICATE_CHAIN;
	const P_X5T = self::PARAM_X509_CERTIFICATE_SHA1_THUMBPRINT;
	const P_X5TS256 = self::PARAM_X509_CERTIFICATE_SHA256_THUMBPRINT;
	const P_TYP = self::PARAM_TYPE;
	const P_CTY = self::PARAM_CONTENT_TYPE;
	const P_CRIT = self::PARAM_CRITICAL;
	const P_ENC = self::PARAM_ENCRYPTION_ALGORITHM;
	const P_ZIP = self::PARAM_COMPRESSION_ALGORITHM;
	const P_EPK = self::PARAM_EPHEMERAL_PUBLIC_KEY;
	const P_APU = self::PARAM_AGREEMENT_PARTYUINFO;
	const P_APV = self::PARAM_AGREEMENT_PARTYVINFO;
	const P_IV = self::PARAM_INITIALIZATION_VECTOR;
	const P_TAG = self::PARAM_AUTHENTICATION_TAG;
	const P_P2S = self::PARAM_PBES2_SALT_INPUT;
	const P_P2C = self::PARAM_PBES2_COUNT;
	const P_B64 = self::PARAM_BASE64URL_ENCODE_PAYLOAD;
	
	/**
	 * Mapping from registered JWT parameter name to class name.
	 *
	 * @internal
	 *
	 * @var array
	 */
	const MAP_NAME_TO_CLASS = array(
		/* @formatter:off */
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
		self::P_B64 => B64PayloadParameter::class
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
	 * Initialize a concrete JWT parameter instance from a JSON value.
	 *
	 * @param mixed $value
	 * @return self
	 */
	public static function fromJSONValue($value) {
		return new static($value);
	}
}

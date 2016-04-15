<?php

namespace JWX\JWT\Parameter;


/**
 * Registered header parameters.
 *
 * @link
 *       http://www.iana.org/assignments/jose/jose.xhtml#web-signature-encryption-header-parameters
 */
abstract class RegisteredJWTParameter extends JWTParameter
{
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
	const PARAM_ISSUER = "iss";
	const PARAM_SUBJECT = "sub";
	const PARAM_AUDIENCE = "aud";
	const PARAM_BASE64URL_ENCODE_PAYLOAD = "b64";
	
	/**
	 * Mapping from registered JWT parameter name to class name
	 *
	 * @var array
	 */
	public static $nameToCls = array(
		/* @formatter:off */
		self::PARAM_ALGORITHM => AlgorithmParameter::class,
		self::PARAM_TYPE => TypeParameter::class,
		self::PARAM_CONTENT_TYPE => ContentTypeParameter::class,
		self::PARAM_ENCRYPTION_ALGORITHM => EncryptionAlgorithmParameter::class
		/* @formatter:on */
	);
	
	/**
	 * Initialize concrete JWT parameter instance from JSON value
	 *
	 * @param mixed $value
	 * @return RegisteredJWTParameter
	 */
	public static function fromJSONValue($value) {
		return new static($value);
	}
}

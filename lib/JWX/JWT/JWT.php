<?php

namespace JWX\JWT;

use JWX\JWE\CompressionAlgorithm;
use JWX\JWE\ContentEncryptionAlgorithm;
use JWX\JWE\JWE;
use JWX\JWE\KeyManagementAlgorithm;
use JWX\JWK\JWKSet;
use JWX\JWS\Algorithm\NoneAlgorithm;
use JWX\JWS\JWS;
use JWX\JWS\SignatureAlgorithm;
use JWX\JWT\Claims;
use JWX\JWT\Exception\ValidationException;
use JWX\JWT\Header\Header;
use JWX\JWT\Header\JOSE;
use JWX\JWT\Parameter\ContentTypeParameter;
use JWX\Util\Base64;


/**
 * Represents a token as a JWS or a JWE compact serialization with claims
 * as a payload.
 *
 * @link https://tools.ietf.org/html/rfc7519#section-3
 */
class JWT
{
	/**
	 * Type identifier for signed JWT.
	 *
	 * @internal
	 *
	 * @var int
	 */
	const TYPE_JWS = 0;
	
	/**
	 * Type identifier for encrypted JWT.
	 *
	 * @internal
	 *
	 * @var int
	 */
	const TYPE_JWE = 1;
	
	/**
	 * JWT parts.
	 *
	 * @var string[] $_parts
	 */
	protected $_parts;
	
	/**
	 * JWT type.
	 *
	 * @var int $_type
	 */
	protected $_type;
	
	/**
	 * Constructor
	 *
	 * @param string $token JWT string
	 * @throws \UnexpectedValueException
	 */
	public function __construct($token) {
		$this->_parts = explode(".", $token);
		switch (count($this->_parts)) {
		case 3:
			$this->_type = self::TYPE_JWS;
			break;
		case 5:
			$this->_type = self::TYPE_JWE;
			break;
		default:
			throw new \UnexpectedValueException("Not a JWT token.");
		}
	}
	
	/**
	 * Convert claims set to an unsecured JWT.
	 *
	 * @param Claims $claims Claims set
	 * @param Header|null $header Optional header
	 * @throws \RuntimeException For generic errors
	 * @return self
	 */
	public static function unsecuredFromClaims(Claims $claims, 
			Header $header = null) {
		return self::signedFromClaims($claims, new NoneAlgorithm(), $header);
	}
	
	/**
	 * Convert claims set to a signed JWS token.
	 *
	 * @param Claims $claims Claims set
	 * @param SignatureAlgorithm $algo Signature algorithm
	 * @param Header|null $header Optional header
	 * @throws \RuntimeException For generic errors
	 * @return self
	 */
	public static function signedFromClaims(Claims $claims, 
			SignatureAlgorithm $algo, Header $header = null) {
		$payload = $claims->toJSON();
		$jws = JWS::sign($payload, $algo, $header);
		return new self($jws->toCompact());
	}
	
	/**
	 * Convert claims set to an encrypted JWE token.
	 *
	 * @param Claims $claims Claims set
	 * @param KeyManagementAlgorithm $key_algo Key management algorithm
	 * @param ContentEncryptionAlgorithm $enc_algo Content encryption algorithm
	 * @param CompressionAlgorithm|null $zip_algo Optional compression algorithm
	 * @param Header|null $header Optional header
	 * @throws \RuntimeException For generic errors
	 * @return self
	 */
	public static function encryptedFromClaims(Claims $claims, 
			KeyManagementAlgorithm $key_algo, 
			ContentEncryptionAlgorithm $enc_algo, 
			CompressionAlgorithm $zip_algo = null, Header $header = null) {
		$payload = $claims->toJSON();
		$jwe = JWE::encrypt($payload, $key_algo, $enc_algo, $zip_algo, $header);
		return new self($jwe->toCompact());
	}
	
	/**
	 * Sign self producing a nested JWT.
	 *
	 * Note that if JWT is to be signed and encrypted, it should be done in
	 * sign-then-encrypt order. Please refer to links for security information.
	 *
	 * @link https://tools.ietf.org/html/rfc7519#section-11.2
	 * @param SignatureAlgorithm $algo Signature algorithm
	 * @param Header|null $header Optional header
	 * @throws \RuntimeException For generic errors
	 * @return self
	 */
	public function signNested(SignatureAlgorithm $algo, Header $header = null) {
		if (!isset($header)) {
			$header = new Header();
		}
		// add JWT content type parameter
		$header = $header->withParameters(
			new ContentTypeParameter(ContentTypeParameter::TYPE_JWT));
		$jws = JWS::sign($this->token(), $algo, $header);
		return new self($jws->toCompact());
	}
	
	/**
	 * Encrypt self producing a nested JWT.
	 *
	 * This JWT should be a JWS, that is, the order of nesting should be
	 * sign-then-encrypt.
	 *
	 * @link https://tools.ietf.org/html/rfc7519#section-11.2
	 * @param KeyManagementAlgorithm $key_algo Key management algorithm
	 * @param ContentEncryptionAlgorithm $enc_algo Content encryption algorithm
	 * @param CompressionAlgorithm|null $zip_algo Optional compression algorithm
	 * @param Header|null $header Optional header
	 * @throws \RuntimeException For generic errors
	 * @return self
	 */
	public function encryptNested(KeyManagementAlgorithm $key_algo, 
			ContentEncryptionAlgorithm $enc_algo, 
			CompressionAlgorithm $zip_algo = null, Header $header = null) {
		if (!isset($header)) {
			$header = new Header();
		}
		// add JWT content type parameter
		$header = $header->withParameters(
			new ContentTypeParameter(ContentTypeParameter::TYPE_JWT));
		$jwe = JWE::encrypt($this->token(), $key_algo, $enc_algo, $zip_algo, 
			$header);
		return new self($jwe->toCompact());
	}
	
	/**
	 * Whether JWT is a JWS.
	 *
	 * @return bool
	 */
	public function isJWS() {
		return $this->_type == self::TYPE_JWS;
	}
	
	/**
	 * Get JWT as a JWS.
	 *
	 * @throws \LogicException
	 * @return JWS
	 */
	public function JWS() {
		if (!$this->isJWS()) {
			throw new \LogicException("Not a JWS.");
		}
		return JWS::fromParts($this->_parts);
	}
	
	/**
	 * Whether JWT is a JWE.
	 *
	 * @return bool
	 */
	public function isJWE() {
		return $this->_type == self::TYPE_JWE;
	}
	
	/**
	 * Get JWT as a JWE.
	 *
	 * @throws \LogicException
	 * @return JWE
	 */
	public function JWE() {
		if (!$this->isJWE()) {
			throw new \LogicException("Not a JWE.");
		}
		return JWE::fromParts($this->_parts);
	}
	
	/**
	 * Check whether JWT contains another nested JWT.
	 *
	 * @return bool
	 */
	public function isNested() {
		$header = $this->header();
		if (!$header->hasContentType()) {
			return false;
		}
		$cty = $header->contentType()->value();
		if ($cty != ContentTypeParameter::TYPE_JWT) {
			return false;
		}
		return true;
	}
	
	/**
	 * Get JWT header.
	 *
	 * @return JOSE
	 */
	public function header() {
		$header = Header::fromJSON(Base64::urlDecode($this->_parts[0]));
		return new JOSE($header);
	}
	
	/**
	 * Get JWT as a string.
	 *
	 * @return string
	 */
	public function token() {
		return implode(".", $this->_parts);
	}
	
	/**
	 * Get claims from the JWT.
	 *
	 * Claims shall be validated according to given validation context.
	 * Validation context must contain all the necessary keys for the signature
	 * validation and/or content decryption.
	 *
	 * @param ValidationContext $ctx
	 * @throws ValidationException If signature is invalid, or decryption fails,
	 *         or claims validation fails.
	 * @throws \RuntimeException For generic errors
	 * @return Claims
	 */
	public function claims(ValidationContext $ctx) {
		$keys = $ctx->keys();
		// check signature or decrypt depending on the JWT type.
		if ($this->isJWS()) {
			$payload = self::_validatedPayloadFromJWS($this->JWS(), $keys);
		} else {
			$payload = self::_validatedPayloadFromJWE($this->JWE(), $keys);
		}
		// if JWT contains a nested token
		if ($this->isNested()) {
			$jwt = new JWT($payload);
			return $jwt->claims($ctx);
		}
		// decode claims and validate
		$claims = Claims::fromJSON($payload);
		$ctx->validate($claims);
		return $claims;
	}
	
	/**
	 * Get payload from JWS.
	 *
	 * @param JWS $jws JWS
	 * @param JWKSet $keys Set of keys usable for signature validation
	 * @throws ValidationException If signature validation fails
	 * @return string
	 */
	private static function _validatedPayloadFromJWS(JWS $jws, JWKSet $keys) {
		try {
			if (1 == count($keys)) {
				$valid = $jws->validateWithJWK($keys->first());
			} else {
				$valid = $jws->validateWithJWKSet($keys);
			}
		} catch (\RuntimeException $e) {
			throw new ValidationException("JWS validation failed.", null, $e);
		}
		if (!$valid) {
			throw new ValidationException("JWS signature is invalid.");
		}
		return $jws->payload();
	}
	
	/**
	 * Get payload from JWE.
	 *
	 * @param JWE $jwe JWE
	 * @param JWKSet $keys Set of keys usable for decryption
	 * @throws ValidationException If decryption fails
	 * @return string
	 */
	private static function _validatedPayloadFromJWE(JWE $jwe, JWKSet $keys) {
		try {
			if (1 == count($keys)) {
				return $jwe->decryptWithJWK($keys->first());
			}
			return $jwe->decryptWithJWKSet($keys);
		} catch (\RuntimeException $e) {
			throw new ValidationException("JWE validation failed.", null, $e);
		}
	}
	
	/**
	 * Convert JWT to string.
	 *
	 * @return string
	 */
	public function __toString() {
		return $this->token();
	}
}

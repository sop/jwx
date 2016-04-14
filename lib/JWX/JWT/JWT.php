<?php

namespace JWX\JWT;

use JWX\JWT\JOSE;
use JWX\JWT\Header;
use JWX\JWT\Claims;
use JWX\JWS\JWS;
use JWX\JWS\SignatureAlgorithm;
use JWX\JWS\Algorithm\NoneAlgorithm;
use JWX\JWE\JWE;
use JWX\JWE\KeyManagementAlgorithm;
use JWX\JWE\ContentEncryptionAlgorithm;
use JWX\Util\Base64;


/**
 * Represents a token as JWS or JWE compact serialization
 * with claims as a payload.
 */
class JWT
{
	const TYPE_JWS = 0;
	const TYPE_JWE = 1;
	
	/**
	 * JWT parts
	 *
	 * @var string[] $_parts
	 */
	protected $_parts;
	
	/**
	 * JWT type
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
		if (count($this->_parts) == 3) {
			$this->_type = self::TYPE_JWS;
		} else if (count($this->_parts) == 5) {
			$this->_type = self::TYPE_JWE;
		} else {
			throw new \UnexpectedValueException("Not a JWT token");
		}
	}
	
	/**
	 * Convert claims set to unsecured JWT
	 *
	 * @param Claims $claims Claims set
	 * @param Header|null $header Optional header
	 * @return self
	 */
	public static function unsecuredFromClaims(Claims $claims, 
		Header $header = null) {
		return self::signedFromClaims($claims, new NoneAlgorithm(), $header);
	}
	
	/**
	 * Convert claims set to signed JWS
	 *
	 * @param Claims $claims Claims set
	 * @param SignatureAlgorithm $algo Signature algorithm
	 * @param Header|null $header Optional header
	 * @return self
	 */
	public static function signedFromClaims(Claims $claims, 
		SignatureAlgorithm $algo, Header $header = null) {
		$payload = $claims->toJSON();
		if (!isset($header)) {
			$header = new Header();
		}
		$token = JWS::sign($payload, $header, $algo)->toCompact();
		return new self($token);
	}
	
	/**
	 * Convert claims set to encrypted JWE token
	 *
	 * @param Claims $claims Claims set
	 * @param KeyManagementAlgorithm $key_algo Key management algorithm
	 * @param ContentEncryptionAlgorithm $enc_algo Content encryption algorithm
	 * @param Header $header Optional header
	 * @return string
	 */
	public static function encryptedFromClaims(Claims $claims, 
		KeyManagementAlgorithm $key_algo, ContentEncryptionAlgorithm $enc_algo, 
		Header $header = null) {
		$payload = $claims->toJSON();
		if (!isset($header)) {
			$header = new Header();
		}
		$token = JWE::encrypt($payload, $header, $key_algo, $enc_algo)->toCompact();
		return new self($token);
	}
	
	/**
	 * Whether JWT is JWS
	 *
	 * @return bool
	 */
	public function isJWS() {
		return $this->_type == self::TYPE_JWS;
	}
	
	/**
	 * Get JWT as JWS
	 *
	 * @throws \LogicException
	 * @return JWS
	 */
	public function JWS() {
		if (!$this->isJWS()) {
			throw new \LogicException("Not a JWS");
		}
		return JWS::fromParts($this->_parts);
	}
	
	/**
	 * Whether JWT is JWE
	 *
	 * @return bool
	 */
	public function isJWE() {
		return $this->_type == self::TYPE_JWE;
	}
	
	/**
	 * Get JWT as a JWE
	 *
	 * @throws \LogicException
	 * @return JWE
	 */
	public function JWE() {
		if (!$this->isJWE()) {
			throw new \LogicException("Not a JWE");
		}
		return JWE::fromParts($this->_parts);
	}
	
	/**
	 * Get JWT header
	 *
	 * @return JOSE
	 */
	public function header() {
		$header = Header::fromJSON(Base64::urlDecode($this->_parts[0]));
		return new JOSE($header);
	}
	
	/**
	 * Get JWT as a string
	 *
	 * @return string
	 */
	public function token() {
		return implode(".", $this->_parts);
	}
	
	public function __toString() {
		return $this->token();
	}
}

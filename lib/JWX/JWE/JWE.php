<?php

namespace JWX\JWE;

use JWX\JWT\JOSE;
use JWX\JWT\Header;
use JWX\JWT\Parameter\AlgorithmParameter;
use JWX\JWT\Parameter\RegisteredJWTParameter;
use JWX\JWT\Parameter\EncryptionAlgorithmParameter;
use JWX\JWE\CompressionAlgorithm\CompressionFactory;
use JWX\Util\Base64;


class JWE
{
	/**
	 * Header
	 *
	 * @var Header $_protectedHeader
	 */
	protected $_protectedHeader;
	
	/**
	 * Encrypted key
	 *
	 * @var string $_encryptedKey
	 */
	protected $_encryptedKey;
	
	/**
	 * Initialization vector
	 *
	 * @var string
	 */
	protected $_iv;
	
	/**
	 * Additional authenticated data
	 *
	 * @var string $_aad
	 */
	protected $_aad;
	
	/**
	 * Ciphertext
	 *
	 * @var string $_ciphertext
	 */
	protected $_ciphertext;
	
	/**
	 * Authentication tag
	 *
	 * @var string $_authenticationTag
	 */
	protected $_authenticationTag;
	
	/**
	 * Constructor
	 *
	 * @param Header $protected_header JWE Protected Header
	 * @param string $encrypted_key Encrypted key
	 * @param string $iv Initialization vector
	 * @param string $ciphertext Ciphertext
	 * @param string $auth_tag Authentication tag
	 * @param string|null $aad Additional authenticated data
	 */
	public function __construct(Header $protected_header, $encrypted_key, $iv, 
		$ciphertext, $auth_tag, $aad = null) {
		$this->_protectedHeader = $protected_header;
		$this->_encryptedKey = $encrypted_key;
		$this->_iv = $iv;
		$this->_aad = $aad;
		$this->_ciphertext = $ciphertext;
		$this->_authenticationTag = $auth_tag;
	}
	
	/**
	 * Initialize from compact serialization
	 *
	 * @param string $data
	 * @return self
	 */
	public static function fromCompact($data) {
		return self::fromParts(explode(".", $data));
	}
	
	/**
	 * Initialize from parts of compact serialization
	 *
	 * @param array $parts
	 * @throws \UnexpectedValueException
	 * @return self
	 */
	public static function fromParts(array $parts) {
		if (count($parts) != 5) {
			throw new \UnexpectedValueException(
				"Invalid JWE compact serialization");
		}
		$header = Header::fromJSON(Base64::urlDecode($parts[0]));
		$encrypted_key = Base64::urlDecode($parts[1]);
		$iv = Base64::urlDecode($parts[2]);
		$ciphertext = Base64::urlDecode($parts[3]);
		$auth_tag = Base64::urlDecode($parts[4]);
		return new self($header, $encrypted_key, $iv, $ciphertext, $auth_tag);
	}
	
	/**
	 * Initialize by encrypting given payload
	 *
	 * @param string $payload Payload
	 * @param string $cek Content encryption key
	 * @param KeyManagementAlgorithm $key_algo Key management algorithm
	 * @param ContentEncryptionAlgorithm $enc_algo Content encryption algorithm
	 * @param Header|null $header Desired header. Algorithm specific parameters
	 *        are automatically added.
	 * @param string|null $iv Initialization vector. Randomly generated if not
	 *        set.
	 * @return self
	 */
	public static function encrypt($payload, $cek, 
		KeyManagementAlgorithm $key_algo, ContentEncryptionAlgorithm $enc_algo, 
		Header $header = null, $iv = null) {
		if (!isset($header)) {
			$header = new Header();
		}
		// generate random IV
		if (!isset($iv)) {
			$iv = openssl_random_pseudo_bytes($enc_algo->ivSize());
		}
		if (strlen($iv) != $enc_algo->ivSize()) {
			throw new \UnexpectedValueException("Invalid IV size");
		}
		// compress
		if ($header->has(RegisteredJWTParameter::PARAM_COMPRESSION_ALGORITHM)) {
			$comp_algo_name = $header->get(
				RegisteredJWTParameter::PARAM_COMPRESSION_ALGORITHM)->value();
			$compressor = CompressionFactory::algoByName($comp_algo_name);
			$payload = $compressor->compress($payload);
		}
		$header = $header->withParameters(
			AlgorithmParameter::fromAlgorithm($key_algo), 
			EncryptionAlgorithmParameter::fromAlgorithm($enc_algo));
		$aad = Base64::urlEncode($header->toJSON());
		list($ciphertext, $auth_tag) = $enc_algo->encrypt($payload, $cek, $iv, 
			$aad);
		return new self($header, $key_algo->encrypt($cek), $iv, $ciphertext, 
			$auth_tag);
	}
	
	/**
	 * Decrypt content
	 *
	 * @param KeyManagementAlgorithm $key_algo
	 * @param ContentEncryptionAlgorithm $enc_algo
	 * @return string Plaintext payload
	 */
	public function decrypt(KeyManagementAlgorithm $key_algo, 
		ContentEncryptionAlgorithm $enc_algo) {
		$cek = $key_algo->decrypt($this->_encryptedKey);
		$aad = Base64::urlEncode($this->_protectedHeader->toJSON());
		$payload = $enc_algo->decrypt($this->_ciphertext, $cek, $this->_iv, 
			$aad, $this->_authenticationTag);
		// decompress
		if ($this->_protectedHeader->has(
			RegisteredJWTParameter::PARAM_COMPRESSION_ALGORITHM)) {
			$comp_algo_name = $this->_protectedHeader->get(
				RegisteredJWTParameter::PARAM_COMPRESSION_ALGORITHM)->value();
			$decompressor = CompressionFactory::algoByName($comp_algo_name);
			$payload = $decompressor->decompress($payload);
		}
		return $payload;
	}
	
	/**
	 * Get JOSE header
	 *
	 * @return JOSE
	 */
	public function header() {
		return new JOSE($this->_protectedHeader);
	}
	
	/**
	 * Get encrypted CEK
	 *
	 * @return string
	 */
	public function encryptedKey() {
		return $this->_encryptedKey;
	}
	
	/**
	 * Get initialization vector
	 *
	 * @return string
	 */
	public function initializationVector() {
		return $this->_iv;
	}
	
	/**
	 * Get ciphertext
	 *
	 * @return string
	 */
	public function ciphertext() {
		return $this->_ciphertext;
	}
	
	/**
	 * Get authentication tag
	 *
	 * @return string
	 */
	public function authenticationTag() {
		return $this->_authenticationTag;
	}
	
	/**
	 * Convert to compact serialization
	 *
	 * @return string
	 */
	public function toCompact() {
		return Base64::urlEncode($this->_protectedHeader->toJSON()) . "." .
			 Base64::urlEncode($this->_encryptedKey) . "." .
			 Base64::urlEncode($this->_iv) . "." .
			 Base64::urlEncode($this->_ciphertext) . "." .
			 Base64::urlEncode($this->_authenticationTag);
	}
	
	/**
	 * Convert JWE to string
	 *
	 * @return string
	 */
	public function __toString() {
		return $this->toCompact();
	}
}

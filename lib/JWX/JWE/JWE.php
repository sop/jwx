<?php

namespace JWX\JWE;

use JWX\Util\Base64;
use JWX\JWT\Header;
use JWX\JWT\Parameter\AlgorithmParameter;
use JWX\JWT\Parameter\EncryptionAlgorithmParameter;


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
	 * @throws \UnexpectedValueException
	 * @return self
	 */
	public static function fromCompact($data) {
		$segments = explode(".", $data);
		if (count($segments) != 5) {
			throw new \UnexpectedValueException(
				"Invalid JWE compact serialization");
		}
		$header = Header::fromJSON(Base64::urlDecode($segments[0]));
		$encrypted_key = Base64::urlDecode($segments[1]);
		$iv = Base64::urlDecode($segments[2]);
		$ciphertext = Base64::urlDecode($segments[3]);
		$auth_tag = Base64::urlDecode($segments[4]);
		return new self($header, $encrypted_key, $iv, $ciphertext, $auth_tag);
	}
	
	/**
	 * Initialize by encrypting given payload
	 *
	 * @param string $payload
	 * @param Header $header Desired header. Algorithm specific parameters
	 *        are automatically added.
	 * @param KeyManagementAlgorithm $key_algo Key management algorithm
	 * @param ContentEncryptionAlgorithm $enc_algo Content encryption algorithm
	 * @return self
	 */
	public static function encrypt($payload, Header $header, 
			KeyManagementAlgorithm $key_algo, 
			ContentEncryptionAlgorithm $enc_algo) {
		$cek = $key_algo->contentEncryptionKey();
		// generate random IV
		$iv = openssl_random_pseudo_bytes($enc_algo->ivSize());
		// @todo add support for compression
		$header = $header->withParameters(
			AlgorithmParameter::fromAlgorithm($key_algo), 
			EncryptionAlgorithmParameter::fromAlgorithm($enc_algo));
		$aad = Base64::urlEncode($header->toJSON());
		list ($ciphertext, $auth_tag) = $enc_algo->encrypt(
			$payload, $cek, $iv, $aad);
		return new self($header, $key_algo->encryptedKey(), $iv, $ciphertext, 
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
		$cek = $key_algo->contentEncryptionKey();
		$aad = Base64::urlEncode($this->_protectedHeader->toJSON());
		$payload = $enc_algo->decrypt($this->_ciphertext, $cek, $this->_iv, 
			$aad, $this->_authenticationTag);
		// @todo add support for uncompression
		return $payload;
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

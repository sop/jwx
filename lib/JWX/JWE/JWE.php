<?php

namespace JWX\JWE;

use JWX\JOSE\JOSE;
use JWX\JOSE\Parameter\AlgorithmParameter;
use JWX\JOSE\Parameter\EncryptionAlgorithmParameter;
use JWX\Util\Base64;


class JWE
{
	/**
	 * Header
	 *
	 * @var JOSE $_protectedHeader
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
	 * @param JOSE $header
	 * @param string $encrypted_key
	 * @param string $iv
	 * @param string $ciphertext
	 * @param string $auth_tag
	 * @param string|null $aad
	 */
	public function __construct(JOSE $header, $encrypted_key, $iv, $ciphertext, 
		$auth_tag, $aad = null) {
		$this->_protectedHeader = $header;
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
				"Not valid JWE compact serialization");
		}
		$header = JOSE::fromJSON(Base64::urlDecode($segments[0]));
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
	 * @param KeyManagementAlgorithm $key_algo
	 * @param ContentEncryptionAlgorithm $enc_algo
	 * @return self
	 */
	public static function encrypt($payload, KeyManagementAlgorithm $key_algo, 
			ContentEncryptionAlgorithm $enc_algo) {
		$cek = $key_algo->contentEncryptionKey();
		$iv = openssl_random_pseudo_bytes($enc_algo->ivSize());
		// @todo add support for compression
		$header = new JOSE(AlgorithmParameter::fromAlgorithm($key_algo), 
			EncryptionAlgorithmParameter::fromAlgorithm($enc_algo));
		$aad = Base64::urlEncode($header->toJSON());
		list($ciphertext, $auth_tag) = $enc_algo->encrypt($payload, $cek, $iv, 
			$aad);
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
}

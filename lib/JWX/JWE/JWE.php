<?php

namespace JWX\JWE;

use JWX\JWE\CompressionAlgorithm\CompressionFactory;
use JWX\JWE\EncryptionAlgorithm\EncryptionAlgorithmFactory;
use JWX\JWE\KeyAlgorithm\KeyAlgorithmFactory;
use JWX\JWK\JWK;
use JWX\JWT\Header\Header;
use JWX\JWT\Header\JOSE;
use JWX\Util\Base64;


/**
 * Class to represent JWE structure.
 *
 * @link https://tools.ietf.org/html/rfc7516#section-3
 */
class JWE
{
	/**
	 * Protected header.
	 *
	 * @var Header $_protectedHeader
	 */
	protected $_protectedHeader;
	
	/**
	 * Encrypted key.
	 *
	 * @var string $_encryptedKey
	 */
	protected $_encryptedKey;
	
	/**
	 * Initialization vector.
	 *
	 * @var string
	 */
	protected $_iv;
	
	/**
	 * Additional authenticated data.
	 *
	 * @var string $_aad
	 */
	protected $_aad;
	
	/**
	 * Ciphertext.
	 *
	 * @var string $_ciphertext
	 */
	protected $_ciphertext;
	
	/**
	 * Authentication tag.
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
	 * Initialize from compact serialization.
	 *
	 * @param string $data
	 * @return self
	 */
	public static function fromCompact($data) {
		return self::fromParts(explode(".", $data));
	}
	
	/**
	 * Initialize from parts of compact serialization.
	 *
	 * @param array $parts
	 * @throws \UnexpectedValueException
	 * @return self
	 */
	public static function fromParts(array $parts) {
		if (count($parts) != 5) {
			throw new \UnexpectedValueException(
				"Invalid JWE compact serialization.");
		}
		$header = Header::fromJSON(Base64::urlDecode($parts[0]));
		$encrypted_key = Base64::urlDecode($parts[1]);
		$iv = Base64::urlDecode($parts[2]);
		$ciphertext = Base64::urlDecode($parts[3]);
		$auth_tag = Base64::urlDecode($parts[4]);
		return new self($header, $encrypted_key, $iv, $ciphertext, $auth_tag);
	}
	
	/**
	 * Initialize by encrypting the given payload.
	 *
	 * @param string $payload Payload
	 * @param KeyManagementAlgorithm $key_algo Key management algorithm
	 * @param ContentEncryptionAlgorithm $enc_algo Content encryption algorithm
	 * @param CompressionAlgorithm|null $zip_algo Optional compression algorithm
	 * @param Header|null $header Optional desired header. Algorithm specific
	 *        parameters are automatically added.
	 * @param string|null $cek Optional content encryption key. Randomly
	 *        generated if not set.
	 * @param string|null $iv Optional initialization vector. Randomly generated
	 *        if not set.
	 * @throws \RuntimeException If encrypt fails
	 * @return self
	 */
	public static function encrypt($payload, KeyManagementAlgorithm $key_algo, 
			ContentEncryptionAlgorithm $enc_algo, 
			CompressionAlgorithm $zip_algo = null, Header $header = null, $cek = null, 
			$iv = null) {
		// if header was not given, initialize empty
		if (!isset($header)) {
			$header = new Header();
		}
		// generate random CEK
		if (!isset($cek)) {
			$cek = $key_algo->cekForEncryption($enc_algo->keySize());
		}
		// generate random IV
		if (!isset($iv)) {
			$iv = openssl_random_pseudo_bytes($enc_algo->ivSize());
		}
		// compress
		if (isset($zip_algo)) {
			$payload = $zip_algo->compress($payload);
			$header = $header->withParameters(...$zip_algo->headerParameters());
		}
		return self::_encryptContent($payload, $cek, $iv, $key_algo, $enc_algo, 
			$header);
	}
	
	/**
	 * Encrypt content with explicit parameters.
	 *
	 * @param string $plaintext Plaintext content to encrypt
	 * @param string $cek Content encryption key
	 * @param string $iv Initialization vector
	 * @param KeyManagementAlgorithm $key_algo Key management algorithm
	 * @param ContentEncryptionAlgorithm $enc_algo Content encryption algorithm
	 * @param Header $header Header
	 * @throws \UnexpectedValueException
	 * @return self
	 */
	private static function _encryptContent($plaintext, $cek, $iv, 
			KeyManagementAlgorithm $key_algo, 
			ContentEncryptionAlgorithm $enc_algo, Header $header) {
		// check that content encryption key has correct size
		if (strlen($cek) != $enc_algo->keySize()) {
			throw new \UnexpectedValueException("Invalid key size.");
		}
		// check that initialization vector has correct size
		if (strlen($iv) != $enc_algo->ivSize()) {
			throw new \UnexpectedValueException("Invalid IV size.");
		}
		// add key and encryption algorithm parameters to the header
		$header = $header->withParameters(...$key_algo->headerParameters())
			->withParameters(...$enc_algo->headerParameters());
		// encrypt the content encryption key
		$encrypted_key = $key_algo->encrypt($cek, $header);
		// sanity check that header wasn't unset via reference
		if (!$header instanceof Header) {
			throw new \RuntimeException("Broken key algorithm.");
		}
		// additional authenticated data
		$aad = Base64::urlEncode($header->toJSON());
		// encrypt
		list($ciphertext, $auth_tag) = $enc_algo->encrypt($plaintext, $cek, $iv, 
			$aad);
		return new self($header, $encrypted_key, $iv, $ciphertext, $auth_tag);
	}
	
	/**
	 * Decrypt content.
	 *
	 * @param KeyManagementAlgorithm $key_algo
	 * @param ContentEncryptionAlgorithm $enc_algo
	 * @throws \RuntimeException If decrypt fails
	 * @return string Plaintext payload
	 */
	public function decrypt(KeyManagementAlgorithm $key_algo, 
			ContentEncryptionAlgorithm $enc_algo) {
		$cek = $key_algo->decrypt($this->_encryptedKey);
		$aad = Base64::urlEncode($this->_protectedHeader->toJSON());
		$payload = $enc_algo->decrypt($this->_ciphertext, $cek, $this->_iv, 
			$aad, $this->_authenticationTag);
		// decompress
		if ($this->_protectedHeader->hasCompressionAlgorithm()) {
			$comp_algo_name = $this->_protectedHeader->compressionAlgorithm()->value();
			$decompressor = CompressionFactory::algoByName($comp_algo_name);
			$payload = $decompressor->decompress($payload);
		}
		return $payload;
	}
	
	/**
	 * Decrypt content using given JWK.
	 *
	 * Key management and content encryption algorithms are determined from the
	 * header.
	 *
	 * @param JWK $jwk JSON Web Key
	 * @return string Plaintext payload
	 */
	public function decryptWithJWK(JWK $jwk) {
		$header = $this->header();
		$key_algo_factory = new KeyAlgorithmFactory($header);
		$key_algo = $key_algo_factory->algoByKey($jwk);
		$enc_algo = EncryptionAlgorithmFactory::algoByHeader($header);
		return $this->decrypt($key_algo, $enc_algo);
	}
	
	/**
	 * Get JOSE header.
	 *
	 * @return JOSE
	 */
	public function header() {
		return new JOSE($this->_protectedHeader);
	}
	
	/**
	 * Get encrypted CEK.
	 *
	 * @return string
	 */
	public function encryptedKey() {
		return $this->_encryptedKey;
	}
	
	/**
	 * Get initialization vector.
	 *
	 * @return string
	 */
	public function initializationVector() {
		return $this->_iv;
	}
	
	/**
	 * Get ciphertext.
	 *
	 * @return string
	 */
	public function ciphertext() {
		return $this->_ciphertext;
	}
	
	/**
	 * Get authentication tag.
	 *
	 * @return string
	 */
	public function authenticationTag() {
		return $this->_authenticationTag;
	}
	
	/**
	 * Convert to compact serialization.
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
	 * Convert JWE to string.
	 *
	 * @return string
	 */
	public function __toString() {
		return $this->toCompact();
	}
}

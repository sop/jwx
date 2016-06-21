<?php

namespace JWX\JWE\KeyAlgorithm;

use GCM\Cipher\Cipher;
use GCM\GCM;
use JWX\JWA\JWA;
use JWX\JWE\KeyAlgorithm\Feature\RandomCEK;
use JWX\JWE\KeyManagementAlgorithm;
use JWX\JWK\JWK;
use JWX\JWK\Symmetric\SymmetricKeyJWK;
use JWX\JWT\Header\Header;
use JWX\JWT\Parameter\AlgorithmParameter;
use JWX\JWT\Parameter\AuthenticationTagParameter;
use JWX\JWT\Parameter\InitializationVectorParameter;
use JWX\JWT\Parameter\JWTParameter;


/**
 * Base class for AES GCM key encryption algorithms.
 *
 * @link https://tools.ietf.org/html/rfc7518#section-4.7
 */
abstract class AESGCMKWAlgorithm extends KeyManagementAlgorithm
{
	use RandomCEK;
	
	/**
	 * Key encryption key.
	 *
	 * @var string $_kek
	 */
	protected $_kek;
	
	/**
	 * Initialization vector.
	 *
	 * @var string $_iv
	 */
	protected $_iv;
	
	/**
	 * Mapping from algorithm name to class name.
	 *
	 * @internal
	 *
	 * @var array
	 */
	const MAP_ALGO_TO_CLASS = array(
		/* @formatter:off */
		JWA::ALGO_A128GCMKW => A128GCMKWAlgorithm::class, 
		JWA::ALGO_A192GCMKW => A192GCMKWAlgorithm::class, 
		JWA::ALGO_A256GCMKW => A256GCMKWAlgorithm::class
		/* @formatter:on */
	);
	
	/**
	 * Required IV size in bytes.
	 *
	 * @var int
	 */
	const IV_SIZE = 12;
	
	/**
	 * Authentication tag size in bytes.
	 *
	 * @var int
	 */
	const AUTH_TAG_SIZE = 16;
	
	/**
	 * Get GCM Cipher instance.
	 *
	 * @return Cipher
	 */
	abstract protected function _getGCMCipher();
	
	/**
	 * Get the required key size.
	 *
	 * @return int
	 */
	abstract protected function _keySize();
	
	/**
	 * Get GCM instance.
	 *
	 * @return GCM
	 */
	final protected function _getGCM() {
		return new GCM($this->_getGCMCipher(), self::AUTH_TAG_SIZE);
	}
	
	/**
	 * Constructor
	 *
	 * @param string $kek Key encryption key
	 * @param string $iv Initialization vector
	 */
	public function __construct($kek, $iv) {
		if (strlen($kek) != $this->_keySize()) {
			throw new \LengthException("Invalid key size.");
		}
		if (strlen($iv) != self::IV_SIZE) {
			throw new \LengthException("Initialization vector must be 96 bits.");
		}
		$this->_kek = $kek;
		$this->_iv = $iv;
	}
	
	/**
	 *
	 * @param JWK $jwk
	 * @param Header $header
	 * @throws \UnexpectedValueException
	 * @return AESGCMKWAlgorithm
	 */
	public static function fromJWK(JWK $jwk, Header $header) {
		$jwk = SymmetricKeyJWK::fromJWK($jwk);
		if (!$header->hasInitializationVector()) {
			throw new \UnexpectedValueException("No initialization vector.");
		}
		$iv = $header->initializationVector()->initializationVector();
		$alg = JWA::deriveAlgorithmName($header, $jwk);
		if (!array_key_exists($alg, self::MAP_ALGO_TO_CLASS)) {
			throw new \UnexpectedValueException("Unsupported algorithm '$alg'.");
		}
		$cls = self::MAP_ALGO_TO_CLASS[$alg];
		return new $cls($jwk->key(), $iv);
	}
	
	/**
	 * Initialize from key encryption key with random IV.
	 *
	 * Key size must match the underlying cipher.
	 *
	 * @param string $key Key encryption key
	 * @return self
	 */
	public static function fromKey($key) {
		$iv = openssl_random_pseudo_bytes(self::IV_SIZE);
		return new static($key, $iv);
	}
	
	/**
	 *
	 * @see \JWX\JWE\KeyManagementAlgorithm::_encryptKey()
	 * @return string
	 */
	protected function _encryptKey($key, Header &$header) {
		list($ciphertext, $auth_tag) = $this->_getGCM()->encrypt($key, "", 
			$this->_kek, $this->_iv);
		// insert authentication tag to the header
		$header = $header->withParameters(
			AuthenticationTagParameter::fromString($auth_tag));
		return $ciphertext;
	}
	
	/**
	 *
	 * @see \JWX\JWE\KeyManagementAlgorithm::_decryptKey()
	 * @throws \RuntimeException For generic errors
	 * @return string
	 */
	protected function _decryptKey($ciphertext, Header $header) {
		if (!$header->hasAuthenticationTag()) {
			throw new \RuntimeException(
				"Header doesn't contain authentication tag.");
		}
		$auth_tag = $header->authenticationTag()->authenticationTag();
		$cek = $this->_getGCM()->decrypt($ciphertext, $auth_tag, "", 
			$this->_kek, $this->_iv);
		return $cek;
	}
	
	/**
	 *
	 * @see \JWX\JWE\KeyManagementAlgorithm::headerParameters()
	 * @return JWTParameter[]
	 */
	public function headerParameters() {
		return array_merge(parent::headerParameters(), 
			array(AlgorithmParameter::fromAlgorithm($this), 
				InitializationVectorParameter::fromString($this->_iv)));
	}
}

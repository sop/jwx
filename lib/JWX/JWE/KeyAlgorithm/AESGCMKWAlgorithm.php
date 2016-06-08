<?php

namespace JWX\JWE\KeyAlgorithm;

use GCM\Cipher\Cipher;
use GCM\GCM;
use JWX\JWA\JWA;
use JWX\JWE\KeyAlgorithm\Feature\RandomCEK;
use JWX\JWE\KeyManagementAlgorithm;
use JWX\JWK\JWK;
use JWX\JWK\Parameter\RegisteredJWKParameter;
use JWX\JWK\Symmetric\SymmetricKeyJWK;
use JWX\JWT\Header\Header;
use JWX\JWT\Parameter\AlgorithmParameter;
use JWX\JWT\Parameter\AuthenticationTagParameter;
use JWX\JWT\Parameter\InitializationVectorParameter;
use JWX\JWT\Parameter\RegisteredJWTParameter;


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
		return new GCM($this->_getGCMCipher(), 16);
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
		if (strlen($iv) != 12) {
			throw new \LengthException("Initialization vector must be 96 bits.");
		}
		$this->_kek = $kek;
		$this->_iv = $iv;
	}
	
	/**
	 * Initialize from JWK.
	 *
	 * If algorithm isn't specified, consult the JWK.
	 *
	 * @param JWK $jwk
	 * @param string $iv Initialization vector
	 * @param string|null $alg Optional explicitly specified algorithm
	 * @throws \UnexpectedValueException If parameters are missing
	 * @return self
	 */
	public static function fromJWK(JWK $jwk, $iv, $alg = null) {
		$jwk = SymmetricKeyJWK::fromJWK($jwk);
		if (!isset($alg)) {
			if (!$jwk->has(RegisteredJWKParameter::P_ALG)) {
				throw new \UnexpectedValueException("No algorithm parameter.");
			}
			$alg = $jwk->get(RegisteredJWKParameter::P_ALG)->value();
		}
		if (!array_key_exists($alg, self::MAP_ALGO_TO_CLASS)) {
			throw new \UnexpectedValueException("Unsupported algorithm '$alg'.");
		}
		$cls = self::MAP_ALGO_TO_CLASS[$alg];
		return new $cls($jwk->key(), $iv);
	}
	
	protected function _encryptKey($key, Header &$header) {
		list($ciphertext, $auth_tag) = $this->_getGCM()->encrypt($key, "", 
			$this->_kek, $this->_iv);
		// insert authentication tag to the header
		$header = $header->withParameters(
			AuthenticationTagParameter::fromString($auth_tag));
		return $ciphertext;
	}
	
	protected function _decryptKey($ciphertext, Header $header) {
		if (!$header->has(RegisteredJWTParameter::P_TAG)) {
			throw new \RuntimeException(
				"Header doesn't contain authentication tag.");
		}
		$auth_tag = $header->getTyped(RegisteredJWTParameter::P_TAG)->authenticationTag();
		$cek = $this->_getGCM()->decrypt($ciphertext, $auth_tag, "", 
			$this->_kek, $this->_iv);
		return $cek;
	}
	
	public function headerParameters() {
		return array(AlgorithmParameter::fromAlgorithm($this), 
			InitializationVectorParameter::fromString($this->_iv));
	}
}

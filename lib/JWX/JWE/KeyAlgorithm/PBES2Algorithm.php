<?php

namespace JWX\JWE\KeyAlgorithm;

use AESKW\AESKeyWrapAlgorithm;
use JWX\JWA\JWA;
use JWX\JWE\KeyAlgorithm\Feature\RandomCEK;
use JWX\JWE\KeyManagementAlgorithm;
use JWX\JWK\JWK;
use JWX\JWK\Symmetric\SymmetricKeyJWK;
use JWX\JWT\Header\Header;
use JWX\JWT\Parameter\AlgorithmParameter;
use JWX\JWT\Parameter\PBES2CountParameter;
use JWX\JWT\Parameter\PBES2SaltInputParameter;


/**
 * Base class for algorithms implementing PBES2 key encryption.
 *
 * @link https://tools.ietf.org/html/rfc7518#section-4.8
 */
abstract class PBES2Algorithm extends KeyManagementAlgorithm
{
	use RandomCEK;
	
	/**
	 * Password.
	 *
	 * @var string $_password
	 */
	protected $_password;
	
	/**
	 * Salt input.
	 *
	 * @var string $_salt
	 */
	protected $_saltInput;
	
	/**
	 * Iteration count.
	 *
	 * @var int $_count
	 */
	protected $_count;
	
	/**
	 * Derived key.
	 *
	 * @var string
	 */
	private $_derivedKey;
	
	/**
	 * Mapping from algorithm name to class name.
	 *
	 * @internal
	 *
	 * @var array
	 */
	const MAP_ALGO_TO_CLASS = array(
		/* @formatter:off */
		JWA::ALGO_PBES2_HS256_A128KW => PBES2HS256A128KWAlgorithm::class, 
		JWA::ALGO_PBES2_HS384_A192KW => PBES2HS384A192KWAlgorithm::class, 
		JWA::ALGO_PBES2_HS512_A256KW => PBES2HS512A256KWAlgorithm::class
		/* @formatter:on */
	);
	
	/**
	 * Get hash algorithm for hash_pbkdf2.
	 *
	 * @return string
	 */
	abstract protected function _hashAlgo();
	
	/**
	 * Get derived key length.
	 *
	 * @return int
	 */
	abstract protected function _keyLength();
	
	/**
	 * Get key wrapping algoritym.
	 *
	 * @return AESKeyWrapAlgorithm
	 */
	abstract protected function _kwAlgo();
	
	/**
	 * Constructor
	 *
	 * @param string $password Password
	 * @param string $salt_input Salt input
	 * @param int $count Iteration count
	 */
	public function __construct($password, $salt_input, $count) {
		$this->_password = $password;
		$this->_saltInput = $salt_input;
		$this->_count = $count;
	}
	
	/**
	 *
	 * @param JWK $jwk
	 * @param Header $header
	 * @throws \UnexpectedValueException
	 * @return PBES2Algorithm
	 */
	public static function fromJWK(JWK $jwk, Header $header) {
		$jwk = SymmetricKeyJWK::fromJWK($jwk);
		if (!$header->hasPBES2SaltInput()) {
			throw new \UnexpectedValueException("No salt input.");
		}
		$salt_input = $header->PBES2SaltInput()->saltInput();
		if (!$header->hasPBES2Count()) {
			throw new \UnexpectedValueException("No iteration count.");
		}
		$count = $header->PBES2Count()->value();
		$alg = JWA::deriveAlgorithmName($header, $jwk);
		if (!array_key_exists($alg, self::MAP_ALGO_TO_CLASS)) {
			throw new \UnexpectedValueException("Unsupported algorithm '$alg'.");
		}
		$cls = self::MAP_ALGO_TO_CLASS[$alg];
		return new $cls($jwk->key(), $salt_input, $count);
	}
	
	/**
	 * Initialize from a password with random salt and default iteration count.
	 *
	 * @param string $password Password
	 * @param int $count Optional user defined iteration count
	 * @param int $salt_bytes Optional user defined salt length
	 * @return self
	 */
	public static function fromPassword($password, $count = 64000, $salt_bytes = 8) {
		$salt_input = openssl_random_pseudo_bytes($salt_bytes);
		return new static($password, $salt_input, $count);
	}
	
	/**
	 * Get salt input.
	 *
	 * @return string
	 */
	public function saltInput() {
		return $this->_saltInput;
	}
	
	/**
	 * Get computed salt.
	 *
	 * @return string
	 */
	public function salt() {
		return PBES2SaltInputParameter::fromString($this->_saltInput)->salt(
			AlgorithmParameter::fromAlgorithm($this));
	}
	
	/**
	 * Get iteration count.
	 *
	 * @return int
	 */
	public function iterationCount() {
		return $this->_count;
	}
	
	/**
	 * Get derived key.
	 *
	 * @return string
	 */
	protected function _derivedKey() {
		if (!isset($this->_derivedKey)) {
			$this->_derivedKey = hash_pbkdf2($this->_hashAlgo(), 
				$this->_password, $this->salt(), $this->_count, 
				$this->_keyLength(), true);
		}
		return $this->_derivedKey;
	}
	
	protected function _encryptKey($key, Header &$header) {
		return $this->_kwAlgo()->wrap($key, $this->_derivedKey());
	}
	
	protected function _decryptKey($ciphertext, Header $header) {
		return $this->_kwAlgo()->unwrap($ciphertext, $this->_derivedKey());
	}
	
	public function headerParameters() {
		return array(AlgorithmParameter::fromAlgorithm($this), 
			PBES2SaltInputParameter::fromString($this->_saltInput), 
			new PBES2CountParameter($this->_count));
	}
}

<?php

namespace JWX\JWE\KeyAlgorithm;

use AESKW\AESKeyWrapAlgorithm;
use JWX\JWA\JWA;
use JWX\JWE\KeyManagementAlgorithm;
use JWX\JWT\Header;
use JWX\JWT\Parameter\AlgorithmParameter;
use JWX\JWT\Parameter\RegisteredJWTParameter;


/**
 * Base class for algorithms implementing PBES2 key encryption.
 *
 * @link https://tools.ietf.org/html/rfc7518#section-4.8
 */
abstract class PBES2Algorithm implements KeyManagementAlgorithm
{
	/**
	 * Password.
	 *
	 * @var string $_password
	 */
	protected $_password;
	
	/**
	 * Salt.
	 *
	 * @var string $_salt
	 */
	protected $_salt;
	
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
	 * @param string $salt Computed salt
	 * @param int $count Iteration count
	 */
	public function __construct($password, $salt, $count) {
		$this->_password = $password;
		$this->_salt = $salt;
		$this->_count = $count;
	}
	
	/**
	 * Initialize from header.
	 *
	 * If algorithm is not explicitly specified, use one from header.
	 *
	 * @param Header $header Header
	 * @param string $password Password
	 * @param string|null $alg Algorithm
	 * @throws \UnexpectedValueException
	 * @return self
	 */
	public static function fromHeader(Header $header, $password, $alg = null) {
		$params = array(RegisteredJWTParameter::PARAM_PBES2_SALT_INPUT, 
			RegisteredJWTParameter::PARAM_PBES2_COUNT);
		if (!$header->has(...$params)) {
			throw new \UnexpectedValueException("Missing header parameters.");
		}
		if (!isset($alg)) {
			if (!$header->has(RegisteredJWTParameter::P_ALG)) {
				throw new \UnexpectedValueException("No algorithm parameter.");
			}
			$alg = $header->get(RegisteredJWTParameter::P_ALG)->value();
		}
		if (!array_key_exists($alg, self::MAP_ALGO_TO_CLASS)) {
			throw new \UnexpectedValueException("Unsupported algorithm '$alg'.");
		}
		$cls = self::MAP_ALGO_TO_CLASS[$alg];
		$salt = $header->get(RegisteredJWTParameter::P_P2S)->salt(
			new AlgorithmParameter($alg));
		$count = $header->get(RegisteredJWTParameter::P_P2C)->value();
		return new $cls($password, $salt, $count);
	}
	
	/**
	 * Get derived key.
	 *
	 * @return string
	 */
	protected function _derivedKey() {
		if (!isset($this->_derivedKey)) {
			$this->_derivedKey = hash_pbkdf2($this->_hashAlgo(), 
				$this->_password, $this->_salt, $this->_count, 
				$this->_keyLength(), true);
		}
		return $this->_derivedKey;
	}
	
	public function encrypt($cek) {
		$kek = $this->_derivedKey();
		return $this->_kwAlgo()->wrap($cek, $kek);
	}
	
	public function decrypt($data) {
		$kek = $this->_derivedKey();
		return $this->_kwAlgo()->unwrap($data, $kek);
	}
}

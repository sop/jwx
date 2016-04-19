<?php

namespace JWX\JWE\KeyAlgorithm;

use JWX\JWE\KeyManagementAlgorithm;


/**
 * Base class for algorithms implementing PBES2 key encryption
 *
 * @link https://tools.ietf.org/html/rfc7518#section-4.8
 */
abstract class PBES2Algorithm implements KeyManagementAlgorithm
{
	/**
	 * Password
	 *
	 * @var string $_password
	 */
	protected $_password;
	
	/**
	 * Salt
	 *
	 * @var string $_salt
	 */
	protected $_salt;
	
	/**
	 * Iteration count
	 *
	 * @var int $_count
	 */
	protected $_count;
	
	/**
	 * Derived key
	 *
	 * @var string
	 */
	private $_derivedKey;
	
	/**
	 * Get hash algorithm for hash_pbkdf2
	 *
	 * @return string
	 */
	abstract protected function _hashAlgo();
	
	/**
	 * Get derived key length
	 *
	 * @return int
	 */
	abstract protected function _keyLength();
	
	/**
	 * Get key wrapping algoritym
	 *
	 * @return \AESKW\AESKeyWrapAlgorithm
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
	 * Get derived key
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

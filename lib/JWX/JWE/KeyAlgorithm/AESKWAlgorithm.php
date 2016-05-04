<?php

namespace JWX\JWE\KeyAlgorithm;

use AESKW\AESKeyWrapAlgorithm;
use JWX\JWE\KeyManagementAlgorithm;
use JWX\JWT\Parameter\AlgorithmParameter;


/**
 * Base class for algorithms implementing AES key wrap.
 *
 * @link https://tools.ietf.org/html/rfc7518#section-4.4
 */
abstract class AESKWAlgorithm implements KeyManagementAlgorithm
{
	/**
	 * Key encryption key.
	 *
	 * @var string $_kek
	 */
	protected $_kek;
	
	/**
	 * Get key wrapping algorithm.
	 *
	 * @return AESKeyWrapAlgorithm
	 */
	abstract protected function _AESKWAlgo();
	
	/**
	 * Constructor
	 *
	 * @param string $kek Key encryption key
	 */
	public function __construct($kek) {
		$this->_kek = $kek;
	}
	
	public function encrypt($cek) {
		return $this->_AESKWAlgo()->wrap($cek, $this->_kek);
	}
	
	public function decrypt($data) {
		return $this->_AESKWAlgo()->unwrap($data, $this->_kek);
	}
	
	public function headerParameters() {
		return array(AlgorithmParameter::fromAlgorithm($this));
	}
}

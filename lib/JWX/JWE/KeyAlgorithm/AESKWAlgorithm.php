<?php

namespace JWX\JWE\KeyAlgorithm;

use JWX\JWE\KeyManagementAlgorithm;


abstract class AESKWAlgorithm implements KeyManagementAlgorithm
{
	/**
	 * Key encryption key
	 *
	 * @var string $_kek
	 */
	protected $_kek;
	
	/**
	 * Get key wrapping algorithm
	 *
	 * @return \AESKW\AESKeyWrapAlgorithm
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
}

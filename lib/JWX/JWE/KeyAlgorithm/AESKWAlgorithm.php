<?php

namespace JWX\JWE\KeyAlgorithm;

use AESKW\AESKeyWrapAlgorithm;
use JWX\JWE\KeyAlgorithm\Feature\RandomCEK;
use JWX\JWE\KeyManagementAlgorithm;
use JWX\JWT\Parameter\AlgorithmParameter;


/**
 * Base class for algorithms implementing AES key wrap.
 *
 * @link https://tools.ietf.org/html/rfc7518#section-4.4
 */
abstract class AESKWAlgorithm implements KeyManagementAlgorithm
{
	use RandomCEK;
	
	/**
	 * Key encryption key.
	 *
	 * @var string $_kek
	 */
	protected $_kek;
	
	/**
	 * Key wrapping algorithm.
	 *
	 * Lazily initialized.
	 *
	 * @var AESKeyWrapAlgorithm|null $_kw
	 */
	protected $_kw;
	
	/**
	 * Get key wrapping algorithm instance.
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
	
	/**
	 * Get key wrapping algorithm.
	 *
	 * @return AESKeyWrapAlgorithm
	 */
	protected function _kw() {
		if (!isset($this->_kw)) {
			$this->_kw = $this->_AESKWAlgo();
		}
		return $this->_kw;
	}
	
	public function encrypt($cek) {
		return $this->_kw()->wrap($cek, $this->_kek);
	}
	
	public function decrypt($data) {
		return $this->_kw()->unwrap($data, $this->_kek);
	}
	
	public function headerParameters() {
		return array(AlgorithmParameter::fromAlgorithm($this));
	}
}

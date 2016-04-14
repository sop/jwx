<?php

namespace JWX\JWE\KeyAlgorithm;

use JWX\JWE\KeyManagementAlgorithm;
use JWX\JWT\Parameter\AlgorithmParameter;


/**
 * Algorithm to carry CEK in plaintext.
 *
 * @link https://tools.ietf.org/html/rfc7518#section-4.5
 */
class DirectCEKAlgorithm implements KeyManagementAlgorithm
{
	/**
	 * Content encryption key
	 *
	 * @var string $_key
	 */
	protected $_key;
	
	/**
	 * Constructor
	 *
	 * @param string $key Content encryption key
	 */
	public function __construct($key) {
		$this->_key = $key;
	}
	
	public function encrypt($cek) {
		return "";
	}
	
	public function decrypt($data) {
		return $this->_key;
	}
	
	public function algorithmParamValue() {
		return AlgorithmParameter::ALGO_DIR;
	}
}

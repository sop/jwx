<?php

namespace JWX\JWE\KeyAlgorithm;

use JWX\JWA\JWA;
use JWX\JWE\KeyManagementAlgorithm;


/**
 * Algorithm to carry CEK in plaintext.
 *
 * @link https://tools.ietf.org/html/rfc7518#section-4.5
 */
class DirectCEKAlgorithm implements KeyManagementAlgorithm
{
	/**
	 * Content encryption key.
	 *
	 * @var string $_cek
	 */
	protected $_cek;
	
	/**
	 * Constructor
	 *
	 * @param string $key Content encryption key
	 */
	public function __construct($cek) {
		$this->_cek = $cek;
	}
	
	/**
	 * Get content encryption key.
	 *
	 * @return string
	 */
	public function cek() {
		return $this->_cek;
	}
	
	public function encrypt($cek) {
		return "";
	}
	
	public function decrypt($data) {
		return $this->_cek;
	}
	
	public function algorithmParamValue() {
		return JWA::ALGO_DIR;
	}
}

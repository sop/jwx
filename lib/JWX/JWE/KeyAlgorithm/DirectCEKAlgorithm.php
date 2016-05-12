<?php

namespace JWX\JWE\KeyAlgorithm;

use JWX\JWA\JWA;
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
		if ($data !== "") {
			throw new \UnexpectedValueException(
				"Encrypted key must be an empty octet sequence.");
		}
		return $this->_cek;
	}
	
	public function cekForEncryption($length) {
		if (strlen($this->_cek) != $length) {
			throw new \UnexpectedValueException("Invalid key length.");
		}
		return $this->_cek;
	}
	
	public function algorithmParamValue() {
		return JWA::ALGO_DIR;
	}
	
	public function headerParameters() {
		return array(AlgorithmParameter::fromAlgorithm($this));
	}
}

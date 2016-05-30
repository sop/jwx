<?php

namespace JWX\JWE\KeyAlgorithm;

use JWX\JWA\JWA;
use JWX\JWE\KeyManagementAlgorithm;
use JWX\JWK\JWK;
use JWX\JWK\Symmetric\SymmetricKeyJWK;
use JWX\JWT\Header;
use JWX\JWT\Parameter\AlgorithmParameter;


/**
 * Algorithm to carry CEK in plaintext.
 *
 * @link https://tools.ietf.org/html/rfc7518#section-4.5
 */
class DirectCEKAlgorithm extends KeyManagementAlgorithm
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
	 * Initialize from JWK.
	 *
	 * @param JWK $jwk
	 */
	public static function fromJWK(JWK $jwk) {
		$jwk = SymmetricKeyJWK::fromJWK($jwk);
		return new self($jwk->key());
	}
	
	/**
	 * Get content encryption key.
	 *
	 * @return string
	 */
	public function cek() {
		return $this->_cek;
	}
	
	protected function _encryptKey($key, Header &$header) {
		if ($key != $this->_cek) {
			throw new \LogicException("Content encryption key doesn't match.");
		}
		return "";
	}
	
	protected function _decryptKey($ciphertext, Header $header) {
		if ($ciphertext !== "") {
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

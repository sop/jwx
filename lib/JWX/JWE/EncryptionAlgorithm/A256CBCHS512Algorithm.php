<?php

namespace JWX\JWE\EncryptionAlgorithm;

use JWX\JWA\JWA;


/**
 * Implements AES with 256-bit key in CBC mode with HMAC SHA-512 authentication.
 *
 * @link https://tools.ietf.org/html/rfc7518#section-5.2.5
 */
class A256CBCHS512Algorithm extends AESCBCAlgorithm
{
	public function keySize() {
		return 64;
	}
	
	public function encryptionAlgorithmParamValue() {
		return JWA::ALGO_A256CBC_HS512;
	}
	
	protected function _cipherMethod() {
		return "AES-256-CBC";
	}
	
	protected function _hashAlgo() {
		return "sha512";
	}
	
	protected function _encKeyLen() {
		return 32;
	}
	
	protected function _macKeyLen() {
		return 32;
	}
	
	protected function _tagLen() {
		return 32;
	}
}

<?php

namespace JWX\JWE\EncryptionAlgorithm;

use JWX\JWA\JWA;


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

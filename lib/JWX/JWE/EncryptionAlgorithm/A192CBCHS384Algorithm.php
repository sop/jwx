<?php

namespace JWX\JWE\EncryptionAlgorithm;

use JWX\JWT\Parameter\EncryptionAlgorithmParameter;


class A192CBCHS384Algorithm extends AESCBCAlgorithm
{
	public function keySize() {
		return 48;
	}
	
	public function encryptionAlgorithmParamValue() {
		return EncryptionAlgorithmParameter::ALGO_A192CBC_HS384;
	}
	
	protected function _cipherMethod() {
		return "AES-192-CBC";
	}
	
	protected function _hashAlgo() {
		return "sha384";
	}
	
	protected function _encKeyLen() {
		return 24;
	}
	
	protected function _macKeyLen() {
		return 24;
	}
	
	protected function _tagLen() {
		return 24;
	}
}

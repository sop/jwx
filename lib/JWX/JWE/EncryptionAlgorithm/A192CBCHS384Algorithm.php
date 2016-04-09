<?php

namespace JWX\JWE\EncryptionAlgorithm;


class A192CBCHS384Algorithm extends AESCBCAlgorithm
{
	public function keySize() {
		return 48;
	}
	
	public function algorithmParamValue() {
		return "A192CBC-HS384";
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

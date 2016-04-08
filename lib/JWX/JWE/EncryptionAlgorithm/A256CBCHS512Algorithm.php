<?php

namespace JWX\JWE\EncryptionAlgorithm;


class A256CBCHS512Algorithm extends AESCBCAlgorithm
{
	public function algorithmParamValue() {
		return "A256CBC-HS512";
	}
	
	protected function _cipherMethod() {
		return "AES-256-CBC";
	}
	
	protected function _hashAlgo() {
		return "sha512";
	}
	
	protected function _keySize() {
		return 64;
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

<?php

namespace JWX\JWE\KeyAlgorithm;

use JWX\JWE\KeyManagementAlgorithm;


class DirectCEKAlgorithm implements KeyManagementAlgorithm
{
	protected $_key;
	
	public function __construct($key) {
		$this->_key = $key;
	}
	
	public function encryptedKey() {
		return "";
	}
	
	public function contentEncryptionKey() {
		return $this->_key;
	}
	
	public function algorithmParamValue() {
		return "dir";
	}
}

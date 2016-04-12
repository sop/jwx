<?php

namespace JWX\JWE;

use JWX\JWT\Parameter\AlgorithmParameterValue;


interface KeyManagementAlgorithm extends AlgorithmParameterValue
{
	public function encryptedKey();
	
	public function contentEncryptionKey();
}

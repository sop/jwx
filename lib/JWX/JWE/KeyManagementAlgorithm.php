<?php

namespace JWX\JWE;

use JWX\JWT\AlgorithmParameterValue;


interface KeyManagementAlgorithm extends AlgorithmParameterValue
{
	public function encryptedKey();
	
	public function contentEncryptionKey();
}

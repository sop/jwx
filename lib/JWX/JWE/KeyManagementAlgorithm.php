<?php

namespace JWX\JWE;

use JWX\Header\AlgorithmParameterValue;


interface KeyManagementAlgorithm extends AlgorithmParameterValue
{
	public function encryptedKey();
	
	public function contentEncryptionKey();
}

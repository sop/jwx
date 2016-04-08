<?php

namespace JWX\JWE;

use JWX\JOSE\AlgorithmParameterValue;


interface KeyManagementAlgorithm extends AlgorithmParameterValue
{
	public function encryptedKey();
	
	public function contentEncryptionKey();
}

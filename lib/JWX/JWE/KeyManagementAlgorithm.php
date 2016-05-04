<?php

namespace JWX\JWE;

use JWX\JWT\HeaderParameters;
use JWX\JWT\Parameter\AlgorithmParameterValue;


/**
 * Interface for algorithms that may be used to derive CEK for
 * content encryption algorithm.
 */
interface KeyManagementAlgorithm extends AlgorithmParameterValue, 
	HeaderParameters
{
	/**
	 * Encrypt a key to be inserted into JWE header.
	 *
	 * @param string $cek Content encryption key
	 * @return string Encrypted key
	 */
	public function encrypt($cek);
	
	/**
	 * Decrypt a CEK from the encrypted data.
	 *
	 * @param string $data Encrypted key
	 * @return string Content encryption key
	 */
	public function decrypt($data);
}

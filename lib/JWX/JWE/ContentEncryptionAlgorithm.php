<?php

namespace JWX\JWE;

use JWX\JWT\Parameter\EncryptionAlgorithmParameterValue;


interface ContentEncryptionAlgorithm extends EncryptionAlgorithmParameterValue
{
	/**
	 * Encrypt plaintext.
	 *
	 * @param string $plaintext Data to encrypt
	 * @param string $key Encryption key
	 * @param string $iv Initialization vector
	 * @param string $aad Additional authenticated data
	 * @return string Ciphertext
	 */
	public function encrypt($plaintext, $key, $iv, $aad);
	
	/**
	 * Decrypt ciphertext.
	 *
	 * @param string $ciphertext Data to decrypt
	 * @param string $key Encryption key
	 * @param string $iv Initialization vector
	 * @param string $aad Additional authenticated data
	 * @param string $auth_tag Authentication tag to compare
	 * @return string Plaintext
	 */
	public function decrypt($ciphertext, $key, $iv, $aad, $auth_tag);
	
	/**
	 * Get IV size in bytes
	 *
	 * @return int
	 */
	public function ivSize();
}

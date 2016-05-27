<?php

namespace JWX\JWE\EncryptionAlgorithm;

use GCM\Cipher\AES\AES256Cipher;
use JWX\JWA\JWA;


/**
 * Implements AES-GCM with 256-bit key.
 *
 * @link https://tools.ietf.org/html/rfc7518#section-5.3
 */
class A256GCMAlgorithm extends AESGCMAlgorithm
{
	public function encryptionAlgorithmParamValue() {
		return JWA::ALGO_A256GCM;
	}
	
	public function keySize() {
		return 32;
	}
	
	protected function _getGCMCipher() {
		return new AES256Cipher();
	}
}

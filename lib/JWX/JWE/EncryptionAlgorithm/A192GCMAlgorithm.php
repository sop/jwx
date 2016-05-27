<?php

namespace JWX\JWE\EncryptionAlgorithm;

use GCM\Cipher\AES\AES192Cipher;
use JWX\JWA\JWA;


/**
 * Implements AES-GCM with 192-bit key.
 *
 * @link https://tools.ietf.org/html/rfc7518#section-5.3
 */
class A192GCMAlgorithm extends AESGCMAlgorithm
{
	public function encryptionAlgorithmParamValue() {
		return JWA::ALGO_A192GCM;
	}
	
	public function keySize() {
		return 24;
	}
	
	protected function _getGCMCipher() {
		return new AES192Cipher();
	}
}

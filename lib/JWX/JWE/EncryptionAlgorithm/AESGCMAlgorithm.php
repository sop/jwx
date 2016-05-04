<?php

namespace JWX\JWE\EncryptionAlgorithm;

use JWX\JWE\ContentEncryptionAlgorithm;
use JWX\JWT\Parameter\AlgorithmParameter;


/**
 * Base class for algorithms implementing AES in Galois/Counter mode.
 *
 * @todo Implement when PHP adds support, see
 *       https://wiki.php.net/rfc/openssl_aead
 * @link https://tools.ietf.org/html/rfc7518#section-5.3
 */
abstract class AESGCMAlgorithm implements ContentEncryptionAlgorithm
{
	public function encrypt($plaintext, $key, $iv, $aad) {

	}
	
	public function decrypt($ciphertext, $key, $iv, $aad, $auth_tag) {

	}
	
	public function ivSize() {
		return 12;
	}
	
	public function headerParameters() {
		return array(AlgorithmParameter::fromAlgorithm($this));
	}
}

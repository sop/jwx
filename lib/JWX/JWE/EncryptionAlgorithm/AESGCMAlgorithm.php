<?php

namespace JWX\JWE\EncryptionAlgorithm;

use GCM\Cipher\Cipher;
use GCM\Exception\AuthenticationException as GCMAuthException;
use GCM\GCM;
use JWX\JWE\ContentEncryptionAlgorithm;
use JWX\JWE\Exception\AuthenticationException;
use JWX\JWT\Parameter\EncryptionAlgorithmParameter;


/**
 * Base class for algorithms implementing AES in Galois/Counter mode.
 *
 * @link https://tools.ietf.org/html/rfc7518#section-5.3
 */
abstract class AESGCMAlgorithm implements ContentEncryptionAlgorithm
{
	/**
	 * Get GCM Cipher instance.
	 *
	 * @return Cipher
	 */
	abstract protected function _getGCMCipher();
	
	/**
	 * Get GCM instance.
	 *
	 * @return GCM
	 */
	final protected function _getGCM() {
		return new GCM($this->_getGCMCipher(), 16);
	}
	
	/**
	 * Check that key is valid.
	 *
	 * @param string $key
	 * @throws \RuntimeException
	 */
	final protected function _validateKey($key) {
		if (strlen($key) != $this->keySize()) {
			throw new \RuntimeException("Invalid key size.");
		}
	}
	
	/**
	 * Check that IV is valid.
	 *
	 * @param string $iv
	 * @throws \RuntimeException
	 */
	final protected function _validateIV($iv) {
		if (strlen($iv) != $this->ivSize()) {
			throw new \RuntimeException("Invalid IV length.");
		}
	}
	
	public function encrypt($plaintext, $key, $iv, $aad) {
		$this->_validateKey($key);
		$this->_validateIV($iv);
		list($ciphertext, $auth_tag) = $this->_getGCM()->encrypt($plaintext, 
			$aad, $key, $iv);
		return [$ciphertext, $auth_tag];
	}
	
	public function decrypt($ciphertext, $key, $iv, $aad, $auth_tag) {
		$this->_validateKey($key);
		$this->_validateIV($iv);
		try {
			$plaintext = $this->_getGCM()->decrypt($ciphertext, $auth_tag, $aad, 
				$key, $iv);
		} catch (GCMAuthException $e) {
			throw new AuthenticationException("Message authentication failed.");
		}
		return $plaintext;
	}
	
	public function ivSize() {
		return 12;
	}
	
	public function headerParameters() {
		return array(EncryptionAlgorithmParameter::fromAlgorithm($this));
	}
}

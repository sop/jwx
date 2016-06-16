<?php

namespace JWX\JWS\Algorithm;

use JWX\JWK\Feature\AsymmetricPrivateKey;
use JWX\JWK\Feature\AsymmetricPublicKey;
use JWX\JWS\SignatureAlgorithm;


/**
 * Base class for algorithms employing asymmetric signature computation
 * using OpenSSL extension.
 */
abstract class OpenSSLSignatureAlgorithm extends SignatureAlgorithm
{
	/**
	 * Public key.
	 *
	 * @var AsymmetricPublicKey $_publicKey
	 */
	protected $_publicKey;
	
	/**
	 * Private key.
	 *
	 * @var AsymmetricPrivateKey|null $_privateKey
	 */
	protected $_privateKey;
	
	/**
	 * Get the message digest method name supported by OpenSSL.
	 *
	 * @return string
	 */
	abstract protected function _mdMethod();
	
	/**
	 *
	 * @see \JWX\JWS\SignatureAlgorithm::computeSignature()
	 * @throws \LogicException If private key was not provided
	 * @throws \RuntimeException For generic errors
	 * @return string
	 */
	public function computeSignature($data) {
		/**
		 * NOTE: OpenSSL uses PKCS #1 v1.5 padding by default, so no explicit
		 * padding is required by sign and verify operations.
		 */
		if (!isset($this->_privateKey)) {
			throw new \LogicException("Private key not set.");
		}
		$key = openssl_pkey_get_private($this->_privateKey->toPEM()->string());
		if (!$key) {
			throw new \RuntimeException(
				"openssl_pkey_get_private() failed: " .
					 $this->_getLastOpenSSLError());
		}
		$result = @openssl_sign($data, $signature, $key, $this->_mdMethod());
		if (!$result) {
			throw new \RuntimeException(
				"openssl_sign() failed: " . $this->_getLastOpenSSLError());
		}
		return $signature;
	}
	
	/**
	 *
	 * @see \JWX\JWS\SignatureAlgorithm::validateSignature()
	 * @throws \RuntimeException For generic errors
	 * @return bool
	 */
	public function validateSignature($data, $signature) {
		$key = openssl_pkey_get_public($this->_publicKey->toPEM()->string());
		if (!$key) {
			throw new \RuntimeException(
				"openssl_pkey_get_public() failed: " .
					 $this->_getLastOpenSSLError());
		}
		$result = @openssl_verify($data, $signature, $key, $this->_mdMethod());
		if (false === $result || -1 == $result) {
			throw new \RuntimeException(
				"openssl_verify() failed: " . $this->_getLastOpenSSLError());
		}
		return $result == 1;
	}
	
	/**
	 * Get the last OpenSSL error message.
	 *
	 * @return string|null
	 */
	protected function _getLastOpenSSLError() {
		$msg = null;
		while (false !== ($err = openssl_error_string())) {
			$msg = $err;
		}
		return $msg;
	}
}

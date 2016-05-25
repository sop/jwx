<?php

namespace JWX\JWE\KeyAlgorithm;

use JWX\JWE\KeyAlgorithm\Feature\RandomCEK;
use JWX\JWE\KeyManagementAlgorithm;
use JWX\JWK\RSA\RSAPrivateKeyJWK;
use JWX\JWK\RSA\RSAPublicKeyJWK;
use JWX\JWT\Parameter\AlgorithmParameter;


/**
 * Base class for algorithms implementing RSA based key encryption.
 *
 * @link https://tools.ietf.org/html/rfc7518#section-4.2
 * @link https://tools.ietf.org/html/rfc7518#section-4.3
 */
abstract class RSAESKeyAlgorithm implements KeyManagementAlgorithm
{
	use RandomCEK;
	
	/**
	 * Public key.
	 *
	 * @var RSAPublicKeyJWK $_publicKey
	 */
	protected $_publicKey;
	
	/**
	 * Private key.
	 *
	 * @var RSAPrivateKeyJWK|null $_privateKey
	 */
	protected $_privateKey;
	
	/**
	 * Get padding scheme.
	 *
	 * @return int
	 */
	abstract protected function _paddingScheme();
	
	/**
	 * Constructor
	 *
	 * Use <b>fromPublicKey</b> and <b>fromPrivateKey</b> instead!
	 *
	 * @param RSAPublicKeyJWK $pub_key
	 * @param RSAPrivateKeyJWK $priv_key
	 */
	protected function __construct(RSAPublicKeyJWK $pub_key, 
			RSAPrivateKeyJWK $priv_key = null) {
		$this->_publicKey = $pub_key;
		$this->_privateKey = $priv_key;
	}
	
	/**
	 * Initialize from public key.
	 *
	 * @param RSAPublicKeyJWK $jwk
	 * @return self
	 */
	public static function fromPublicKey(RSAPublicKeyJWK $jwk) {
		return new static($jwk);
	}
	
	/**
	 * Initialize from private key.
	 *
	 * @param RSAPrivateKeyJWK $jwk
	 * @return self
	 */
	public static function fromPrivateKey(RSAPrivateKeyJWK $jwk) {
		return new static($jwk->publicKey(), $jwk);
	}
	
	/**
	 * Get public key.
	 *
	 * @return RSAPublicKeyJWK
	 */
	public function publicKey() {
		return $this->_publicKey;
	}
	
	/**
	 * Check whether private key is present.
	 *
	 * @return bool
	 */
	public function hasPrivateKey() {
		return isset($this->_privateKey);
	}
	
	/**
	 * Get private key.
	 *
	 * @throws \LogicException
	 * @return RSAPrivateKeyJWK
	 */
	public function privateKey() {
		if (!$this->hasPrivateKey()) {
			throw new \LogicException("Private key not set.");
		}
		return $this->_privateKey;
	}
	
	public function encrypt($cek) {
		$key = openssl_pkey_get_public(
			$this->publicKey()
				->toPEM()
				->string());
		if (false === $key) {
			throw new \RuntimeException(
				"openssl_pkey_get_public() failed: " .
					 $this->_getLastOpenSSLError());
		}
		$result = openssl_public_encrypt($cek, $crypted, $key, 
			$this->_paddingScheme());
		if (!$result) {
			throw new \RuntimeException(
				"openssl_public_encrypt() failed: " .
					 $this->_getLastOpenSSLError());
		}
		return $crypted;
	}
	
	public function decrypt($data) {
		$key = openssl_pkey_get_private(
			$this->privateKey()
				->toPEM()
				->string());
		if (!$key) {
			throw new \RuntimeException(
				"openssl_pkey_get_private() failed: " .
					 $this->_getLastOpenSSLError());
		}
		$result = openssl_private_decrypt($data, $cek, $key, 
			$this->_paddingScheme());
		if (!$result) {
			throw new \RuntimeException(
				"openssl_private_decrypt() failed: " .
					 $this->_getLastOpenSSLError());
		}
		return $cek;
	}
	
	/**
	 * Get last OpenSSL error message.
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
	
	public function headerParameters() {
		return array(AlgorithmParameter::fromAlgorithm($this));
	}
}

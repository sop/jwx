<?php

namespace JWX\JWE\KeyAlgorithm;

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
	/**
	 * Public key.
	 *
	 * @var RSAPublicKeyJWK $_publicKey
	 */
	protected $_publicKey;
	
	/**
	 * Private key.
	 *
	 * @var RSAPrivateKeyJWK $_privateKey
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
	
	public function encrypt($cek) {
		$key = openssl_pkey_get_public($this->_publicKey->toPEM()->str());
		if (false === $key) {
			throw new \RuntimeException("Failed to load public key.");
		}
		$result = openssl_public_encrypt($cek, $crypted, $key, 
			$this->_paddingScheme());
		if (!$result) {
			throw new \RuntimeException("openssl_public_encrypt() failed.");
		}
		return $crypted;
	}
	
	public function decrypt($data) {
		if (!isset($this->_privateKey)) {
			throw new \LogicException("Private key not set.");
		}
		$key = openssl_pkey_get_private($this->_privateKey->toPEM()->str());
		if (!$key) {
			throw new \RuntimeException("Failed to load private key.");
		}
		$result = openssl_private_decrypt($data, $cek, $key, 
			$this->_paddingScheme());
		if (!$result) {
			throw new \RuntimeException("openssl_private_decrypt() failed.");
		}
		return $cek;
	}
	
	public function headerParameters() {
		return array(AlgorithmParameter::fromAlgorithm($this));
	}
}

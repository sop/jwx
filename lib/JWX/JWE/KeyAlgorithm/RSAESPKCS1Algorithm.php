<?php

namespace JWX\JWE\KeyAlgorithm;

use JWX\JWE\KeyManagementAlgorithm;
use JWX\JWT\Parameter\AlgorithmParameter;
use JWX\JWK\RSA\RSAPublicKeyJWK;
use JWX\JWK\RSA\RSAPrivateKeyJWK;


/**
 * Key Encryption with RSAES-PKCS1-v1_5
 *
 * @link https://tools.ietf.org/html/rfc7518#section-4.2
 */
class RSAESPKCS1Algorithm implements KeyManagementAlgorithm
{
	/**
	 * Public key
	 *
	 * @var RSAPublicKeyJWK $_publicKey
	 */
	protected $_publicKey;
	
	/**
	 * Private key
	 *
	 * @var RSAPrivateKeyJWK $_privateKey
	 */
	protected $_privateKey;
	
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
	 * Initialize from public key
	 *
	 * @param RSAPublicKeyJWK $jwk
	 * @return self
	 */
	public static function fromPublicKey(RSAPublicKeyJWK $jwk) {
		return new self($jwk);
	}
	
	/**
	 * Initialize from private key
	 *
	 * @param RSAPrivateKeyJWK $jwk
	 * @return self
	 */
	public static function fromPrivateKey(RSAPrivateKeyJWK $jwk) {
		return new self($jwk->publicKey(), $jwk);
	}
	
	public function encrypt($cek) {
		$key = openssl_pkey_get_public($this->_publicKey->toPEM()->str());
		if (false === $key) {
			throw new \RuntimeException("Failed to load public key");
		}
		$result = openssl_public_encrypt($cek, $crypted, $key, 
			OPENSSL_PKCS1_PADDING);
		if (!$result) {
			throw new \RuntimeException("openssl_public_encrypt() failed");
		}
		return $crypted;
	}
	
	public function decrypt($data) {
		if (!isset($this->_privateKey)) {
			throw new \LogicException("Private key not set");
		}
		$key = openssl_pkey_get_private($this->_privateKey->toPEM()->str());
		if (!$key) {
			throw new \RuntimeException("Failed to load private key");
		}
		$result = openssl_private_decrypt($data, $cek, $key, 
			OPENSSL_PKCS1_PADDING);
		if (!$result) {
			throw new \RuntimeException("openssl_private_decrypt() failed");
		}
		return $cek;
	}
	
	public function algorithmParamValue() {
		return AlgorithmParameter::ALGO_RSA1_5;
	}
}

<?php

namespace JWX\JWS\Algorithm;

use JWX\JWS\SignatureAlgorithm;
use JWX\JWK\RSA\RSAPublicKeyJWK;
use JWX\JWK\RSA\RSAPrivateKeyJWK;


/**
 * Base class for algorithms implementing signature with PKCS #1.
 */
abstract class RSAPKCS1Algorithm implements SignatureAlgorithm
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
	 * @var RSAPrivateKeyJWK|null $_privateKey
	 */
	protected $_privateKey;
	
	/**
	 * Get message digest method name supported by openssl
	 *
	 * @return string
	 */
	abstract protected function _mdMethod();
	
	/**
	 * Constructor
	 *
	 * Use <b>fromPublicKey</b> or <b>fromPrivateKey</b>
	 * static initializers instead.
	 */
	protected function __construct() {}
	
	/**
	 * Initialize from public key
	 *
	 * @param RSAPublicKeyJWK $jwk
	 * @return self
	 */
	public static function fromPublicKey(RSAPublicKeyJWK $jwk) {
		$obj = new static();
		$obj->_publicKey = $jwk;
		return $obj;
	}
	
	/**
	 * Initialize from private key
	 *
	 * @param RSAPrivateKeyJWK $jwk
	 * @return self
	 */
	public static function fromPrivateKey(RSAPrivateKeyJWK $jwk) {
		$obj = new static();
		$obj->_publicKey = $jwk->publicKey();
		$obj->_privateKey = $jwk;
		return $obj;
	}
	
	/**
	 * NOTE: OpenSSL uses PKCS #1 v1.5 padding by default, so
	 * no explicit padding is required by sign and verify operations.
	 *
	 * @see \JWX\JWS\SignatureAlgorithm::computeSignature()
	 */
	public function computeSignature($data) {
		if (!isset($this->_privateKey)) {
			throw new \LogicException("Private key not set");
		}
		$key = openssl_pkey_get_private($this->_privateKey->toPEM()->str());
		if (!$key) {
			throw new \RuntimeException("Failed to load private key");
		}
		$result = openssl_sign($data, $signature, $key, $this->_mdMethod());
		if (!$result) {
			throw new \RuntimeException("openssl_sign failed");
		}
		return $signature;
	}
	
	public function validateSignature($data, $signature) {
		$key = openssl_pkey_get_public($this->_publicKey->toPEM()->str());
		if (!$key) {
			throw new \RuntimeException("Failed to load public key");
		}
		$result = openssl_verify($data, $signature, $key, $this->_mdMethod());
		if ($result == -1) {
			throw new \RuntimeException("openssl_verify failed");
		}
		return $result == 1;
	}
}

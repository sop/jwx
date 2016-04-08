<?php

namespace JWX\JWS\Algorithm;

use JWX\JWS\SignatureAlgorithm;


/**
 * NOTE: OpenSSL uses PKCS#1 v1.5 padding by default, so
 * no explicit padding is required by sign and verify operations.
 */
abstract class RSAPKCS1Algorithm implements SignatureAlgorithm
{
	/**
	 * Public key
	 *
	 * @var string $_publicKey
	 */
	protected $_publicKey;
	
	/**
	 * Private key
	 *
	 * @var string $_privateKey
	 */
	protected $_privateKey;
	
	/**
	 * Get message digest method name supported by openssl
	 *
	 * @return string
	 */
	abstract protected function _mdMethod();
	
	/**
	 * Initialize from public key
	 *
	 * @param string $pem PEM formatted public key
	 * @return self
	 */
	public static function fromPublicKey($pem) {
		$obj = new static();
		$obj->_publicKey = $pem;
		return $obj;
	}
	
	/**
	 * Initialize from private key
	 *
	 * @param string $pem PEM formatted private key
	 * @return self
	 */
	public static function fromPrivateKey($pem) {
		$obj = new static();
		$obj->_privateKey = $pem;
		return $obj;
	}
	
	public function computeSignature($data) {
		$key = openssl_pkey_get_private($this->_privateKey);
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
		$key = openssl_pkey_get_public($this->_publicKey);
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

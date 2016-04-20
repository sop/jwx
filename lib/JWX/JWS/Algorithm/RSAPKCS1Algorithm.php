<?php

namespace JWX\JWS\Algorithm;

use JWX\JWS\SignatureAlgorithm;
use JWX\JWK\JWK;
use JWX\JWK\RSA\RSAPublicKeyJWK;
use JWX\JWK\RSA\RSAPrivateKeyJWK;
use JWX\JWK\Parameter\RegisteredJWKParameter;
use JWX\JWA\JWA;


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
	 * Mapping from algorithm name to class name
	 *
	 * @var array
	 */
	private static $_algoToCls = array(
		/* @formatter:off */
		JWA::ALGO_RS256 => RS256Algorithm::class,
		JWA::ALGO_RS384 => RS384Algorithm::class,
		JWA::ALGO_RS512 => RS512Algorithm::class
		/* @formatter:on */
	);
	
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
	 * static initializer instead!
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
		return new static($jwk);
	}
	
	/**
	 * Initialize from private key
	 *
	 * @param RSAPrivateKeyJWK $jwk
	 * @return self
	 */
	public static function fromPrivateKey(RSAPrivateKeyJWK $jwk) {
		return new static($jwk->publicKey(), $jwk);
	}
	
	/**
	 * Initialize from JWK.
	 *
	 * @param JWK $jwk
	 * @throws \UnexpectedValueException
	 * @return self
	 */
	public static function fromJWK(JWK $jwk, $alg = null) {
		// if algorithm is not explicitly given, consult JWK
		if (!isset($alg)) {
			if (!$jwk->has(RegisteredJWKParameter::P_ALG)) {
				throw new \UnexpectedValueException(
					"Missing algorithm parameter");
			}
			$alg = $jwk->get(RegisteredJWKParameter::PARAM_ALGORITHM)->value();
		}
		if (!isset(self::$_algoToCls[$alg])) {
			throw new \UnexpectedValueException("Algorithm '$alg' not supported");
		}
		$cls = self::$_algoToCls[$alg];
		$params = RSAPrivateKeyJWK::requiredParams();
		if ($jwk->has(...$params)) {
			return $cls::fromPrivateKey(RSAPrivateKeyJWK::fromJWK($jwk));
		}
		$params = RSAPublicKeyJWK::requiredParams();
		if ($jwk->has(...$params)) {
			return $cls::fromPublicKey(RSAPublicKeyJWK::fromJWK($jwk));
		}
		throw new \UnexpectedValueException("Not an RSA key");
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

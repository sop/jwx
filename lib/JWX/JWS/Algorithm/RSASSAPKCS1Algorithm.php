<?php

namespace JWX\JWS\Algorithm;

use JWX\JWA\JWA;
use JWX\JWK\JWK;
use JWX\JWK\RSA\RSAPrivateKeyJWK;
use JWX\JWK\RSA\RSAPublicKeyJWK;
use JWX\JWT\Parameter\AlgorithmParameter;


/**
 * Base class for algorithms implementing signature with PKCS #1.
 *
 * @link https://tools.ietf.org/html/rfc7518#section-3.3
 */
abstract class RSASSAPKCS1Algorithm extends OpenSSLSignatureAlgorithm
{
	/**
	 * Mapping from algorithm name to class name.
	 *
	 * @internal
	 *
	 * @var array
	 */
	const MAP_NAME_TO_CLASS = array(
		/* @formatter:off */
		JWA::ALGO_RS256 => RS256Algorithm::class,
		JWA::ALGO_RS384 => RS384Algorithm::class,
		JWA::ALGO_RS512 => RS512Algorithm::class
		/* @formatter:on */
	);
	
	/**
	 * Constructor
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
	 * Initialize from a public key.
	 *
	 * @param RSAPublicKeyJWK $jwk
	 * @return self
	 */
	public static function fromPublicKey(RSAPublicKeyJWK $jwk) {
		return new static($jwk);
	}
	
	/**
	 * Initialize from a private key.
	 *
	 * @param RSAPrivateKeyJWK $jwk
	 * @return self
	 */
	public static function fromPrivateKey(RSAPrivateKeyJWK $jwk) {
		return new static($jwk->publicKey(), $jwk);
	}
	
	/**
	 * Initialize from a JWK.
	 *
	 * If algorithm is not specified, look from JWK.
	 *
	 * @param JWK $jwk
	 * @param string|null $alg Optional algorithm name
	 * @throws \UnexpectedValueException
	 * @return self
	 */
	public static function fromJWK(JWK $jwk, $alg = null) {
		// if algorithm is not explicitly given, consult JWK
		if (!isset($alg)) {
			if (!$jwk->hasAlgorithmParameter()) {
				throw new \UnexpectedValueException(
					"Missing algorithm parameter.");
			}
			$alg = $jwk->algorithmParameter()->value();
		}
		if (!array_key_exists($alg, self::MAP_NAME_TO_CLASS)) {
			throw new \UnexpectedValueException(
				"Algorithm '$alg' not supported.");
		}
		$cls = self::MAP_NAME_TO_CLASS[$alg];
		$params = RSAPrivateKeyJWK::MANAGED_PARAMS;
		if ($jwk->has(...$params)) {
			return $cls::fromPrivateKey(RSAPrivateKeyJWK::fromJWK($jwk));
		}
		$params = RSAPublicKeyJWK::MANAGED_PARAMS;
		if ($jwk->has(...$params)) {
			return $cls::fromPublicKey(RSAPublicKeyJWK::fromJWK($jwk));
		}
		throw new \UnexpectedValueException("Not an RSA key.");
	}
	
	public function headerParameters() {
		return array(AlgorithmParameter::fromAlgorithm($this));
	}
}

<?php

namespace JWX\JWS\Algorithm;

use JWX\JWS\SignatureAlgorithm;
use JWX\JWA\JWA;
use JWX\JWK\JWK;
use JWX\JWK\Parameter\RegisteredJWKParameter;
use JWX\JWK\Parameter\KeyTypeParameter;


/**
 * Base class for algorithms implementing HMAC signature.
 *
 * @link https://tools.ietf.org/html/rfc7518#section-3.2
 */
abstract class HMACAlgorithm implements SignatureAlgorithm
{
	/**
	 * Shared secret key
	 *
	 * @var string $_key
	 */
	protected $_key;
	
	/**
	 * Get algorithm name that is recognized by the Hash extension
	 *
	 * @return string
	 */
	abstract protected function _hashAlgo();
	
	/**
	 * Constructor
	 *
	 * @param string $key Shared secret key
	 */
	public function __construct($key) {
		$this->_key = $key;
	}
	
	/**
	 * Initialize from JWK
	 *
	 * @param JWK $jwk
	 * @throws \UnexpectedValueException
	 * @return self
	 */
	public static function fromJWK(JWK $jwk) {
		static $params = array(RegisteredJWKParameter::PARAM_KEY_TYPE, 
			RegisteredJWKParameter::PARAM_ALGORITHM, 
			RegisteredJWKParameter::PARAM_KEY_VALUE);
		// check that all the parameters are present
		if (!$jwk->has(...$params)) {
			throw new \UnexpectedValueException("Missing parameters");
		}
		// check that key type is correct
		$kty = $jwk->get(RegisteredJWKParameter::PARAM_KEY_TYPE)->value();
		if ($kty != KeyTypeParameter::TYPE_OCT) {
			throw new \UnexpectedValueException("Invalid key type");
		}
		$alg = $jwk->get(RegisteredJWKParameter::PARAM_ALGORITHM)->value();
		$key = $jwk->get(RegisteredJWKParameter::PARAM_KEY_VALUE)->key();
		switch ($alg) {
		case JWA::ALGO_HS256:
			return new HS256Algorithm($key);
		case JWA::ALGO_HS384:
			return new HS384Algorithm($key);
		case JWA::ALGO_HS512:
			return new HS512Algorithm($key);
		}
		throw new \UnexpectedValueException("Unsupported algorithm '$alg'");
	}
	
	public function computeSignature($data) {
		$result = hash_hmac($this->_hashAlgo(), $data, $this->_key, true);
		if (false === $result) {
			throw new \RuntimeException("hash_hmac failed");
		}
		return $result;
	}
	
	public function validateSignature($data, $signature) {
		return $this->computeSignature($data) === $signature;
	}
}

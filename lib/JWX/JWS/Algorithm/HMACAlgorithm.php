<?php

namespace JWX\JWS\Algorithm;

use JWX\JWA\JWA;
use JWX\JWK\JWK;
use JWX\JWK\Symmetric\SymmetricKeyJWK;
use JWX\JWS\SignatureAlgorithm;
use JWX\JWT\Parameter\AlgorithmParameter;


/**
 * Base class for algorithms implementing HMAC signature.
 *
 * @link https://tools.ietf.org/html/rfc7518#section-3.2
 */
abstract class HMACAlgorithm implements SignatureAlgorithm
{
	/**
	 * Shared secret key.
	 *
	 * @var string $_key
	 */
	protected $_key;
	
	/**
	 * Mapping from algorithm name to class name.
	 *
	 * @internal
	 *
	 * @var array
	 */
	const MAP_NAME_TO_CLASS = array(
		/* @formatter:off */
		JWA::ALGO_HS256 => HS256Algorithm::class, 
		JWA::ALGO_HS384 => HS384Algorithm::class, 
		JWA::ALGO_HS512 => HS512Algorithm::class
		/* @formatter:on */
	);
	
	/**
	 * Get algorithm name recognized by the Hash extension.
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
		$jwk = SymmetricKeyJWK::fromJWK($jwk);
		// if algorithm is not explicitly given, consult JWK
		if (!isset($alg)) {
			if (!$jwk->hasAlgorithmParameter()) {
				throw new \UnexpectedValueException(
					"Missing algorithm parameter.");
			}
			$alg = $jwk->algorithmParameter()->value();
		}
		if (!array_key_exists($alg, self::MAP_NAME_TO_CLASS)) {
			throw new \UnexpectedValueException("Unsupported algorithm '$alg'.");
		}
		$cls = self::MAP_NAME_TO_CLASS[$alg];
		return new $cls($jwk->key());
	}
	
	public function computeSignature($data) {
		$result = @hash_hmac($this->_hashAlgo(), $data, $this->_key, true);
		if (false === $result) {
			$err = error_get_last();
			$msg = isset($err) ? $err["message"] : "hash_hmac() failed.";
			throw new \RuntimeException($msg);
		}
		return $result;
	}
	
	public function validateSignature($data, $signature) {
		return $this->computeSignature($data) === $signature;
	}
	
	public function headerParameters() {
		return array(AlgorithmParameter::fromAlgorithm($this));
	}
}

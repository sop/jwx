<?php

namespace JWX\JWS\Algorithm;

use JWX\JWS\SignatureAlgorithm;


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

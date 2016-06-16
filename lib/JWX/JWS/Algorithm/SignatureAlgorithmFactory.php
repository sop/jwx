<?php

namespace JWX\JWS\Algorithm;

use JWX\JWA\JWA;
use JWX\JWK\JWK;
use JWX\JWK\JWKSet;
use JWX\JWS\SignatureAlgorithm;
use JWX\JWT\Header\Header;


/**
 * Factory class to construct signature algorithm instances.
 */
class SignatureAlgorithmFactory
{
	/**
	 * Header.
	 *
	 * @var Header $_header
	 */
	protected $_header;
	
	/**
	 * Mapping from algorithm name to class name.
	 *
	 * @internal
	 *
	 * @var array
	 */
	const MAP_ALGO_TO_CLASS = array(
		/* @formatter:off */
		JWA::ALGO_HS256 => HS256Algorithm::class,
		JWA::ALGO_HS384 => HS384Algorithm::class,
		JWA::ALGO_HS512 => HS512Algorithm::class,
		JWA::ALGO_RS256 => RS256Algorithm::class,
		JWA::ALGO_RS384 => RS384Algorithm::class,
		JWA::ALGO_RS512 => RS512Algorithm::class,
		JWA::ALGO_ES256 => ES256Algorithm::class,
		JWA::ALGO_ES384 => ES384Algorithm::class,
		JWA::ALGO_ES512 => ES512Algorithm::class
		/* @formatter:on */
	);
	
	/**
	 * Constructor.
	 *
	 * @param Header $header
	 */
	public function __construct(Header $header) {
		$this->_header = $header;
	}
	
	/**
	 * Get signature algorithm by given JWK.
	 *
	 * @param JWK $jwk
	 * @return SignatureAlgorithm
	 */
	public function algoByKey(JWK $jwk) {
		$alg = JWA::deriveAlgorithmName($this->_header, $jwk);
		$cls = self::_algoClassByName($alg);
		return $cls::fromJWK($jwk, $this->_header);
	}
	
	/**
	 * Get signature algorithm using a matching key from given JWK set.
	 *
	 * @param JWKSet $set
	 * @throws \UnexpectedValueException If a key cannot be found
	 * @return SignatureAlgorithm
	 */
	public function algoByKeys(JWKSet $set) {
		if (!$this->_header->hasKeyID()) {
			throw new \UnexpectedValueException("No key ID paremeter.");
		}
		$id = $this->_header->keyID()->value();
		if (!$set->hasKeyID($id)) {
			throw new \UnexpectedValueException("No key for ID '$id'.");
		}
		return $this->algoByKey($set->keyByID($id));
	}
	
	/**
	 * Get the algorithm implementation class name by an algorithm name.
	 *
	 * @param string $alg Algorithm name
	 * @throws \UnexpectedValueException
	 * @return string Class name
	 */
	private static function _algoClassByName($alg) {
		if (!array_key_exists($alg, self::MAP_ALGO_TO_CLASS)) {
			throw new \UnexpectedValueException(
				"Algorithm '$alg' not supported.");
		}
		return self::MAP_ALGO_TO_CLASS[$alg];
	}
}

<?php

namespace JWX\JWE\KeyAlgorithm;

use JWX\JWA\JWA;
use JWX\JWE\KeyManagementAlgorithm;
use JWX\JWK\JWK;
use JWX\JWK\JWKSet;
use JWX\JWT\Header\Header;


/**
 * Factory class to construct key management algorithm instances.
 */
class KeyAlgorithmFactory
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
		JWA::ALGO_A128KW => A128KWAlgorithm::class,
		JWA::ALGO_A192KW => A192KWAlgorithm::class,
		JWA::ALGO_A128KW => A256KWAlgorithm::class,
		JWA::ALGO_A128GCMKW => A128GCMKWAlgorithm::class,
		JWA::ALGO_A192GCMKW => A192GCMKWAlgorithm::class,
		JWA::ALGO_A256GCMKW => A256GCMKWAlgorithm::class,
		JWA::ALGO_PBES2_HS256_A128KW => PBES2HS256A128KWAlgorithm::class,
		JWA::ALGO_PBES2_HS384_A192KW => PBES2HS384A192KWAlgorithm::class,
		JWA::ALGO_PBES2_HS512_A256KW => PBES2HS512A256KWAlgorithm::class,
		JWA::ALGO_DIR => DirectCEKAlgorithm::class,
		JWA::ALGO_RSA1_5 => RSAESPKCS1Algorithm::class,
		JWA::ALGO_RSA_OAEP => RSAESOAEPAlgorithm::class
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
	 * Get key management algorithm by given JWK.
	 *
	 * @param JWK $jwk
	 * @return KeyManagementAlgorithm
	 */
	public function algoByKey(JWK $jwk) {
		$alg = JWA::deriveAlgorithmName($this->_header, $jwk);
		$cls = self::_algoClassByName($alg);
		return $cls::fromJWK($jwk, $this->_header);
	}
	
	/**
	 * Get key management algorithm using a matching key from given JWK set.
	 *
	 * @param JWKSet $set
	 * @throws \UnexpectedValueException If a key cannot be found
	 * @return KeyManagementAlgorithm
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

<?php

namespace JWX\JWE\EncryptionAlgorithm;

use JWX\JWA\JWA;
use JWX\JWE\EncryptionAlgorithm\A128CBCHS256Algorithm;
use JWX\JWE\EncryptionAlgorithm\A128GCMAlgorithm;
use JWX\JWE\EncryptionAlgorithm\A192CBCHS384Algorithm;
use JWX\JWE\EncryptionAlgorithm\A192GCMAlgorithm;
use JWX\JWE\EncryptionAlgorithm\A256CBCHS512Algorithm;
use JWX\JWE\EncryptionAlgorithm\A256GCMAlgorithm;


/**
 * Factory class to construct content encryption algorithm instances.
 */
abstract class EncryptionFactory
{
	/**
	 * Mapping from algorithm name to class name.
	 *
	 * @internal
	 *
	 * @var array
	 */
	const MAP_ALGO_TO_CLASS = array(
		/* @formatter:off */
		JWA::ALGO_A128CBC_HS256 => A128CBCHS256Algorithm::class,
		JWA::ALGO_A192CBC_HS384 => A192CBCHS384Algorithm::class,
		JWA::ALGO_A256CBC_HS512 => A256CBCHS512Algorithm::class,
		JWA::ALGO_A128GCM => A128GCMAlgorithm::class,
		JWA::ALGO_A192GCM => A192GCMAlgorithm::class,
		JWA::ALGO_A256GCM => A256GCMAlgorithm::class
		/* @formatter:on */
	);
	
	/**
	 * Get content encryption algorithm by algorithm name.
	 *
	 * @param string $name Algorithm name
	 * @throws \UnexpectedValueException If algorithm name is invalid
	 * @return ContentEncryptionAlgorithm
	 */
	public static function algoByName($name) {
		if (!array_key_exists($name, self::MAP_ALGO_TO_CLASS)) {
			throw new \UnexpectedValueException(
				"No content encryption algorithm '$name'.");
		}
		$cls = self::MAP_ALGO_TO_CLASS[$name];
		return new $cls();
	}
}

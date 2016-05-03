<?php

namespace JWX\JWE\CompressionAlgorithm;

use JWX\JWE\CompressionAlgorithm;
use JWX\JWT\Parameter\CompressionAlgorithmParameter;


/**
 * Factory class to construct compression algorithm instances.
 */
class CompressionFactory
{
	/**
	 * Mapping from algorithm name to class name.
	 *
	 * @var array
	 */
	const ALGO_TO_CLS = array(
		/* @formatter:off */
		CompressionAlgorithmParameter::ALGO_DEFLATE => DeflateAlgorithm::class
		/* @formatter:on */
	);
	
	/**
	 * Get compression algorithm by name.
	 *
	 * @param string $name
	 * @throws \UnexpectedValueException
	 * @return CompressionAlgorithm
	 */
	public static function algoByName($name) {
		if (!array_key_exists($name, self::ALGO_TO_CLS)) {
			throw new \UnexpectedValueException(
				"No compression algorithm '$name'.");
		}
		$cls = self::ALGO_TO_CLS[$name];
		return new $cls();
	}
}

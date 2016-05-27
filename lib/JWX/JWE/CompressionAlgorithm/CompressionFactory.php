<?php

namespace JWX\JWE\CompressionAlgorithm;

use JWX\JWA\JWA;
use JWX\JWE\CompressionAlgorithm;


/**
 * Factory class to construct compression algorithm instances.
 */
abstract class CompressionFactory
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
		JWA::ALGO_DEFLATE => DeflateAlgorithm::class
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
		if (!array_key_exists($name, self::MAP_ALGO_TO_CLASS)) {
			throw new \UnexpectedValueException(
				"No compression algorithm '$name'.");
		}
		$cls = self::MAP_ALGO_TO_CLASS[$name];
		return new $cls();
	}
}

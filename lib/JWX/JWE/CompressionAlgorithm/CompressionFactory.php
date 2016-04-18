<?php

namespace JWX\JWE\CompressionAlgorithm;

use JWX\JWE\CompressionAlgorithm;
use JWX\JWT\Parameter\CompressionAlgorithmParameter;


class CompressionFactory
{
	/**
	 * Mapping from algorithm name to class name
	 *
	 * @var array
	 */
	private static $_nameToCls = array(
		/* @formatter:off */
		CompressionAlgorithmParameter::ALGO_DEFLATE => DeflateAlgorithm::class
		/* @formatter:on */
	);
	
	/**
	 * Get compression algorithm by name
	 *
	 * @param string $name
	 * @throws \UnexpectedValueException
	 * @return CompressionAlgorithm
	 */
	public static function algoByName($name) {
		if (!isset(self::$_nameToCls[$name])) {
			throw new \UnexpectedValueException(
				"No compression algorithm '$name'");
		}
		$cls = self::$_nameToCls[$name];
		return new $cls();
	}
}

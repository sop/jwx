<?php

declare(strict_types = 1);

namespace JWX\JWE\CompressionAlgorithm;

use JWX\JWA\JWA;
use JWX\JWE\CompressionAlgorithm;
use JWX\JWT\Header\Header;

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
     * Get the compression algorithm by name.
     *
     * @param string $name
     * @throws \UnexpectedValueException If algorithm is not supported
     * @return CompressionAlgorithm
     */
    public static function algoByName(string $name): CompressionAlgorithm
    {
        if (!array_key_exists($name, self::MAP_ALGO_TO_CLASS)) {
            throw new \UnexpectedValueException(
                "No compression algorithm '$name'.");
        }
        $cls = self::MAP_ALGO_TO_CLASS[$name];
        return new $cls();
    }
    
    /**
     * Get the compression algorithm as specified in the given header.
     *
     * @param Header $header Header
     * @throws \UnexpectedValueException If compression algorithm parameter is
     *         not present or algorithm is not supported
     * @return CompressionAlgorithm
     */
    public static function algoByHeader(Header $header): CompressionAlgorithm
    {
        if (!$header->hasCompressionAlgorithm()) {
            throw new \UnexpectedValueException(
                "No compression algorithm parameter.");
        }
        return self::algoByName($header->compressionAlgorithm()->value());
    }
}

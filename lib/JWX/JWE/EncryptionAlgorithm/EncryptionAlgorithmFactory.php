<?php

declare(strict_types = 1);

namespace JWX\JWE\EncryptionAlgorithm;

use JWX\JWA\JWA;
use JWX\JWE\ContentEncryptionAlgorithm;
use JWX\JWT\Header\Header;

/**
 * Factory class to construct content encryption algorithm instances.
 */
abstract class EncryptionAlgorithmFactory
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
     * Get the content encryption algorithm by algorithm name.
     *
     * @param string $name Algorithm name
     * @throws \UnexpectedValueException If algorithm is not supported.
     * @return ContentEncryptionAlgorithm
     */
    public static function algoByName(string $name): ContentEncryptionAlgorithm
    {
        if (!array_key_exists($name, self::MAP_ALGO_TO_CLASS)) {
            throw new \UnexpectedValueException(
                "No content encryption algorithm '$name'.");
        }
        $cls = self::MAP_ALGO_TO_CLASS[$name];
        return new $cls();
    }
    
    /**
     * Get the content encryption algorithm as specified in the given header.
     *
     * @param Header $header Header
     * @throws \UnexpectedValueException If content encryption algorithm
     *         parameter is not present or algorithm is not supported.
     * @return ContentEncryptionAlgorithm
     */
    public static function algoByHeader(Header $header): ContentEncryptionAlgorithm
    {
        if (!$header->hasEncryptionAlgorithm()) {
            throw new \UnexpectedValueException(
                "No encryption algorithm parameter.");
        }
        return self::algoByName($header->encryptionAlgorithm()->value());
    }
}

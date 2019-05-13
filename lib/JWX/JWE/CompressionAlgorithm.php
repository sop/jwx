<?php

declare(strict_types = 1);

namespace Sop\JWX\JWE;

use Sop\JWX\JWT\Header\HeaderParameters;
use Sop\JWX\JWT\Parameter\CompressionAlgorithmParameterValue;

/**
 * Interface for algorithms that may be used to compress and decompress data.
 */
interface CompressionAlgorithm extends CompressionAlgorithmParameterValue, HeaderParameters
{
    /**
     * Compress data.
     *
     * @param string $data Uncompressed data
     *
     * @return string Compressed data
     */
    public function compress(string $data): string;

    /**
     * Decompress data.
     *
     * @param string $data Compressed data
     *
     * @return string Uncompressed data
     */
    public function decompress(string $data): string;
}

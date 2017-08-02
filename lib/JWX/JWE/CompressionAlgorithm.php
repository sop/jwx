<?php

namespace JWX\JWE;

use JWX\JWT\Header\HeaderParameters;
use JWX\JWT\Parameter\CompressionAlgorithmParameterValue;

/**
 * Interface for algorithms that may be used to compress and decompress data.
 */
interface CompressionAlgorithm extends 
    CompressionAlgorithmParameterValue,
    HeaderParameters
{
    /**
     * Compress data.
     *
     * @param string $data Compressed data
     */
    public function compress($data);
    
    /**
     * Decompress data.
     *
     * @param string $data Uncompressed data
     */
    public function decompress($data);
}

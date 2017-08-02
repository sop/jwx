<?php

namespace JWX\JWT\Parameter;

/**
 * Interface for algorithms providing value for 'zip' header parameter.
 */
interface CompressionAlgorithmParameterValue
{
    /**
     * Get compression algorithm type as an 'zip' parameter value.
     *
     * @return string
     */
    public function compressionParamValue();
}

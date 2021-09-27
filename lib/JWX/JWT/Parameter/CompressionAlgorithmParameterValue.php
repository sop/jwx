<?php

declare(strict_types = 1);

namespace Sop\JWX\JWT\Parameter;

/**
 * Interface for algorithms providing value for 'zip' header parameter.
 */
interface CompressionAlgorithmParameterValue
{
    /**
     * Get compression algorithm type as an 'zip' parameter value.
     */
    public function compressionParamValue(): string;
}

<?php

declare(strict_types = 1);

namespace JWX\JWT\Parameter;

use JWX\Parameter\Feature\StringParameterValue;

/**
 * Implements 'Compression Algorithm' parameter.
 *
 * @link https://tools.ietf.org/html/rfc7516#section-4.1.3
 */
class CompressionAlgorithmParameter extends JWTParameter
{
    use StringParameterValue;
    
    /**
     * Constructor.
     *
     * @param string $algo
     */
    public function __construct(string $algo)
    {
        parent::__construct(self::PARAM_COMPRESSION_ALGORITHM, $algo);
    }
    
    /**
     * Initialize from CompressionAlgorithmParameterValue.
     *
     * @param CompressionAlgorithmParameterValue $value
     * @return self
     */
    public static function fromAlgorithm(
        CompressionAlgorithmParameterValue $value): self
    {
        return new self($value->compressionParamValue());
    }
}

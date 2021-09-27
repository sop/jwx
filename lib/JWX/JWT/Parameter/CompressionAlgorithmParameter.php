<?php

declare(strict_types = 1);

namespace Sop\JWX\JWT\Parameter;

use Sop\JWX\Parameter\Feature\StringParameterValue;

/**
 * Implements 'Compression Algorithm' parameter.
 *
 * @see https://tools.ietf.org/html/rfc7516#section-4.1.3
 */
class CompressionAlgorithmParameter extends JWTParameter
{
    use StringParameterValue;

    /**
     * Constructor.
     */
    public function __construct(string $algo)
    {
        parent::__construct(self::PARAM_COMPRESSION_ALGORITHM, $algo);
    }

    /**
     * Initialize from CompressionAlgorithmParameterValue.
     *
     * @return self
     */
    public static function fromAlgorithm(
        CompressionAlgorithmParameterValue $value): JWTParameter
    {
        return new self($value->compressionParamValue());
    }
}

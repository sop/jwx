<?php

declare(strict_types = 1);

namespace Sop\JWX\JWT\Parameter;

use Sop\JWX\Parameter\Feature\StringParameterValue;

/**
 * Implements 'Algorithm' parameter for JWS/JWE headers.
 *
 * @see https://tools.ietf.org/html/rfc7515#section-4.1.1
 * @see https://tools.ietf.org/html/rfc7516#section-4.1.1
 */
class AlgorithmParameter extends JWTParameter
{
    use StringParameterValue;

    /**
     * Constructor.
     *
     * @param string $algo Algorithm name
     */
    public function __construct(string $algo)
    {
        parent::__construct(self::PARAM_ALGORITHM, $algo);
    }

    /**
     * Initialize from AlgorithmParameterValue.
     *
     * @param AlgorithmParameterValue $value
     *
     * @return self
     */
    public static function fromAlgorithm(AlgorithmParameterValue $value): self
    {
        return new self($value->algorithmParamValue());
    }
}

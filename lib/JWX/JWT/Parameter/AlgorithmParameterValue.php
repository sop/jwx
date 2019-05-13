<?php

declare(strict_types = 1);

namespace Sop\JWX\JWT\Parameter;

/**
 * Interface for algorithms providing value for 'alg' header parameter.
 */
interface AlgorithmParameterValue
{
    /**
     * Get algorithm type as an 'alg' parameter value.
     *
     * @return string
     */
    public function algorithmParamValue(): string;
}

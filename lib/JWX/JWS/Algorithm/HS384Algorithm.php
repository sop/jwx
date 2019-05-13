<?php

declare(strict_types = 1);

namespace Sop\JWX\JWS\Algorithm;

use Sop\JWX\JWA\JWA;

/**
 * Implements HMAC using SHA-384.
 *
 * @see https://tools.ietf.org/html/rfc7518#section-3.2
 */
class HS384Algorithm extends HMACAlgorithm
{
    /**
     * {@inheritdoc}
     */
    public function algorithmParamValue(): string
    {
        return JWA::ALGO_HS384;
    }

    /**
     * {@inheritdoc}
     */
    protected function _hashAlgo(): string
    {
        return 'sha384';
    }
}

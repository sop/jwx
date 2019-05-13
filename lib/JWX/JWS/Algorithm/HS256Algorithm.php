<?php

declare(strict_types = 1);

namespace Sop\JWX\JWS\Algorithm;

use Sop\JWX\JWA\JWA;

/**
 * Implements HMAC using SHA-256.
 *
 * @see https://tools.ietf.org/html/rfc7518#section-3.2
 */
class HS256Algorithm extends HMACAlgorithm
{
    /**
     * {@inheritdoc}
     */
    public function algorithmParamValue(): string
    {
        return JWA::ALGO_HS256;
    }

    /**
     * {@inheritdoc}
     */
    protected function _hashAlgo(): string
    {
        return 'sha256';
    }
}

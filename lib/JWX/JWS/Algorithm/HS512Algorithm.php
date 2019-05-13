<?php

declare(strict_types = 1);

namespace Sop\JWX\JWS\Algorithm;

use Sop\JWX\JWA\JWA;

/**
 * Implements HMAC using SHA-512.
 *
 * @see https://tools.ietf.org/html/rfc7518#section-3.2
 */
class HS512Algorithm extends HMACAlgorithm
{
    /**
     * {@inheritdoc}
     */
    public function algorithmParamValue(): string
    {
        return JWA::ALGO_HS512;
    }

    /**
     * {@inheritdoc}
     */
    protected function _hashAlgo(): string
    {
        return 'sha512';
    }
}

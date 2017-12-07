<?php

declare(strict_types = 1);

namespace JWX\JWS\Algorithm;

use JWX\JWA\JWA;

/**
 * Implements HMAC using SHA-384.
 *
 * @link https://tools.ietf.org/html/rfc7518#section-3.2
 */
class HS384Algorithm extends HMACAlgorithm
{
    /**
     *
     * {@inheritdoc}
     */
    protected function _hashAlgo(): string
    {
        return "sha384";
    }
    
    /**
     *
     * {@inheritdoc}
     */
    public function algorithmParamValue(): string
    {
        return JWA::ALGO_HS384;
    }
}

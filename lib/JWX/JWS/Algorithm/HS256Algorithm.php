<?php

namespace JWX\JWS\Algorithm;

use JWX\JWA\JWA;

/**
 * Implements HMAC using SHA-256.
 *
 * @link https://tools.ietf.org/html/rfc7518#section-3.2
 */
class HS256Algorithm extends HMACAlgorithm
{
    /**
     *
     * {@inheritdoc}
     */
    protected function _hashAlgo()
    {
        return "sha256";
    }
    
    /**
     *
     * {@inheritdoc}
     */
    public function algorithmParamValue()
    {
        return JWA::ALGO_HS256;
    }
}

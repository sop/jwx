<?php

namespace JWX\JWS\Algorithm;

use JWX\JWA\JWA;

/**
 * Implements HMAC using SHA-512.
 *
 * @link https://tools.ietf.org/html/rfc7518#section-3.2
 */
class HS512Algorithm extends HMACAlgorithm
{
    /**
     *
     * {@inheritdoc}
     */
    protected function _hashAlgo()
    {
        return "sha512";
    }
    
    /**
     *
     * {@inheritdoc}
     */
    public function algorithmParamValue()
    {
        return JWA::ALGO_HS512;
    }
}

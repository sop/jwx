<?php

declare(strict_types = 1);

namespace JWX\JWS\Algorithm;

use JWX\JWA\JWA;

/**
 * Implements RSASSA-PKCS1-v1_5 using SHA-256.
 *
 * @link https://tools.ietf.org/html/rfc7518#section-3.3
 */
class RS256Algorithm extends RSASSAPKCS1Algorithm
{
    /**
     *
     * {@inheritdoc}
     */
    protected function _mdMethod(): string
    {
        return "sha256WithRSAEncryption";
    }
    
    /**
     *
     * {@inheritdoc}
     */
    public function algorithmParamValue(): string
    {
        return JWA::ALGO_RS256;
    }
}

<?php

declare(strict_types = 1);

namespace Sop\JWX\JWS\Algorithm;

use Sop\JWX\JWA\JWA;

/**
 * Implements RSASSA-PKCS1-v1_5 using SHA-256.
 *
 * @see https://tools.ietf.org/html/rfc7518#section-3.3
 */
class RS256Algorithm extends RSASSAPKCS1Algorithm
{
    /**
     * {@inheritdoc}
     */
    public function algorithmParamValue(): string
    {
        return JWA::ALGO_RS256;
    }

    /**
     * {@inheritdoc}
     */
    protected function _mdMethod(): int
    {
        return OPENSSL_ALGO_SHA256;
    }
}

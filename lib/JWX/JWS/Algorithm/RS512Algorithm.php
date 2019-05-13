<?php

declare(strict_types = 1);

namespace Sop\JWX\JWS\Algorithm;

use Sop\JWX\JWA\JWA;

/**
 * Implements RSASSA-PKCS1-v1_5 using SHA-512.
 *
 * @see https://tools.ietf.org/html/rfc7518#section-3.3
 */
class RS512Algorithm extends RSASSAPKCS1Algorithm
{
    /**
     * {@inheritdoc}
     */
    public function algorithmParamValue(): string
    {
        return JWA::ALGO_RS512;
    }

    /**
     * {@inheritdoc}
     */
    protected function _mdMethod(): int
    {
        return OPENSSL_ALGO_SHA512;
    }
}

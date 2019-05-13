<?php

declare(strict_types = 1);

namespace Sop\JWX\JWE\KeyAlgorithm;

use Sop\JWX\JWA\JWA;

/**
 * Implements key encryption with RSAES-PKCS1-v1_5.
 *
 * @see https://tools.ietf.org/html/rfc7518#section-4.2
 */
class RSAESPKCS1Algorithm extends RSAESKeyAlgorithm
{
    /**
     * {@inheritdoc}
     */
    public function algorithmParamValue(): string
    {
        return JWA::ALGO_RSA1_5;
    }

    /**
     * {@inheritdoc}
     */
    protected function _paddingScheme(): int
    {
        return OPENSSL_PKCS1_PADDING;
    }
}

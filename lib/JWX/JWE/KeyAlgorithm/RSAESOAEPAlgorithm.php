<?php

declare(strict_types = 1);

namespace Sop\JWX\JWE\KeyAlgorithm;

use Sop\JWX\JWA\JWA;

/**
 * Implements key encryption with RSAES OAEP.
 *
 * @see https://tools.ietf.org/html/rfc7518#section-4.3
 */
class RSAESOAEPAlgorithm extends RSAESKeyAlgorithm
{
    /**
     * {@inheritdoc}
     */
    public function algorithmParamValue(): string
    {
        return JWA::ALGO_RSA_OAEP;
    }

    /**
     * {@inheritdoc}
     */
    protected function _paddingScheme(): int
    {
        return OPENSSL_PKCS1_OAEP_PADDING;
    }
}

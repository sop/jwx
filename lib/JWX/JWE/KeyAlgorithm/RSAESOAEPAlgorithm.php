<?php

declare(strict_types = 1);

namespace JWX\JWE\KeyAlgorithm;

use JWX\JWA\JWA;

/**
 * Implements key encryption with RSAES OAEP.
 *
 * @link https://tools.ietf.org/html/rfc7518#section-4.3
 */
class RSAESOAEPAlgorithm extends RSAESKeyAlgorithm
{
    /**
     *
     * {@inheritdoc}
     */
    protected function _paddingScheme(): int
    {
        return OPENSSL_PKCS1_OAEP_PADDING;
    }
    
    /**
     *
     * {@inheritdoc}
     */
    public function algorithmParamValue(): string
    {
        return JWA::ALGO_RSA_OAEP;
    }
}

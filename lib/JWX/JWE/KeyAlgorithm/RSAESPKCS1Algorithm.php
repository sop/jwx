<?php

namespace JWX\JWE\KeyAlgorithm;

use JWX\JWA\JWA;

/**
 * Implements key encryption with RSAES-PKCS1-v1_5.
 *
 * @link https://tools.ietf.org/html/rfc7518#section-4.2
 */
class RSAESPKCS1Algorithm extends RSAESKeyAlgorithm
{
    /**
     *
     * {@inheritdoc}
     */
    protected function _paddingScheme()
    {
        return OPENSSL_PKCS1_PADDING;
    }
    
    /**
     *
     * {@inheritdoc}
     */
    public function algorithmParamValue()
    {
        return JWA::ALGO_RSA1_5;
    }
}

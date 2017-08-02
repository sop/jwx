<?php

namespace JWX\JWE\KeyAlgorithm;

use GCM\Cipher\AES\AES128Cipher;
use JWX\JWA\JWA;

/**
 * Implements key encryption with AES GCM using 128-bit key.
 *
 * @link https://tools.ietf.org/html/rfc7518#section-4.7
 */
class A128GCMKWAlgorithm extends AESGCMKWAlgorithm
{
    /**
     *
     * {@inheritdoc}
     */
    protected function _getGCMCipher()
    {
        return new AES128Cipher();
    }
    
    /**
     *
     * {@inheritdoc}
     */
    protected function _keySize()
    {
        return 16;
    }
    
    /**
     *
     * {@inheritdoc}
     */
    public function algorithmParamValue()
    {
        return JWA::ALGO_A128GCMKW;
    }
}
